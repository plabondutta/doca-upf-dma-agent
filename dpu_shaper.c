/*
 * dpu_shaper.c — DPU ARM-side token-bucket shaper for GBR YELLOW packets
 *
 * Thread model:
 *   - shaper_loop runs on a dedicated lcore, polling Rx queues rx_queue_base
 *     through rx_queue_base + nr_rx_queues - 1.
 *   - register/unregister/update_rate are called from the Comch callback
 *     thread.  The rte_hash is created with RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY
 *     so concurrent lookup (shaper lcore) + add/del (Comch lcore) is safe.
 *     Flow-slot data visibility is additionally guarded by __atomic
 *     ACQUIRE/RELEASE on flow->active.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>

#include <doca_log.h>

#include "dpu_shaper.h"

DOCA_LOG_REGISTER(DPU_SHAPER);

/* ── Helpers ────────────────────────────────────────────────────────── */

/** Convert kbps to bytes/sec: kbps * 1000 / 8 */
static inline uint64_t
kbps_to_bytes_per_sec(uint64_t kbps)
{
    return kbps * 125;  /* kbps * 1000 / 8 */
}

/**
 * Refill tokens based on elapsed TSC since last refill.
 * Uses integer arithmetic to avoid floating point on the data path.
 */
static inline void
token_refill(shaper_flow_t *flow, uint64_t now_tsc)
{
    uint64_t rate = __atomic_load_n(&flow->rate_bytes_per_sec,
                                    __ATOMIC_RELAXED);
    if (rate == 0)
        return;

    uint64_t elapsed = now_tsc - flow->last_refill_tsc;
    uint64_t hz = rte_get_tsc_hz();

    /* tokens_to_add = rate * elapsed / hz
     * Use 64-bit multiply; if elapsed < hz/rate this rounds to 0 which
     * is acceptable (sub-refill granularity, tokens accumulate next time). */
    uint64_t add = rate * (elapsed / hz)
                 + (rate * (elapsed % hz)) / hz;

    if (add == 0)
        return;

    flow->tokens += add;
    if (flow->tokens > flow->max_tokens)
        flow->tokens = flow->max_tokens;
    flow->last_refill_tsc = now_tsc;
}

/**
 * Try to consume pkt_len bytes of tokens.
 * Returns true if pkt is conforming (tokens consumed), false if not.
 */
static inline bool
token_consume(shaper_flow_t *flow, uint32_t pkt_len)
{
    if (flow->tokens >= pkt_len) {
        flow->tokens -= pkt_len;
        return true;
    }
    return false;
}

/**
 * Look up a flow slot from hw_rule_id via rte_hash.
 * Returns pointer to flow slot or NULL.
 */
static inline shaper_flow_t *
lookup_flow(shaper_ctx_t *ctx, uint32_t hw_rule_id)
{
    int idx = rte_hash_lookup(ctx->rule_id_map, &hw_rule_id);
    if (idx < 0)
        return NULL;
    shaper_flow_t *flow = &ctx->flows[idx];
    if (!__atomic_load_n(&flow->active, __ATOMIC_ACQUIRE))
        return NULL;
    return flow;
}

/* ── Public API ─────────────────────────────────────────────────────── */

void
shaper_init(shaper_ctx_t *ctx,
            uint16_t proxy_port_id,
            uint16_t rx_queue_base,
            uint16_t nr_rx_queues,
            uint16_t tx_queue_id)
{
    memset(ctx, 0, sizeof(*ctx));

    ctx->proxy_port_id = proxy_port_id;
    ctx->rx_queue_base = rx_queue_base;
    ctx->nr_rx_queues  = nr_rx_queues;
    ctx->tx_queue_id   = tx_queue_id;
    ctx->running       = true;   /* true before lcore launch so shaper_stop() is never a no-op */

    /* Create rte_hash for hw_rule_id → slot index mapping */
    struct rte_hash_parameters hash_params = {
        .name       = "shaper_rule_map",
        .entries    = SHAPER_MAX_FLOWS,
        .key_len    = sizeof(uint32_t),
        .hash_func  = rte_jhash,
        .socket_id  = (int)rte_socket_id(),
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY,
    };
    ctx->rule_id_map = rte_hash_create(&hash_params);
    if (!ctx->rule_id_map) {
        DOCA_LOG_ERR("Failed to create shaper rte_hash (entries=%u)",
                     SHAPER_MAX_FLOWS);
        return;
    }

    DOCA_LOG_INFO("Shaper init: proxy_port=%u rx_base=%u rx_queues=%u "
                  "tx_queue=%u max_flows=%u",
                  proxy_port_id, rx_queue_base, nr_rx_queues,
                  tx_queue_id, SHAPER_MAX_FLOWS);
}

int
shaper_register_flow(shaper_ctx_t *ctx,
                     uint32_t hw_rule_id,
                     uint8_t direction,
                     uint64_t gbr_kbps,
                     uint64_t mbr_kbps)
{
    if (!ctx->rule_id_map)
        return -1;

    /* EIR = MBR − GBR.  If MBR <= GBR, shaping rate is 0 (drop all YELLOW) */
    uint64_t eir_kbps = (mbr_kbps > gbr_kbps) ? (mbr_kbps - gbr_kbps) : 0;

    /* Add to hash — rte_hash_add_key returns the slot index */
    int idx = rte_hash_add_key(ctx->rule_id_map, &hw_rule_id);
    if (idx < 0) {
        DOCA_LOG_ERR("shaper register: hash add failed hw_rule_id=%u "
                     "(rc=%d, table full?)", hw_rule_id, idx);
        return -1;
    }

    shaper_flow_t *flow = &ctx->flows[idx];
    flow->hw_rule_id         = hw_rule_id;
    flow->direction          = direction;
    flow->rate_bytes_per_sec = kbps_to_bytes_per_sec(eir_kbps);
    flow->tokens             = SHAPER_BURST_BYTES;
    flow->max_tokens         = SHAPER_BURST_BYTES;
    flow->last_refill_tsc    = rte_rdtsc();
    flow->passed             = 0;
    flow->dropped            = 0;
    /* Release fence: all fields above are visible to the shaper lcore
     * before it observes active==true via ACQUIRE load in lookup_flow. */
    __atomic_store_n(&flow->active, true, __ATOMIC_RELEASE);

    DOCA_LOG_INFO("shaper register: hw_rule_id=%u dir=%s "
                  "gbr=%lu mbr=%lu eir=%lu kbps slot=%d",
                  hw_rule_id,
                  (direction == HW_DIR_UPLINK) ? "UL" : "DL",
                  (unsigned long)gbr_kbps, (unsigned long)mbr_kbps,
                  (unsigned long)eir_kbps, idx);
    return 0;
}

void
shaper_unregister_flow(shaper_ctx_t *ctx, uint32_t hw_rule_id)
{
    if (!ctx->rule_id_map)
        return;

    int idx = rte_hash_lookup(ctx->rule_id_map, &hw_rule_id);
    if (idx < 0)
        return;

    shaper_flow_t *flow = &ctx->flows[idx];

    DOCA_LOG_INFO("shaper unregister: hw_rule_id=%u "
                  "passed=%lu dropped=%lu",
                  hw_rule_id,
                  (unsigned long)flow->passed,
                  (unsigned long)flow->dropped);

    /* Release fence: shaper lcore sees active==false via ACQUIRE load
     * BEFORE we remove the hash entry, preventing a window where the
     * hash lookup succeeds but the slot is being reused. */
    __atomic_store_n(&flow->active, false, __ATOMIC_RELEASE);
    rte_hash_del_key(ctx->rule_id_map, &hw_rule_id);
}

int
shaper_update_rate(shaper_ctx_t *ctx,
                   uint32_t hw_rule_id,
                   uint64_t gbr_kbps,
                   uint64_t mbr_kbps)
{
    shaper_flow_t *flow = lookup_flow(ctx, hw_rule_id);
    if (!flow) {
        DOCA_LOG_WARN("shaper update_rate: hw_rule_id=%u not found",
                      hw_rule_id);
        return -1;
    }

    uint64_t eir_kbps = (mbr_kbps > gbr_kbps) ? (mbr_kbps - gbr_kbps) : 0;
    __atomic_store_n(&flow->rate_bytes_per_sec,
                     kbps_to_bytes_per_sec(eir_kbps), __ATOMIC_RELAXED);

    /* Don't reset tokens — let the bucket drain/fill naturally */

    DOCA_LOG_INFO("shaper update_rate: hw_rule_id=%u "
                  "gbr=%lu mbr=%lu eir=%lu kbps",
                  hw_rule_id,
                  (unsigned long)gbr_kbps, (unsigned long)mbr_kbps,
                  (unsigned long)eir_kbps);
    return 0;
}

int
shaper_loop(void *arg)
{
    shaper_ctx_t *ctx = (shaper_ctx_t *)arg;
    struct rte_mbuf *rx_bufs[SHAPER_RX_BURST];
    struct rte_mbuf *tx_bufs[SHAPER_RX_BURST];

    /* running was already set true in shaper_init — do NOT re-set here
     * to avoid a race where shaper_stop() between launch and this point
     * would be overwritten. */

    DOCA_LOG_INFO("Shaper loop started on lcore %u: "
                  "proxy_port=%u rx_base=%u rx_queues=%u tx_queue=%u",
                  rte_lcore_id(), ctx->proxy_port_id,
                  ctx->rx_queue_base, ctx->nr_rx_queues, ctx->tx_queue_id);

    while (ctx->running) {
        for (uint16_t q = 0; q < ctx->nr_rx_queues; q++) {
            uint16_t qid = ctx->rx_queue_base + q;
            uint16_t nb_rx = rte_eth_rx_burst(ctx->proxy_port_id,
                                               qid, rx_bufs, SHAPER_RX_BURST);
            if (nb_rx == 0)
                continue;

            uint64_t now_tsc = rte_rdtsc();
            uint16_t nb_tx = 0;

            for (uint16_t i = 0; i < nb_rx; i++) {
                /*
                 * Extract hw_rule_id from pkt_meta.
                 * The match pipe set pkt_meta = htonl(hw_rule_id) and
                 * DOCA Flow preserves it across the RSS redirect.
                 */
                uint32_t meta = rte_flow_dynf_metadata_get(rx_bufs[i]);
                uint32_t rule_id = ntohl(meta);

                shaper_flow_t *flow = lookup_flow(ctx, rule_id);
                if (!flow) {
                    /* Unknown flow — shouldn't happen; drop */
                    rte_pktmbuf_free(rx_bufs[i]);
                    continue;
                }

                /* Token bucket: refill, then try to consume */
                token_refill(flow, now_tsc);

                uint32_t pkt_len = rte_pktmbuf_pkt_len(rx_bufs[i]);
                if (!token_consume(flow, pkt_len)) {
                    /* Over EIR — drop */
                    flow->dropped++;
                    rte_pktmbuf_free(rx_bufs[i]);
                    continue;
                }

                flow->passed++;

                /* Stamp reinject metadata marker (same scheme as buffer) */
                uint32_t base = htonl(rule_id) & ~REINJECT_BITS_MASK;
                uint32_t marker;
                if (flow->direction == HW_DIR_UPLINK)
                    marker = base | REINJECT_MARKER_BIT | REINJECT_UL_DIR_BIT;
                else
                    marker = base | REINJECT_MARKER_BIT;

                rte_flow_dynf_metadata_set(rx_bufs[i], marker);
                rx_bufs[i]->ol_flags |= RTE_MBUF_DYNFLAG_TX_METADATA;

                tx_bufs[nb_tx++] = rx_bufs[i];
            }

            /* Burst Tx for conforming packets */
            if (nb_tx > 0) {
                uint16_t sent = rte_eth_tx_burst(ctx->proxy_port_id,
                                                  ctx->tx_queue_id,
                                                  tx_bufs, nb_tx);
                /* Free unsent packets */
                for (uint16_t i = sent; i < nb_tx; i++)
                    rte_pktmbuf_free(tx_bufs[i]);
            }
        }
    }

    DOCA_LOG_INFO("Shaper loop exiting on lcore %u", rte_lcore_id());
    return 0;
}

void
shaper_stop(shaper_ctx_t *ctx)
{
    ctx->running = false;
}

void
shaper_destroy(shaper_ctx_t *ctx)
{
    /* Log per-flow stats */
    for (int i = 0; i < SHAPER_MAX_FLOWS; i++) {
        if (ctx->flows[i].active) {
            DOCA_LOG_INFO("shaper flow[%d]: hw_rule_id=%u "
                          "passed=%lu dropped=%lu",
                          i, ctx->flows[i].hw_rule_id,
                          (unsigned long)ctx->flows[i].passed,
                          (unsigned long)ctx->flows[i].dropped);
        }
    }

    if (ctx->rule_id_map) {
        rte_hash_free(ctx->rule_id_map);
        ctx->rule_id_map = NULL;
    }

    DOCA_LOG_INFO("Shaper destroyed");
}
