/*
 * dpu_buffer.c — DPU ARM-side per-flow packet buffering (rte_ring based)
 *
 * Uses DPDK rte_ring in SPSC (single-producer, single-consumer) mode
 * for lockless thread safety between the Rx lcore (enqueue) and the
 * Comch callback thread (drain/unregister).
 *
 * Rings are created on first register_flow and persist until
 * dpu_buffer_destroy() (shutdown).  unregister_flow flushes the ring
 * but does NOT free it, avoiding a free-while-enqueue race with the
 * Rx lcore.  The ring is reused if the same flow slot is re-registered.
 *
 * State machine:
 *   FORW path: ACTIVE → DRAINING → CLOSED
 *     Rx lcore owns drain + pass-through in DRAINING state (Option A).
 *     Main thread waits for drain_done before switching HW.
 *   DROP/DELETE path: ACTIVE → CLOSING → CLOSED
 *     HW source cut first, quiesce on enq_seq/deq_seq, then discard.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <stdio.h>

#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ring.h>

#include <doca_log.h>

#include "dpu_buffer.h"
#include "hw_offload_msg.h"

DOCA_LOG_REGISTER(DPU_BUFFER);

/* ── Internal helpers ───────────────────────────────────────────────── */

/**
 * Find a flow by hw_rule_id.  Returns any non-INACTIVE flow (ACTIVE,
 * DRAINING, CLOSING, or CLOSED) so that state-transition APIs can
 * locate them regardless of current lifecycle stage.
 */
static dpu_buffer_flow_t *
find_flow(dpu_buffer_ctx_t *ctx, uint32_t hw_rule_id)
{
    for (uint32_t i = 0; i < DPU_BUFFER_MAX_FLOWS; i++) {
        uint32_t st = __atomic_load_n(&ctx->flows[i].state, __ATOMIC_ACQUIRE);
        if (st != DPU_BUF_INACTIVE &&
            ctx->flows[i].hw_rule_id == hw_rule_id)
            return &ctx->flows[i];
    }
    return NULL;
}

/**
 * Allocate a free flow slot.  Accepts INACTIVE or CLOSED slots.
 */
static dpu_buffer_flow_t *
alloc_flow(dpu_buffer_ctx_t *ctx)
{
    for (uint32_t i = 0; i < DPU_BUFFER_MAX_FLOWS; i++) {
        uint32_t st = __atomic_load_n(&ctx->flows[i].state, __ATOMIC_ACQUIRE);
        if (st == DPU_BUF_INACTIVE || st == DPU_BUF_CLOSED)
            return &ctx->flows[i];
    }
    return NULL;
}

/** Flush all remaining packets from a flow's ring. */
static uint32_t
ring_flush(dpu_buffer_ctx_t *ctx, dpu_buffer_flow_t *flow)
{
    if (!flow->ring)
        return 0;

    struct rte_mbuf *mbuf;
    uint32_t flushed = 0;
    while (rte_ring_sc_dequeue(flow->ring, (void **)&mbuf) == 0) {
        rte_pktmbuf_free(mbuf);
        flushed++;
    }
    if (flushed > 0)
        __atomic_fetch_sub(&ctx->global_count, flushed, __ATOMIC_RELAXED);
    return flushed;
}


/**
 * Stamp reinject metadata and Tx-burst a batch of packets.
 * Computes the per-direction marker once and applies to all packets.
 * Frees any packets that rte_eth_tx_burst fails to send.
 *
 * @return  Number of packets successfully transmitted.
 */
static uint16_t
reinject_burst(dpu_buffer_ctx_t *ctx, dpu_buffer_flow_t *flow,
               struct rte_mbuf **pkts, uint16_t nb_pkts)
{
    uint32_t base = htonl(flow->hw_rule_id) & ~REINJECT_BITS_MASK;
    uint32_t marker;
    if (flow->direction == HW_DIR_UPLINK)
        marker = base | REINJECT_MARKER_BIT | REINJECT_UL_DIR_BIT;
    else
        marker = base | REINJECT_MARKER_BIT;

    for (uint16_t i = 0; i < nb_pkts; i++) {
        rte_flow_dynf_metadata_set(pkts[i], marker);
        pkts[i]->ol_flags |= RTE_MBUF_DYNFLAG_TX_METADATA;
    }

    uint16_t sent = rte_eth_tx_burst(ctx->proxy_port_id,
                                      ctx->tx_queue_id,
                                      pkts, nb_pkts);
    for (uint16_t i = sent; i < nb_pkts; i++)
        rte_pktmbuf_free(pkts[i]);

    return sent;
}


/* ═══════════════════════════════════════════════════════════════════════
 *  Public API
 * ═══════════════════════════════════════════════════════════════════════ */

void
dpu_buffer_init(dpu_buffer_ctx_t *ctx,
                uint16_t proxy_port_id,
                uint16_t nr_rx_queues,
                uint16_t tx_queue_id,
                dpu_pipeline_ctx_t *pipeline)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->proxy_port_id = proxy_port_id;
    ctx->nr_rx_queues  = nr_rx_queues;
    ctx->tx_queue_id   = tx_queue_id;
    ctx->pipeline      = pipeline;
    ctx->running       = true;

    DOCA_LOG_INFO("Buffer init: proxy_port=%u rx_queues=%u tx_queue=%u",
                  proxy_port_id, nr_rx_queues, tx_queue_id);
}

int
dpu_buffer_register_flow(dpu_buffer_ctx_t *ctx,
                         uint32_t hw_rule_id,
                         uint8_t direction)
{
    /* Check if already registered.  A CLOSED flow for the same
     * hw_rule_id is NOT "already registered" — it completed a previous
     * BUFF cycle and must be re-activated for the new BUFF request. */
    dpu_buffer_flow_t *flow = find_flow(ctx, hw_rule_id);
    if (flow) {
        uint32_t st = __atomic_load_n(&flow->state, __ATOMIC_ACQUIRE);
        if (st == DPU_BUF_ACTIVE) {
            DOCA_LOG_DBG("buffer: flow hw_rule_id=%u already ACTIVE",
                         hw_rule_id);
            return 0;
        }
        if (st == DPU_BUF_DRAINING) {
            DOCA_LOG_WARN("buffer: flow hw_rule_id=%u still DRAINING "
                          "from previous FORW cycle \u2014 refusing registration",
                          hw_rule_id);
            return -1;
        }
        if (st == DPU_BUF_CLOSING) {
            DOCA_LOG_WARN("buffer: flow hw_rule_id=%u still CLOSING "
                          "from previous cycle \u2014 refusing registration",
                          hw_rule_id);
            return -1;
        }
        /* CLOSED: reuse this slot — fall through to re-initialise */
    } else {
        flow = alloc_flow(ctx);
        if (!flow) {
            DOCA_LOG_ERR("buffer: no free flow slots for hw_rule_id=%u",
                         hw_rule_id);
            return -1;
        }
    }

    /* Create rte_ring if this slot hasn't been used before (or was
     * destroyed at shutdown).  If the ring already exists from a
     * previous register/unregister cycle, flush any stale mbufs
     * (possible from the Rx-lcore enqueue-after-unregister race)
     * before resetting for reuse. */
    if (flow->ring) {
        ring_flush(ctx, flow);
        rte_ring_reset(flow->ring);
    } else {
        char name[RTE_RING_NAMESIZE];
        snprintf(name, sizeof(name), "buf_%u", hw_rule_id);
        flow->ring = rte_ring_create(name, DPU_BUFFER_PER_FLOW,
                                      rte_socket_id(),
                                      RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (!flow->ring) {
            DOCA_LOG_ERR("buffer: rte_ring_create failed for hw_rule_id=%u",
                         hw_rule_id);
            return -1;
        }
    }

    flow->hw_rule_id  = hw_rule_id;
    flow->direction   = direction;
    flow->enqueued    = 0;
    flow->dropped     = 0;
    flow->drained     = 0;
    flow->passthrough = 0;
    flow->requeued    = 0;

    /* Reset quiesce sequence counters and drain signalling */
    __atomic_store_n(&flow->enq_seq, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&flow->deq_seq, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&flow->drain_done, 0, __ATOMIC_RELAXED);

    /* Publish state=ACTIVE last (release semantics) so the Rx lcore
     * sees a fully initialised flow when it observes state==ACTIVE. */
    __atomic_store_n(&flow->state, DPU_BUF_ACTIVE, __ATOMIC_RELEASE);

    DOCA_LOG_INFO("buffer: registered flow hw_rule_id=%u dir=%s",
                  hw_rule_id,
                  direction == HW_DIR_UPLINK ? "UL" : "DL");
    return 0;
}

void
dpu_buffer_unregister_flow(dpu_buffer_ctx_t *ctx,
                           uint32_t hw_rule_id)
{
    dpu_buffer_flow_t *flow = find_flow(ctx, hw_rule_id);
    if (!flow) return;

    uint32_t prev_st = __atomic_load_n(&flow->state, __ATOMIC_ACQUIRE);

    /* Mark inactive immediately (release semantics).  This is the
     * fast-path rollback — no quiesce needed because the flow was
     * just registered and the HW fwd is being rolled back. */
    __atomic_store_n(&flow->state, DPU_BUF_INACTIVE, __ATOMIC_RELEASE);

    if (prev_st == DPU_BUF_DRAINING)
        __atomic_fetch_sub(&ctx->nr_draining, 1, __ATOMIC_RELEASE);

    /* Flush residual packets (ring is NOT freed — reused on next register,
     * freed at shutdown by dpu_buffer_destroy). */
    uint32_t flushed = ring_flush(ctx, flow);

    DOCA_LOG_INFO("buffer: unregistered flow hw_rule_id=%u "
                  "(flushed %u queued, enq=%lu drop=%lu drain=%lu)",
                  hw_rule_id, flushed,
                  (unsigned long)flow->enqueued,
                  (unsigned long)flow->dropped,
                  (unsigned long)flow->drained);
}

int
dpu_buffer_drain_flow(dpu_buffer_ctx_t *ctx,
                      uint32_t hw_rule_id)
{
    dpu_buffer_flow_t *flow = find_flow(ctx, hw_rule_id);
    if (!flow) {
        DOCA_LOG_WARN("buffer drain: hw_rule_id=%u not found", hw_rule_id);
        return -1;
    }
    if (!flow->ring)
        return 0;

    uint32_t total_drained = 0;

    /*
     * Drain in batches of 32 via rte_ring_sc_dequeue_burst.
     * Set reinject metadata marker before TX:
     *   UL: pkt_meta = htonl(hw_rule_id) | REINJECT_MARKER_BIT | REINJECT_UL_DIR_BIT
     *       ROOT entry matches pkt_meta bits 0-1 == 0x03 → fwd to N6
     *   DL: pkt_meta = htonl(hw_rule_id) | REINJECT_MARKER_BIT
     *       ROOT entry matches pkt_meta bits 0-1 == 0x01 → fwd to N3
     *       N3 egress → DL_ENCAP matches pkt_meta (mask ignores bits 0-1)
     */
    struct rte_mbuf *tx_bufs[32];

    for (;;) {
        unsigned int nb_deq = rte_ring_sc_dequeue_burst(
            flow->ring, (void **)tx_bufs, 32, NULL);
        if (nb_deq == 0)
            break;

        __atomic_fetch_sub(&ctx->global_count, nb_deq, __ATOMIC_RELAXED);

        /* Stamp reinject metadata on each packet.
         * Clear bits 0-1 of htonl(hw_rule_id) before OR'ing markers
         * to avoid collision when hw_rule_id is large enough that
         * htonl() produces non-zero low bits (bits 24-25 of input). */
        uint32_t base = htonl(hw_rule_id) & ~REINJECT_BITS_MASK;
        for (unsigned int i = 0; i < nb_deq; i++) {
            uint32_t marker;
            if (flow->direction == HW_DIR_UPLINK)
                marker = base | REINJECT_MARKER_BIT | REINJECT_UL_DIR_BIT;
            else
                marker = base | REINJECT_MARKER_BIT;

            rte_flow_dynf_metadata_set(tx_bufs[i], marker);
            tx_bufs[i]->ol_flags |= RTE_MBUF_DYNFLAG_TX_METADATA;
        }

        uint16_t sent = rte_eth_tx_burst(ctx->proxy_port_id,
                                          ctx->tx_queue_id,
                                          tx_bufs, (uint16_t)nb_deq);
        /* Free any unsent packets */
        for (uint16_t i = sent; i < nb_deq; i++)
            rte_pktmbuf_free(tx_bufs[i]);

        total_drained += sent;
    }

    flow->drained += total_drained;

    DOCA_LOG_INFO("buffer drain: hw_rule_id=%u drained %u pkts "
                  "(total: enq=%lu drop=%lu drain=%lu)",
                  hw_rule_id, total_drained,
                  (unsigned long)flow->enqueued,
                  (unsigned long)flow->dropped,
                  (unsigned long)flow->drained);

    return (int)total_drained;
}

/* ═══════════════════════════════════════════════════════════════════════
 *  Rx-owned drain API (FORW path: begin_drain / wait_drain_done / close)
 * ═══════════════════════════════════════════════════════════════════════ */

int
dpu_buffer_begin_drain(dpu_buffer_ctx_t *ctx,
                       uint32_t hw_rule_id)
{
    dpu_buffer_flow_t *flow = find_flow(ctx, hw_rule_id);
    if (!flow) {
        DOCA_LOG_DBG("begin_drain: hw_rule_id=%u not registered", hw_rule_id);
        return -1;
    }

    uint32_t st = __atomic_load_n(&flow->state, __ATOMIC_ACQUIRE);
    if (st == DPU_BUF_DRAINING)
        return 0;  /* idempotent */

    if (st != DPU_BUF_ACTIVE) {
        DOCA_LOG_WARN("begin_drain: hw_rule_id=%u unexpected state=%u "
                      "(expected ACTIVE)", hw_rule_id, st);
        return -1;
    }

    __atomic_store_n(&flow->drain_done, 0, __ATOMIC_RELAXED);

    /* ACTIVE → DRAINING: Rx lcore will drain ring + pass-through.
     * HW must still point to TO_DPU_ARM at this point. */
    __atomic_store_n(&flow->state, DPU_BUF_DRAINING, __ATOMIC_RELEASE);
    __atomic_fetch_add(&ctx->nr_draining, 1, __ATOMIC_RELEASE);

    DOCA_LOG_INFO("begin_drain: hw_rule_id=%u ACTIVE \u2192 DRAINING "
                  "(ring_count=%u)", hw_rule_id,
                  flow->ring ? rte_ring_count(flow->ring) : 0);
    return 0;
}

int
dpu_buffer_wait_drain_done(dpu_buffer_ctx_t *ctx,
                           uint32_t hw_rule_id)
{
    dpu_buffer_flow_t *flow = find_flow(ctx, hw_rule_id);
    if (!flow)
        return -1;

    uint32_t st = __atomic_load_n(&flow->state, __ATOMIC_ACQUIRE);
    if (st != DPU_BUF_DRAINING) {
        DOCA_LOG_WARN("wait_drain_done: hw_rule_id=%u not DRAINING (state=%u)",
                      hw_rule_id, st);
        return -1;
    }

    uint64_t deadline = rte_get_timer_cycles() +
        (uint64_t)DPU_BUFFER_QUIESCE_US * rte_get_timer_hz() / 1000000;

    while (!__atomic_load_n(&flow->drain_done, __ATOMIC_ACQUIRE)) {
        if (rte_get_timer_cycles() > deadline) {
            DOCA_LOG_ERR("wait_drain_done: timeout hw_rule_id=%u "
                         "(ring_count=%u) \u2014 flow stays DRAINING",
                         hw_rule_id,
                         flow->ring ? rte_ring_count(flow->ring) : 0);
            return -1;
        }
        rte_pause();
    }

    DOCA_LOG_INFO("wait_drain_done: hw_rule_id=%u drain complete "
                  "(drained=%lu passthrough=%lu)",
                  hw_rule_id,
                  (unsigned long)flow->drained,
                  (unsigned long)flow->passthrough);
    return 0;
}

int
dpu_buffer_close_flow(dpu_buffer_ctx_t *ctx,
                      uint32_t hw_rule_id)
{
    dpu_buffer_flow_t *flow = find_flow(ctx, hw_rule_id);
    if (!flow)
        return -1;

    uint32_t st = __atomic_load_n(&flow->state, __ATOMIC_ACQUIRE);
    if (st != DPU_BUF_DRAINING) {
        DOCA_LOG_WARN("close_flow: hw_rule_id=%u not DRAINING (state=%u)",
                      hw_rule_id, st);
        return -1;
    }

    /* DRAINING → CLOSED: Rx lcore stops accepting packets for this flow. */
    __atomic_store_n(&flow->state, DPU_BUF_CLOSED, __ATOMIC_RELEASE);
    __atomic_fetch_sub(&ctx->nr_draining, 1, __ATOMIC_RELEASE);

    /* Safety net: flush any residual packets that may have slipped
     * into the ring between the last drain and the CLOSED transition. */
    uint32_t residual = ring_flush(ctx, flow);

    DOCA_LOG_INFO("close_flow: hw_rule_id=%u DRAINING \u2192 CLOSED "
                  "(enq=%lu requeued=%lu drop=%lu drain=%lu "
                  "passthrough=%lu residual=%u)",
                  hw_rule_id,
                  (unsigned long)flow->enqueued,
                  (unsigned long)flow->requeued,
                  (unsigned long)flow->dropped,
                  (unsigned long)flow->drained,
                  (unsigned long)flow->passthrough,
                  residual);
    return 0;
}


/* ═══════════════════════════════════════════════════════════════════════
 *  DROP/DELETE path API (begin_close / quiesce_and_drain)
 * ═══════════════════════════════════════════════════════════════════════ */

int
dpu_buffer_begin_close(dpu_buffer_ctx_t *ctx,
                       uint32_t hw_rule_id)
{
    dpu_buffer_flow_t *flow = find_flow(ctx, hw_rule_id);
    if (!flow)
        return 0;  /* not registered — nothing to close */

    uint32_t st = __atomic_load_n(&flow->state, __ATOMIC_ACQUIRE);
    if (st == DPU_BUF_CLOSING || st == DPU_BUF_CLOSED)
        return 0;  /* idempotent */

    if (st != DPU_BUF_ACTIVE) {
        DOCA_LOG_WARN("begin_close: hw_rule_id=%u unexpected state=%u",
                      hw_rule_id, st);
        return 0;
    }

    /* ACTIVE → CLOSING: Rx lcore still accepts in-flight packets,
     * but the HW source should already be cut by the caller. */
    __atomic_store_n(&flow->state, DPU_BUF_CLOSING, __ATOMIC_RELEASE);

    DOCA_LOG_INFO("begin_close: hw_rule_id=%u ACTIVE → CLOSING",
                  hw_rule_id);
    return 0;
}

/**
 * Internal: drain ring contents via Tx reinject or discard.
 * Reuses the existing drain logic from dpu_buffer_drain_flow.
 */
static int
ring_drain_or_discard(dpu_buffer_ctx_t *ctx, dpu_buffer_flow_t *flow,
                      uint32_t hw_rule_id, bool discard)
{
    if (!flow->ring)
        return 0;

    uint32_t total = 0;
    struct rte_mbuf *tx_bufs[32];

    for (;;) {
        unsigned int nb_deq = rte_ring_sc_dequeue_burst(
            flow->ring, (void **)tx_bufs, 32, NULL);
        if (nb_deq == 0)
            break;

        __atomic_fetch_sub(&ctx->global_count, nb_deq, __ATOMIC_RELAXED);

        if (discard) {
            for (unsigned int i = 0; i < nb_deq; i++)
                rte_pktmbuf_free(tx_bufs[i]);
            total += nb_deq;
            continue;
        }

        /* Stamp reinject metadata */
        uint32_t base = htonl(hw_rule_id) & ~REINJECT_BITS_MASK;
        for (unsigned int i = 0; i < nb_deq; i++) {
            uint32_t marker;
            if (flow->direction == HW_DIR_UPLINK)
                marker = base | REINJECT_MARKER_BIT | REINJECT_UL_DIR_BIT;
            else
                marker = base | REINJECT_MARKER_BIT;

            rte_flow_dynf_metadata_set(tx_bufs[i], marker);
            tx_bufs[i]->ol_flags |= RTE_MBUF_DYNFLAG_TX_METADATA;
        }

        uint16_t sent = rte_eth_tx_burst(ctx->proxy_port_id,
                                          ctx->tx_queue_id,
                                          tx_bufs, (uint16_t)nb_deq);
        for (uint16_t i = sent; i < nb_deq; i++)
            rte_pktmbuf_free(tx_bufs[i]);

        total += sent;
    }

    return (int)total;
}

int
dpu_buffer_quiesce_and_drain(dpu_buffer_ctx_t *ctx,
                             uint32_t hw_rule_id,
                             bool discard)
{
    dpu_buffer_flow_t *flow = find_flow(ctx, hw_rule_id);
    if (!flow)
        return 0;  /* not registered */

    uint32_t st = __atomic_load_n(&flow->state, __ATOMIC_ACQUIRE);
    if (st == DPU_BUF_INACTIVE || st == DPU_BUF_CLOSED)
        return 0;  /* nothing to do */
    if (st == DPU_BUF_DRAINING) {
        DOCA_LOG_WARN("quiesce_and_drain: hw_rule_id=%u is DRAINING "
                      "(use wait_drain_done + close_flow instead)",
                      hw_rule_id);
        return -1;
    }

    /* ── Quiesce loop: wait for Rx in-flight packets to complete ── */
    uint64_t deadline = rte_get_timer_cycles() +
        (uint64_t)DPU_BUFFER_QUIESCE_US * rte_get_timer_hz() / 1000000;

    for (;;) {
        uint64_t enq = __atomic_load_n(&flow->enq_seq, __ATOMIC_ACQUIRE);
        uint64_t deq = __atomic_load_n(&flow->deq_seq, __ATOMIC_ACQUIRE);

        if (enq == deq) {
            /* Stability double-read: verify enq_seq hasn't changed */
            if (__atomic_load_n(&flow->enq_seq, __ATOMIC_ACQUIRE) == enq)
                break;  /* Truly quiesced */
        }

        if (rte_get_timer_cycles() > deadline) {
            DOCA_LOG_ERR("quiesce timeout hw_rule_id=%u "
                         "enq_seq=%lu deq_seq=%lu — keeping CLOSING",
                         hw_rule_id,
                         (unsigned long)enq, (unsigned long)deq);
            return -1;  /* Stay CLOSING — do NOT set CLOSED */
        }

        rte_pause();
    }

    /* ── Drain or discard ring contents ──────────────────────────── */
    int drained = ring_drain_or_discard(ctx, flow, hw_rule_id, discard);
    flow->drained += (drained > 0 ? (uint64_t)drained : 0);

    /* Flush any residual (safety net) */
    ring_flush(ctx, flow);

    /* ── Transition to CLOSED ────────────────────────────────────── */
    __atomic_store_n(&flow->state, DPU_BUF_CLOSED, __ATOMIC_RELEASE);

    DOCA_LOG_INFO("quiesce_and_drain: hw_rule_id=%u %s %d pkts "
                  "(enq=%lu drop=%lu drain=%lu) → CLOSED",
                  hw_rule_id, discard ? "discarded" : "reinjected",
                  drained,
                  (unsigned long)flow->enqueued,
                  (unsigned long)flow->dropped,
                  (unsigned long)flow->drained);

    return drained;
}

int
dpu_buffer_rx_loop(void *arg)
{
    dpu_buffer_ctx_t *ctx = (dpu_buffer_ctx_t *)arg;
    struct rte_mbuf *rx_bufs[32];

    DOCA_LOG_INFO("Buffer Rx loop started on lcore %u: "
                  "proxy_port=%u rx_queues=%u",
                  rte_lcore_id(), ctx->proxy_port_id, ctx->nr_rx_queues);

    while (ctx->running) {
        /*
         * ── Phase 1: service DRAINING flows (Rx-owned ring drain) ──
         *
         * drain_done is ONLY set here (never in Phase 2).  This ensures
         * that when the main thread observes drain_done=1, Phase 2 of
         * the previous iteration has fully completed — meaning all
         * Rx queue packets have been processed (pass-through reinjected
         * or enqueued for other states).  This is the strongest fence
         * we can provide: at least one full Rx burst cycle has passed
         * since the ring was emptied.
         *
         * Also handles the "no new traffic" edge case: drains the ring
         * progressively in bounded chunks (32 pkts) to avoid starving
         * Rx queue processing.  Early-exit once all DRAINING flows
         * are visited.
         */
        uint32_t nr_drain = __atomic_load_n(&ctx->nr_draining,
                                            __ATOMIC_ACQUIRE);
        if (nr_drain > 0) {
            for (uint32_t f = 0;
                 f < DPU_BUFFER_MAX_FLOWS && nr_drain > 0; f++) {
                dpu_buffer_flow_t *fl = &ctx->flows[f];
                if (__atomic_load_n(&fl->state, __ATOMIC_ACQUIRE)
                    != DPU_BUF_DRAINING)
                    continue;
                nr_drain--;

                if (__atomic_load_n(&fl->drain_done, __ATOMIC_RELAXED))
                    continue;

                struct rte_mbuf *drain_bufs[32];
                unsigned int nb = rte_ring_sc_dequeue_burst(
                    fl->ring, (void **)drain_bufs, 32, NULL);
                if (nb > 0) {
                    __atomic_fetch_sub(&ctx->global_count,
                                       nb, __ATOMIC_RELAXED);
                    fl->drained += reinject_burst(ctx, fl,
                                                  drain_bufs, (uint16_t)nb);
                } else {
                    __atomic_store_n(&fl->drain_done, 1, __ATOMIC_RELEASE);
                }
            }
        }

        /*
         * ── Phase 2: Rx burst processing ───────────────────────────
         */
        for (uint16_t q = 0; q < ctx->nr_rx_queues; q++) {
            uint16_t nb_rx = rte_eth_rx_burst(ctx->proxy_port_id,
                                               q, rx_bufs, 32);
            if (nb_rx == 0)
                continue;

            for (uint16_t i = 0; i < nb_rx; i++) {
                uint32_t meta = rte_flow_dynf_metadata_get(rx_bufs[i]);
                uint32_t rule_id = ntohl(meta);

                dpu_buffer_flow_t *flow = find_flow(ctx, rule_id);
                if (!flow) {
                    DOCA_LOG_DBG("buffer rx: no flow for rule_id=%u, "
                                "dropping", rule_id);
                    rte_pktmbuf_free(rx_bufs[i]);
                    continue;
                }

                uint32_t st = __atomic_load_n(&flow->state,
                                              __ATOMIC_ACQUIRE);

                /*
                 * DRAINING: bounded drain + conditional re-enqueue.
                 *
                 * Pull at most 32 old packets from the ring (bounded
                 * to avoid starving rte_eth_rx_burst for other flows).
                 * If old packets remain after the bounded drain, the
                 * new packet is enqueued at the ring TAIL — it sits
                 * behind old packets, preserving FIFO order, and will
                 * be drained by Phase 1 in a subsequent iteration.
                 * If the ring is empty, the new packet is pass-through
                 * reinjected directly (fast path).
                 *
                 * drain_done is NOT set here — Phase 1 handles it
                 * exclusively at the top of the next iteration.  This
                 * guarantees that when the main thread observes
                 * drain_done=1, at least one full Rx burst cycle has
                 * completed since the ring was emptied (i.e. Phase 2
                 * of the previous iteration has fully processed any
                 * Rx queue packets).
                 */
                if (st == DPU_BUF_DRAINING) {
                    if (!__atomic_load_n(&flow->drain_done,
                                         __ATOMIC_RELAXED)) {
                        /* Bounded drain: pull at most 32 old packets. */
                        struct rte_mbuf *drain_bufs[32];
                        unsigned int nb = rte_ring_sc_dequeue_burst(
                            flow->ring, (void **)drain_bufs, 32, NULL);
                        if (nb > 0) {
                            __atomic_fetch_sub(&ctx->global_count,
                                               nb, __ATOMIC_RELAXED);
                            flow->drained += reinject_burst(
                                ctx, flow, drain_bufs, (uint16_t)nb);
                        }

                        /* If old packets remain, enqueue new pkt at
                         * ring tail.  FIFO: it sits behind old pkts.
                         * Phase 1 will drain it in a future iteration. */
                        if (rte_ring_count(flow->ring) > 0) {
                            if (rte_ring_sp_enqueue(flow->ring,
                                                     rx_bufs[i]) == 0) {
                                __atomic_fetch_add(&ctx->global_count,
                                                   1, __ATOMIC_RELAXED);
                                flow->requeued++;
                            } else {
                                flow->dropped++;
                                rte_pktmbuf_free(rx_bufs[i]);
                            }
                            continue;
                        }
                    }
                    /* Ring is empty (or drain_done already set) —
                     * pass-through reinject directly. */
                    flow->passthrough += reinject_burst(
                        ctx, flow, &rx_bufs[i], 1);
                    continue;
                }

                /* ACTIVE / CLOSING: enqueue into per-flow ring.
                 * INACTIVE / CLOSED: reject (free). */
                if (st != DPU_BUF_ACTIVE && st != DPU_BUF_CLOSING) {
                    rte_pktmbuf_free(rx_bufs[i]);
                    continue;
                }

                __atomic_fetch_add(&flow->enq_seq, 1, __ATOMIC_RELEASE);

                if (__atomic_load_n(&ctx->global_count,
                                    __ATOMIC_RELAXED) >= DPU_BUFFER_GLOBAL_CAP) {
                    flow->dropped++;
                    rte_pktmbuf_free(rx_bufs[i]);
                    __atomic_fetch_add(&flow->deq_seq, 1, __ATOMIC_RELEASE);
                    continue;
                }

                if (rte_ring_sp_enqueue(flow->ring, rx_bufs[i]) != 0) {
                    flow->dropped++;
                    rte_pktmbuf_free(rx_bufs[i]);
                    __atomic_fetch_add(&flow->deq_seq, 1, __ATOMIC_RELEASE);
                    continue;
                }

                __atomic_fetch_add(&ctx->global_count, 1, __ATOMIC_RELAXED);
                flow->enqueued++;
                __atomic_fetch_add(&flow->deq_seq, 1, __ATOMIC_RELEASE);
            }
        }
    }

    DOCA_LOG_INFO("Buffer Rx loop exiting on lcore %u", rte_lcore_id());
    return 0;
}

void
dpu_buffer_stop(dpu_buffer_ctx_t *ctx)
{
    ctx->running = false;
}

void
dpu_buffer_destroy(dpu_buffer_ctx_t *ctx)
{
    for (uint32_t i = 0; i < DPU_BUFFER_MAX_FLOWS; i++) {
        dpu_buffer_flow_t *flow = &ctx->flows[i];
        if (flow->ring) {
            ring_flush(ctx, flow);
            rte_ring_free(flow->ring);
            flow->ring = NULL;
        }
    }
    DOCA_LOG_INFO("Buffer destroyed");
}
