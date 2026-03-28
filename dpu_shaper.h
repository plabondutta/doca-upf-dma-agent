/*
 * dpu_shaper.h — DPU ARM-side token-bucket shaper for GBR YELLOW packets
 *
 * When a GBR flow's trTCM meter marks a packet YELLOW (between GBR and
 * MBR), the SHAPED color-gate pipe forwards it to ARM Rx queues via RSS.
 * This module shapes those YELLOW packets at the Excess Information Rate
 * (EIR = MBR − GBR) using a per-flow token bucket, then reinjects
 * conforming packets into the eSwitch.
 *
 * Packets that exceed the token bucket are dropped (they've already
 * exceeded MBR since GREEN consumed GBR and shaped YELLOW consumed EIR).
 *
 * Reinject markers reuse the same 2-bit scheme as the buffer module:
 *   UL: pkt_meta = htonl(hw_rule_id) | REINJECT_MARKER_BIT | REINJECT_UL_DIR_BIT
 *   DL: pkt_meta = htonl(hw_rule_id) | REINJECT_MARKER_BIT
 *
 * Thread model: shaper_loop runs on a dedicated lcore (Core 2),
 * polling Rx queues 4-7.  Registration/unregistration is called from
 * the Comch callback thread (Core 0), protected by rte_hash atomicity.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>

#include <rte_mbuf.h>
#include <rte_hash.h>

#include "dpu_pipeline.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Limits ─────────────────────────────────────────────────────────── */
#define SHAPER_MAX_FLOWS     MAX_HW_RULES
#define SHAPER_BURST_BYTES   (64 * 1024)   /* max burst: 64 KB per flow   */
#define SHAPER_RX_BURST      32             /* rte_eth_rx_burst batch size */

/* ── Per-flow shaper slot ───────────────────────────────────────────── */
typedef struct {
    /* Cross-lcore synchronisation:
     *   active             — written with RELEASE by Comch thread,
     *                        read with ACQUIRE by shaper lcore.
     *   rate_bytes_per_sec — written with RELAXED store by Comch thread,
     *                        read with RELAXED load by shaper lcore.
     * Other fields are only written at register time (before the RELEASE
     * store of active) and read after the ACQUIRE load succeeds. */
    bool     active;             /* slot in use (atomic, see above)      */
    uint32_t hw_rule_id;         /* unique rule ID for this flow         */
    uint8_t  direction;          /* HW_DIR_UPLINK / HW_DIR_DOWNLINK     */

    /* Token bucket (byte-based) */
    uint64_t rate_bytes_per_sec; /* EIR = (MBR − GBR), bytes/sec (atomic) */
    uint64_t tokens;             /* current token count (bytes)          */
    uint64_t max_tokens;         /* = SHAPER_BURST_BYTES                */
    uint64_t last_refill_tsc;    /* TSC at last refill                  */

    /* Stats */
    uint64_t passed;
    uint64_t dropped;
} shaper_flow_t;

/* ── Shaper context (single instance on ARM) ────────────────────────── */
typedef struct {
    shaper_flow_t    flows[SHAPER_MAX_FLOWS];
    struct rte_hash *rule_id_map;     /* hw_rule_id → flows[] index       */

    /* DPDK Rx/Tx for the proxy port */
    uint16_t         proxy_port_id;
    uint16_t         nr_rx_queues;    /* number of shaper Rx queues       */
    uint16_t         rx_queue_base;   /* first Rx queue ID (e.g., 4)      */
    uint16_t         tx_queue_id;     /* Tx queue for reinject            */

    volatile bool    running;
} shaper_ctx_t;


/* ═══════════════════════════════════════════════════════════════════════
 *  API
 * ═══════════════════════════════════════════════════════════════════════ */

/**
 * Initialise the shaper context and create the rte_hash lookup table.
 *
 * @param ctx            Shaper context (caller-allocated, zero-initialised)
 * @param proxy_port_id  DPDK port ID for the switch proxy port
 * @param rx_queue_base  First Rx queue ID assigned to shaper (e.g. 4)
 * @param nr_rx_queues   Number of Rx queues for shaper RSS
 * @param tx_queue_id    Tx queue ID for reinject
 */
void shaper_init(shaper_ctx_t *ctx,
                 uint16_t proxy_port_id,
                 uint16_t rx_queue_base,
                 uint16_t nr_rx_queues,
                 uint16_t tx_queue_id);

/**
 * Register a GBR flow for shaping.
 *
 * @param ctx           Shaper context
 * @param hw_rule_id    Globally unique rule ID
 * @param direction     HW_DIR_UPLINK or HW_DIR_DOWNLINK
 * @param gbr_kbps      Guaranteed Bit Rate (kbps)
 * @param mbr_kbps      Maximum Bit Rate (kbps)
 * @return              0 on success, -1 on failure (table full / hash error)
 */
int shaper_register_flow(shaper_ctx_t *ctx,
                         uint32_t hw_rule_id,
                         uint8_t direction,
                         uint64_t gbr_kbps,
                         uint64_t mbr_kbps);

/**
 * Unregister a flow from the shaper (called on rule delete or GBR→0).
 *
 * @param ctx           Shaper context
 * @param hw_rule_id    Globally unique rule ID
 */
void shaper_unregister_flow(shaper_ctx_t *ctx,
                            uint32_t hw_rule_id);

/**
 * Update shaping rate for an existing flow (called on QER update).
 *
 * @param ctx           Shaper context
 * @param hw_rule_id    Globally unique rule ID
 * @param gbr_kbps      New GBR (kbps)
 * @param mbr_kbps      New MBR (kbps)
 * @return              0 on success, -1 if flow not found
 */
int shaper_update_rate(shaper_ctx_t *ctx,
                       uint32_t hw_rule_id,
                       uint64_t gbr_kbps,
                       uint64_t mbr_kbps);

/**
 * Shaper Rx/Tx loop — runs on a dedicated lcore.
 * Polls shaper Rx queues, identifies flows via pkt_meta, applies
 * per-flow token bucket, and reinjects conforming packets via Tx.
 *
 * @param arg   Pointer to shaper_ctx_t
 * @return      0 on exit
 */
int shaper_loop(void *arg);

/**
 * Signal the shaper loop to stop.
 */
void shaper_stop(shaper_ctx_t *ctx);

/**
 * Destroy shaper context and free rte_hash.
 */
void shaper_destroy(shaper_ctx_t *ctx);

#ifdef __cplusplus
}
#endif
