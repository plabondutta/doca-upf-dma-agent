/*
 * dpu_buffer.h — DPU ARM-side per-flow packet buffering
 *
 * When the SMF sends UpdateFAR(BUFF), the DPU Agent swaps the per-entry
 * fwd from COLOR_GATE → TO_DPU_ARM.  Packets for that flow arrive via
 * RSS on ARM Rx queues, where this module stores them in per-flow
 * rte_ring queues (SPSC lockless) in BF3 DDR.
 *
 * On UpdateFAR(FORW), the buffer is drained with near-ordered delivery:
 *   1. Main thread sets state=DRAINING (HW still points to TO_DPU_ARM)
 *   2. Rx lcore performs bounded drain (≤32 pkts/iter) of old ring packets;
 *      if old packets remain, new arrivals are re-enqueued at ring tail
 *      (FIFO-preserving).  Once the ring is empty, new arrivals are
 *      pass-through reinjected directly (no enqueue).
 *   3. Main thread waits for drain_done, THEN switches HW to COLOR_GATE
 * This keeps all traffic on a single path (ARM reinject) during the
 * transition, preserving FIFO order within the Rx lcore's processing.
 *
 * Reinject markers (two-bit scheme in pkt_meta bits 0-1):
 *   UL packets: pkt_meta = htonl(hw_rule_id) | REINJECT_MARKER_BIT | REINJECT_UL_DIR_BIT
 *     → ROOT entry matches pkt_meta bits 0-1 == 0x03 → forwards to N6
 *   DL packets: pkt_meta = htonl(hw_rule_id) | REINJECT_MARKER_BIT
 *     → ROOT entry matches pkt_meta bits 0-1 == 0x01 → forwards to N3
 *     → N3 egress triggers DL_ENCAP (mask ignores bits 0-1) → encaps
 *
 * Thread safety:
 *   rte_ring provides lockless SPSC semantics (Rx lcore = producer,
 *   Comch thread = consumer).  global_count uses __atomic builtins.
 *   flow->state uses atomic store/load for cross-lcore visibility.
 *
 * State machine (per-flow):
 *   INACTIVE → ACTIVE (register)
 *   ACTIVE   → DRAINING (begin_drain)  [FORW path: Rx-owned drain]
 *   ACTIVE   → CLOSING  (begin_close)  [DROP/DELETE path: HW source cut]
 *   DRAINING → CLOSED   (close_flow)
 *   CLOSING  → CLOSED   (quiesce_and_drain)
 *
 *   ACTIVE:   Rx lcore enqueues into per-flow ring.
 *   DRAINING: Rx lcore bounded-drains ring; re-enqueues new pkts while
 *             ring non-empty, then pass-through reinjects once empty.
 *   CLOSING:  HW source cut; Rx still enqueues in-flight packets.
 *   CLOSED:   Rx rejects; safe to reuse slot.
 *   INACTIVE: Slot available.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>

#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ring.h>

#include "dpu_pipeline.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Per-flow buffer queue limits ───────────────────────────────────── */
#define DPU_BUFFER_MAX_FLOWS   MAX_HW_RULES
#define DPU_BUFFER_PER_FLOW    64     /* rte_ring capacity per flow       */
#define DPU_BUFFER_GLOBAL_CAP  16384  /* max pkts queued across all flows */
#define DPU_BUFFER_QUIESCE_US  100000 /* spin-loop safety timeout in µs (100ms)
                                       * Used by wait_drain_done (FORW path)
                                       * and quiesce_and_drain (DROP/DELETE).
                                       * Not an intentional delay — both loops
                                       * converge in microseconds normally.   */

/* ── Per-flow buffer state machine ─────────────────────────────────── */
enum dpu_buffer_state {
    DPU_BUF_INACTIVE = 0,  /* Slot available (initial / after CLOSED cleanup)  */
    DPU_BUF_ACTIVE   = 1,  /* Actively buffering; Rx lcore enqueues            */
    DPU_BUF_DRAINING = 2,  /* FORW transition: Rx drains ring + pass-through   */
    DPU_BUF_CLOSING  = 3,  /* DROP/DELETE: HW source cut; Rx accepts in-flight */
    DPU_BUF_CLOSED   = 4,  /* Quiesced + drained; Rx rejects; safe to reuse    */
};

/* ── Per-flow buffer slot ───────────────────────────────────────────── */
typedef struct {
    uint32_t state;                    /* enum dpu_buffer_state (atomic)   */
    uint32_t hw_rule_id;
    uint8_t  direction;                /* HW_DIR_UPLINK / HW_DIR_DOWNLINK */

    struct rte_ring *ring;             /* SPSC lockless ring (or NULL)     */

    /* Quiesce sequence counters (atomic, written by Rx lcore).
     * enq_seq: incremented BEFORE Rx processes a packet for this flow.
     * deq_seq: incremented AFTER Rx finishes (enqueue/drop/free).
     * Quiesce waits for enq_seq == deq_seq to prove no in-flight pkts.
     * Used by CLOSING (DROP/DELETE) path only. */
    uint64_t enq_seq;
    uint64_t deq_seq;

    /* Rx-owned drain signalling (DRAINING state, FORW path).
     * Set to 1 by Rx lcore when ring drain completes (release).
     * Polled by main thread via wait_drain_done (acquire). */
    uint32_t drain_done;               /* atomic: 0=pending, 1=complete   */

    /* Statistics (written by Rx lcore, read by main thread for logging) */
    uint64_t enqueued;
    uint64_t dropped;                  /* tail-drop when at per-flow cap  */
    uint64_t drained;
    uint64_t passthrough;              /* pass-through reinjected (DRAINING) */
    uint64_t requeued;                 /* new pkts re-enqueued at ring tail
                                        * during DRAINING (bounded drain)   */
} dpu_buffer_flow_t;

/* ── Buffer context (single instance on ARM) ────────────────────────── */
typedef struct {
    dpu_buffer_flow_t flows[DPU_BUFFER_MAX_FLOWS];
    uint32_t          global_count;    /* atomic: total pkts across flows */

    /* Drain coordination: incremented by begin_drain, decremented by
     * close_flow.  The Rx loop uses this as a fast check to skip the
     * DRAINING flow scan when no drains are active. */
    uint32_t          nr_draining;     /* atomic: count of DRAINING flows */

    /* DPDK Rx/Tx identifiers (for the proxy port) */
    uint16_t          proxy_port_id;
    uint16_t          nr_rx_queues;
    uint16_t          tx_queue_id;

    /* Back-reference to pipeline for drain reinject */
    dpu_pipeline_ctx_t *pipeline;

    volatile bool     running;
} dpu_buffer_ctx_t;


/* ═══════════════════════════════════════════════════════════════════════
 *  API
 * ═══════════════════════════════════════════════════════════════════════ */

/**
 * Initialise the buffer context.
 *
 * @param ctx            Buffer context (caller-allocated, zero-initialised)
 * @param proxy_port_id  DPDK port ID for the switch proxy port
 * @param nr_rx_queues   Number of Rx queues configured for RSS
 * @param tx_queue_id    Tx queue ID for reinject
 * @param pipeline       Back-reference to the pipeline context
 */
void dpu_buffer_init(dpu_buffer_ctx_t *ctx,
                     uint16_t proxy_port_id,
                     uint16_t nr_rx_queues,
                     uint16_t tx_queue_id,
                     dpu_pipeline_ctx_t *pipeline);

/**
 * Register a flow for buffering (called when BUFF mode is entered).
 *
 * @param ctx          Buffer context
 * @param hw_rule_id   Globally unique rule ID
 * @param direction    HW_DIR_UPLINK or HW_DIR_DOWNLINK
 * @return             0 on success, -1 if no slots available
 */
int dpu_buffer_register_flow(dpu_buffer_ctx_t *ctx,
                             uint32_t hw_rule_id,
                             uint8_t direction);

/**
 * Unregister a flow immediately (rollback / emergency only).
 * Sets state to INACTIVE, flushes ring.  NOT used for normal
 * BUFF→FORW/DROP/DELETE transitions — use begin_close +
 * quiesce_and_drain for those.
 *
 * @param ctx          Buffer context
 * @param hw_rule_id   Globally unique rule ID
 */
void dpu_buffer_unregister_flow(dpu_buffer_ctx_t *ctx,
                                uint32_t hw_rule_id);

/**
 * Begin Rx-owned drain for a BUFF→FORW transition (ACTIVE → DRAINING).
 *
 * HW must still point to TO_DPU_ARM when this is called.  The Rx lcore
 * will drain old ring packets first, then pass-through reinject new
 * arrivals.  When the ring is empty, the Rx lcore sets drain_done=1.
 *
 * The caller must update DL_ENCAP with new target gNB params (via
 * dpu_pipeline_update_dlencap_only) BEFORE calling this, so drained
 * DL packets get the correct outer header during handover.
 *
 * Call wait_drain_done() after this, THEN switch HW to COLOR_GATE.
 *
 * @param ctx          Buffer context
 * @param hw_rule_id   Globally unique rule ID
 * @return             0 on success, -1 if flow not found or wrong state
 */
int dpu_buffer_begin_drain(dpu_buffer_ctx_t *ctx,
                           uint32_t hw_rule_id);

/**
 * Wait for the Rx lcore to complete the ring drain (spins on drain_done).
 *
 * Returns once drain_done==1 (set by Rx lcore) or on timeout.
 * On success, the ring is guaranteed empty and the caller can safely
 * switch HW to COLOR_GATE.
 *
 * @param ctx          Buffer context
 * @param hw_rule_id   Globally unique rule ID
 * @return             0 on success, -1 on timeout (flow stays DRAINING)
 */
int dpu_buffer_wait_drain_done(dpu_buffer_ctx_t *ctx,
                               uint32_t hw_rule_id);

/**
 * Close a drained flow (DRAINING → CLOSED).
 *
 * Called after wait_drain_done succeeds AND HW has been switched
 * to COLOR_GATE.  Flushes any residual packets (safety net),
 * transitions to CLOSED, and decrements nr_draining.
 *
 * @param ctx          Buffer context
 * @param hw_rule_id   Globally unique rule ID
 * @return             0 on success, -1 if flow not found
 */
int dpu_buffer_close_flow(dpu_buffer_ctx_t *ctx,
                          uint32_t hw_rule_id);

/**
 * Begin closing a buffered flow (ACTIVE → CLOSING).
 * Used for DROP/DELETE paths where HW source is cut FIRST.
 * The Rx lcore continues accepting in-flight packets during CLOSING,
 * but the HW source should already be cut (fwd swapped / rule deleted)
 * before calling this.
 *
 * For BUFF→FORW transitions, use begin_drain + wait_drain_done +
 * close_flow instead.
 *
 * @param ctx          Buffer context
 * @param hw_rule_id   Globally unique rule ID
 * @return             0 on success or if flow not found / already closing
 */
int dpu_buffer_begin_close(dpu_buffer_ctx_t *ctx,
                           uint32_t hw_rule_id);

/**
 * Quiesce, drain (or discard), and mark a flow CLOSED.
 * Used for DROP/DELETE paths (begin_close → quiesce_and_drain).
 *
 * Spins until the Rx lcore's in-flight sequence counters converge
 * (enq_seq == deq_seq, stability-checked), then drains the ring.
 *
 * If @p discard is false, drained packets are reinjected into the
 * eSwitch with reinject metadata markers (normal FORW path).
 * If @p discard is true, drained packets are freed (DROP / DELETE).
 *
 * On quiesce timeout (100 ms), returns -1 and leaves the flow in
 * CLOSING state — the caller must NOT free or reuse the flow.
 *
 * @param ctx          Buffer context
 * @param hw_rule_id   Globally unique rule ID
 * @param discard      true = free drained packets; false = Tx reinject
 * @return             Number of packets drained, or -1 on timeout / error
 */
int dpu_buffer_quiesce_and_drain(dpu_buffer_ctx_t *ctx,
                                 uint32_t hw_rule_id,
                                 bool discard);

/**
 * Drain all buffered packets for a flow via Tx reinject.
 * Sets appropriate metadata markers for loop prevention.
 *
 * WARNING: NOT safe to call while the Rx lcore is processing
 * the same flow (TX queue ownership conflict).  Use begin_drain +
 * wait_drain_done for safe FORW transitions.
 *
 * @param ctx          Buffer context
 * @param hw_rule_id   Globally unique rule ID
 * @return             Number of packets drained, or -1 on error
 */
int dpu_buffer_drain_flow(dpu_buffer_ctx_t *ctx,
                          uint32_t hw_rule_id);

/**
 * Buffer Rx loop — runs on a dedicated lcore.
 * Receives packets from ARM Rx queues, identifies the flow via pkt_meta,
 * and enqueues into per-flow bounded ring buffers (ACTIVE/CLOSING state).
 *
 * For DRAINING flows (BUFF→FORW), the loop:
 *   Phase 1: drains old ring packets in bounded chunks (no-traffic path)
 *   Phase 2: on per-packet encounter, bounded-drains ≤32 old packets;
 *            if ring still non-empty, re-enqueues new pkt at tail.
 *            Once ring is empty, pass-through reinjects directly.
 *
 * @param arg   Pointer to dpu_buffer_ctx_t
 * @return      0 on exit
 */
int dpu_buffer_rx_loop(void *arg);

/**
 * Signal the buffer loop to stop.
 */
void dpu_buffer_stop(dpu_buffer_ctx_t *ctx);

/**
 * Free all rte_ring objects and flush any remaining packets.
 * Call after dpu_buffer_stop() + rte_eal_wait_lcore().
 */
void dpu_buffer_destroy(dpu_buffer_ctx_t *ctx);

#ifdef __cplusplus
}
#endif
