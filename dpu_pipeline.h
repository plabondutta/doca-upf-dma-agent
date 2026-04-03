/*
 * dpu_pipeline.h — DOCA Flow pipeline for DPU Agent (switch,hws mode)
 *
 * 17-pipe hierarchy on BlueField-3 with priority-bucketed matching:
 *   ROOT                   → control pipe (is_root=true), steers by port_id+protocol
 *   UL_MATCH[0..3]         → basic pipes: TEID + QFI + inner src_ip
 *                             chained by precedence, set pkt_meta + meter
 *   DL_MATCH[0..3]         → basic pipes: outer dst_ip (UE IP)
 *                             chained by precedence, set pkt_meta + meter
 *   UL_DECAP               → basic pipe: GTP decap + L2 inject → N6 wire
 *   UL_COLOR_GATE_POLICED  → basic pipe: GREEN+YELLOW → UL_DECAP, RED → DROP
 *   DL_COLOR_GATE_POLICED  → basic pipe: GREEN+YELLOW → DL_ENCAP, RED → DROP
 *   UL_COLOR_GATE_SHAPED   → basic pipe: GREEN → UL_DECAP, YELLOW → RSS ARM, RED → DROP
 *   DL_COLOR_GATE_SHAPED   → basic pipe: GREEN → DL_ENCAP, YELLOW → RSS ARM, RED → DROP
 *   DL_ENCAP               → basic pipe: match pkt_meta → GTP encap + PSC → N3 wire
 *   TO_HOST                → basic pipe: catch-all → FWD to Host VF representor
 *   TO_DPU_ARM             → basic pipe: RSS → ARM Rx queues (for idle UE buffering)
 *
 * Precedence: 3GPP precedence mapped to 4 priority buckets (lower = higher prio).
 *   UL_MATCH[0].miss → UL_MATCH[1] → ... → UL_MATCH[3].miss → TO_HOST
 *   Same for DL_MATCH.
 *
 * Per-entry match_mask wildcards unused SDF fields for catch-all PDRs.
 *
 * Build order: TO_HOST → TO_DPU_ARM → UL_DECAP → DL_ENCAP → POLICED gates
 *              → SHAPED gates → MATCH[3..0] → ROOT
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>

#include <doca_flow.h>
#include <doca_dev.h>
#include <doca_error.h>

#include "hw_offload_msg.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Port configuration ─────────────────────────────────────────────── */
#define DPU_MAX_PORTS       8
#define NUM_PRIO_BUCKETS    4      /* priority-bucketed match pipes          */
#define PRIO_BUCKET_RANGE   64     /* 3GPP precedence per bucket             */
#define MAX_HW_RULES        4096   /* max tracked HW-offloaded rules         */

/* ── ARM buffer / reinject metadata markers (two-bit scheme) ─────────── */
/*
 * Reinject packets get two marker bits in pkt_meta bits 0-1.
 *
 *   Bit 0 (REINJECT_MARKER_BIT) — set on ALL reinject packets.
 *   Bit 1 (REINJECT_UL_DIR_BIT) — set only on UL reinject.
 *
 * The drain path ALWAYS clears bits 0-1 of htonl(hw_rule_id) before
 * OR'ing the markers, so direction detection works regardless of
 * hw_rule_id magnitude.  (htonl puts input bits 24-25 into output
 * bits 0-1; for hw_rule_id ≥ 0x02000000 those bits are non-zero.)
 *
 *   UL drain: pkt_meta = (htonl(hw_rule_id) & ~0x03) | 0x03
 *   DL drain: pkt_meta = (htonl(hw_rule_id) & ~0x03) | 0x01
 *
 * ROOT control entries (no port_id matching):
 *   Prio 2: pkt_meta & REINJECT_BITS_MASK == 0x03 → N6  (UL reinject)
 *   Prio 3: pkt_meta & REINJECT_BITS_MASK == 0x01 → N3  (DL reinject)
 *
 * Normal wire traffic arrives with pkt_meta == 0 at ROOT ingress,
 * so bits 0-1 == 00 and neither entry matches.
 *
 * DL_ENCAP pipe mask ignores bits 0-1 (~REINJECT_BITS_MASK) so that
 * both normal DL and DL-reinject packets match the same encap entry.
 *
 * CONSTRAINT: insert_rule rejects hw_rule_ids where
 * htonl(hw_rule_id) & REINJECT_BITS_MASK != 0, preventing DL_ENCAP
 * aliasing between two rules that differ only in bits 24-25.
 */
#define REINJECT_MARKER_BIT  0x00000001u  /* bit 0: marks all reinject pkts */
#define REINJECT_UL_DIR_BIT  0x00000002u  /* bit 1: UL direction flag       */
#define REINJECT_BITS_MASK   0x00000003u  /* mask for reinject bits 0-1     */

/* ── ARM buffer Rx/Tx configuration ──────────────────────────────────── */
#define BUFFER_RX_QUEUES    4       /* RSS queues for buffered traffic     */
#define BUFFER_TX_QUEUES    1       /* TX queue for buffer reinject        */
/*
 * Pool must cover: Rx ring descriptors (TOTAL_RX_QUEUES * 512 = 4096)
 * + DPU_BUFFER_GLOBAL_CAP (16384) + shaper in-flight + headroom.
 * 32767 = next power-of-two minus 1 (DPDK convention).
 */
#define BUFFER_NB_MBUFS     32767   /* packet buffer pool size             */
#define BUFFER_MBUF_CACHE   256     /* per-core cache for mbuf pool        */

/* ── ARM shaper Rx/Tx configuration (GBR YELLOW traffic) ─────────────── */
#define SHAPER_RX_QUEUES    4       /* RSS queues for shaped YELLOW traffic */
#define SHAPER_TX_QUEUES    1       /* TX queue for shaper reinject         */
#define SHAPER_TX_QUEUE_ID  1       /* Tx queue index (buffer uses 0)       */

/* Total queues on proxy port = BUFFER + SHAPER */
#define TOTAL_RX_QUEUES     (BUFFER_RX_QUEUES + SHAPER_RX_QUEUES)
#define TOTAL_TX_QUEUES     (BUFFER_TX_QUEUES + SHAPER_TX_QUEUES)

/* ── Per-rule mode (for future buffering) ───────────────────────────── */
enum dpu_rule_mode {
    DPU_MODE_FAST   = 0,   /* Normal wire-speed forwarding via COLOR_GATE */
    DPU_MODE_BUFFER = 1,   /* Packets redirected to ARM for buffering     */
};

/* ── Per-rule entry-handle record ───────────────────────────────────── */
typedef struct {
    bool     in_use;
    uint32_t hw_rule_id;

    struct doca_flow_pipe_entry *ul_entry;       /* UL_MATCH entry (or NULL)  */
    struct doca_flow_pipe_entry *dl_entry;       /* DL_MATCH entry (or NULL)  */
    struct doca_flow_pipe_entry *dl_encap_entry; /* DL_ENCAP entry (or NULL)  */

    uint8_t  pipe_bucket;      /* which UL/DL_MATCH[0..3] bucket             */
    uint8_t  direction;        /* HW_DIR_UPLINK / HW_DIR_DOWNLINK            */
    uint8_t  current_mode;     /* enum dpu_rule_mode                         */
    bool     is_gbr_flow;      /* true if GBR > 0 (uses SHAPED color gate)   */
    uint32_t meter_id;         /* shared meter ID (for QER updates)          */
} dpu_rule_record_t;

typedef struct {
    uint16_t  n3_port_id;       /* physical port facing gNBs (uplink)     */
    uint16_t  n6_port_id;       /* physical port facing DN   (downlink)   */
    uint16_t  host_vf_port_id;  /* host VF representor for SW fallback    */

    /* DOCA devices — required by doca_flow_port_cfg_set_dev() */
    struct doca_dev     *n3_dev;       /* device for N3 port                */
    struct doca_dev     *n6_dev;       /* device for N6 port                */
    struct doca_dev     *host_vf_dev;  /* device for Host VF port           */
    struct doca_dev_rep *host_vf_rep;  /* VF representor (NULL if PF-based) */

    /* MAC addresses for L2 injection during UL decap */
    uint8_t   upf_n6_mac[6];   /* UPF's N6 interface MAC (src in decap)  */
    uint8_t   dn_gw_mac[6];    /* DN gateway MAC          (dst in decap) */

    /* MAC for DL GTP encap (outer header) */
    uint8_t   upf_n3_mac[6];   /* UPF's N3 interface MAC (outer src)     */
    uint8_t   gnb_mac[6];      /* gNB MAC                (outer dst)     */

    /* UPF N3 IP for GTP encap (NBO) */
    uint32_t  upf_n3_ip;       /* struct in_addr.s_addr equivalent       */
} dpu_port_cfg_t;

/* ── Pipeline context ───────────────────────────────────────────────── */
typedef struct {
    /* DOCA Flow ports */
    struct doca_flow_port *ports[DPU_MAX_PORTS];
    struct doca_flow_port *switch_port;  /* switch manager port (switch,hws) */
    uint16_t              nb_ports;

    /* Pipe handles */
    struct doca_flow_pipe *root_pipe;
    struct doca_flow_pipe *ul_match_pipes[NUM_PRIO_BUCKETS];
    struct doca_flow_pipe *dl_match_pipes[NUM_PRIO_BUCKETS];
    struct doca_flow_pipe *ul_color_gate_policed_pipe;  /* GREEN+YELLOW → wire */
    struct doca_flow_pipe *dl_color_gate_policed_pipe;
    struct doca_flow_pipe *ul_color_gate_shaped_pipe;   /* GREEN → wire, YELLOW → ARM RSS */
    struct doca_flow_pipe *dl_color_gate_shaped_pipe;
    struct doca_flow_pipe *ul_decap_pipe;               /* UL GTP decap + L2 inject */
    struct doca_flow_pipe *dl_encap_pipe;
    struct doca_flow_pipe *to_host_pipe;
    struct doca_flow_pipe *to_dpu_arm_pipe;

    /* Port configuration */
    dpu_port_cfg_t         port_cfg;

    /* ARM buffer RSS config (populated during init if buffering enabled) */
    uint16_t               rss_queues[BUFFER_RX_QUEUES];
    uint32_t               nr_rss_queues;

    /* ARM shaper RSS config (populated during init if shaping enabled) */
    uint16_t               shaper_rss_queues[SHAPER_RX_QUEUES];
    uint32_t               nr_shaper_rss_queues;

    /* Entry tracking */
    uint32_t               nb_entries;
    dpu_rule_record_t      rules[MAX_HW_RULES];

} dpu_pipeline_ctx_t;


/* ═══════════════════════════════════════════════════════════════════════
 *  API
 * ═══════════════════════════════════════════════════════════════════════ */

/**
 * Phase 1: Init DOCA Flow, create ports, get switch port handle.
 * After this returns, the caller MUST configure DPDK Rx/Tx queues on the
 * proxy port (port 0) before calling dpu_pipeline_build_pipes().
 *
 * @param ctx             Pipeline context (caller-allocated, zero-initialised)
 * @param port_cfg        Port configuration (port IDs, MACs, IPs)
 * @param rss_queues            Array of Rx queue indices for TO_DPU_ARM RSS (NULL to disable buffering)
 * @param nr_rss_queues         Number of buffer RSS queues (0 to disable buffering)
 * @param shaper_rss_queues     Array of Rx queue indices for SHAPED YELLOW RSS (NULL to disable shaping)
 * @param nr_shaper_rss_queues  Number of shaper RSS queues (0 to disable shaping)
 * @return                      DOCA_SUCCESS on success
 */
doca_error_t dpu_pipeline_create_ports(dpu_pipeline_ctx_t *ctx,
                                       const dpu_port_cfg_t *port_cfg,
                                       uint16_t *rss_queues,
                                       uint32_t nr_rss_queues,
                                       uint16_t *shaper_rss_queues,
                                       uint32_t nr_shaper_rss_queues);

/**
 * Phase 2: Build the pipe hierarchy.  Must be called after proxy port
 * Rx/Tx queues are configured and the port is started.
 *
 * @param ctx  Pipeline context (ports must already be created)
 * @return     DOCA_SUCCESS on success
 */
doca_error_t dpu_pipeline_build_pipes(dpu_pipeline_ctx_t *ctx);

/**
 * Insert a PDR rule into the pipeline based on an hw_offload_msg.
 * Selects UL_MATCH or DL_MATCH based on msg->direction, creates
 * the meter, inserts the match entry, and (for DL) the encap entry.
 *
 * @param ctx  Pipeline context
 * @param msg  Hardware offload message (from Host Agent via Comch)
 * @return     DOCA_SUCCESS on success
 */
doca_error_t dpu_pipeline_insert_rule(dpu_pipeline_ctx_t *ctx,
                                       const hw_offload_msg_t *msg);

/**
 * Tear down all pipes and ports. Called at shutdown.
 */
void dpu_pipeline_destroy(dpu_pipeline_ctx_t *ctx);

/**
 * Delete a previously inserted rule by hw_rule_id.
 * Removes all associated DOCA Flow entries (UL/DL/ENCAP) and frees the record.
 */
doca_error_t dpu_pipeline_delete_rule(dpu_pipeline_ctx_t *ctx,
                                       uint32_t hw_rule_id);

/**
 * Update the forwarding action of an existing rule (FAR action change).
 * Uses doca_flow_pipe_update_entry() to change the per-entry fwd target.
 * - BUFF: swaps per-entry fwd from COLOR_GATE → TO_DPU_ARM (if available)
 * - FORW (from BUFFER): swaps per-entry fwd back to COLOR_GATE
 * - DROP: removes the HW rule entirely
 */
doca_error_t dpu_pipeline_update_far(dpu_pipeline_ctx_t *ctx,
                                      const hw_offload_msg_t *msg);

/**
 * Update meter rates for an existing rule (QER rate change).
 * Destroys the old shared meter and creates a new one, then updates the entry.
 */
doca_error_t dpu_pipeline_update_qer(dpu_pipeline_ctx_t *ctx,
                                      const hw_offload_msg_t *msg);

/**
 * Update PDR (match criteria may change).  Implemented as delete + re-create
 * since DOCA Flow does not support updating match fields of an existing entry.
 */
doca_error_t dpu_pipeline_update_pdr(dpu_pipeline_ctx_t *ctx,
                                      const hw_offload_msg_t *msg);

/**
 * Downgrade a GBR flow from shaped to policed color gate.
 * Called when shaper registration fails — YELLOW packets go to wire
 * (slightly over-admitted) instead of being dropped on ARM.
 */
doca_error_t dpu_pipeline_downgrade_to_policed(dpu_pipeline_ctx_t *ctx,
                                                uint32_t hw_rule_id);

/**
 * Update only the DL_ENCAP entry's encapsulation actions (target gNB IP,
 * TEID, QFI) without touching the match entry's fwd target.
 *
 * Must be called BEFORE dpu_buffer_begin_drain() during BUFF→FORW
 * transitions so that drained/reinjected packets hit the new encap
 * parameters.  Safe to call while the match entry still points to
 * TO_DPU_ARM — no fast-path traffic reaches DL_ENCAP for this rule
 * until the fwd is swapped back to COLOR_GATE.
 *
 * No-op for UL rules or if encap params are unchanged.
 *
 * @param ctx  Pipeline context
 * @param msg  Message carrying new OHC params (ohc_ipv4, ohc_teid, encap_qfi)
 * @return     DOCA_SUCCESS, or error if the HW commit fails
 */
doca_error_t dpu_pipeline_update_dlencap_only(dpu_pipeline_ctx_t *ctx,
                                              const hw_offload_msg_t *msg);

/**
 * Set the logical mode (FAST/BUFFER) for a rule record.
 * Used by the caller to update mode at the correct lifecycle point
 * (e.g., after quiesce completes for FORW transitions).
 */
void dpu_pipeline_set_mode(dpu_pipeline_ctx_t *ctx,
                           uint32_t hw_rule_id,
                           uint8_t mode);

#ifdef __cplusplus
}
#endif
