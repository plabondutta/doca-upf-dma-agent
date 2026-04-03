/*
 * dpu_pipeline.c — DOCA Flow pipeline on BlueField-3 (switch,hws mode)
 *
 * Implements the Split-Agent DPU-side data plane for ICNP offload:
 *   - Full SDF matching (inner/outer IPs + protocol) with per-entry mask
 *   - 4 priority-bucketed pipes per direction for 3GPP precedence
 *   - trTCM RFC 2698 metering (CIR=GBR, PIR=MBR), skipped when no QER
 *   - Color-gate enforcement (GREEN+YELLOW pass, RED drops)
 *   - Inline GTP decap + L2 injection for uplink
 *   - pkt_meta-based GTP encap for downlink (with PSC extension)
 *   - TO_DPU_ARM pipe for DL buffering via RSS to ARM Rx queues
 *
 * 14-pipe hierarchy:
 *   ROOT  → UL_MATCH[0..3] → UL_COLOR_GATE → fwd N6
 *         → DL_MATCH[0..3] → DL_COLOR_GATE → fwd N3 → DL_ENCAP (egress)
 *         → TO_HOST (catch-all)
 *   TO_DPU_ARM: RSS → ARM Rx queues (entered via per-entry fwd swap on BUFF)
 *
 * All pipes created on switch manager port (doca_flow_port_switch_get).
 * Devargs passed via EAL -a flag: dv_flow_en=2,fdb_def_rule_en=0,
 *   vport_match=1,repr_matching_en=0,dv_xmeta_en=4
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <arpa/inet.h>
#include <rte_byteorder.h>

#include <doca_flow.h>
#include <doca_log.h>

/* DOCA 3.3 compat: DOCA_FLOW_NO_WAIT = 0 is documented but may be
 * absent in some SDK builds; provide the constant if needed. */
#ifndef DOCA_FLOW_NO_WAIT
#  define DOCA_FLOW_NO_WAIT 0
#endif

#include "dpu_pipeline.h"

DOCA_LOG_REGISTER(DPU_PIPELINE);

/* ── Constants ──────────────────────────────────────────────────────── */
#define GTP_UDP_PORT   2152
#define GTP_EXT_PSC    0x85   /* GTP next-ext-hdr-type for PDU Session Container */
#define NO_METER_ID    UINT32_MAX  /* sentinel: skip metering for this entry */

/* ── Record helpers ─────────────────────────────────────────────────── */

static dpu_rule_record_t *
find_record(dpu_pipeline_ctx_t *ctx, uint32_t hw_rule_id)
{
    for (uint32_t i = 0; i < MAX_HW_RULES; i++) {
        if (ctx->rules[i].in_use && ctx->rules[i].hw_rule_id == hw_rule_id)
            return &ctx->rules[i];
    }
    return NULL;
}

static dpu_rule_record_t *
alloc_record(dpu_pipeline_ctx_t *ctx)
{
    for (uint32_t i = 0; i < MAX_HW_RULES; i++) {
        if (!ctx->rules[i].in_use)
            return &ctx->rules[i];
    }
    return NULL;
}

static void
free_record(dpu_rule_record_t *rec)
{
    memset(rec, 0, sizeof(*rec));
}

/* ── Helpers ────────────────────────────────────────────────────────── */

/** Map 3GPP precedence (lower = higher priority) to bucket index [0..3]. */
static inline int
precedence_to_bucket(uint32_t precedence)
{
    int bucket = (int)(precedence / PRIO_BUCKET_RANGE);
    if (bucket >= NUM_PRIO_BUCKETS)
        bucket = NUM_PRIO_BUCKETS - 1;
    return bucket;
}

/* ── Pipe entry callback ────────────────────────────────────────────── */
static void
entry_process_cb(struct doca_flow_pipe_entry *entry,
                 uint16_t pipe_queue,
                 enum doca_flow_entry_status status,
                 enum doca_flow_entry_op op,
                 void *user_ctx)
{
    (void)entry; (void)pipe_queue; (void)user_ctx;
    if (status != DOCA_FLOW_ENTRY_STATUS_SUCCESS)
        DOCA_LOG_ERR("Entry op=%d failed with status=%d", op, status);
}


/* ═══════════════════════════════════════════════════════════════════════
 *  DOCA Flow Initialisation
 * ═══════════════════════════════════════════════════════════════════════ */

static doca_error_t
init_doca_flow(uint32_t pipe_queues)
{
    struct doca_flow_cfg *cfg;
    doca_error_t result;

    result = doca_flow_cfg_create(&cfg);
    if (result != DOCA_SUCCESS) return result;

    doca_flow_cfg_set_pipe_queues(cfg, pipe_queues);
    doca_flow_cfg_set_nr_counters(cfg, 4096);
    doca_flow_cfg_set_nr_meters(cfg, 4096);
    doca_flow_cfg_set_mode_args(cfg, "switch,isolated,hws");
    doca_flow_cfg_set_cb_entry_process(cfg, entry_process_cb);
    doca_flow_cfg_set_nr_shared_resource(cfg, 4096,
                                          DOCA_FLOW_SHARED_RESOURCE_METER);

    result = doca_flow_init(cfg);
    doca_flow_cfg_destroy(cfg);
    return result;
}


/* ═══════════════════════════════════════════════════════════════════════
 *  Port creation — binds logical ID + DOCA device + optional representor
 * ═══════════════════════════════════════════════════════════════════════ */

static doca_error_t
create_port(uint16_t port_id,
            struct doca_dev *dev,
            struct doca_dev_rep *dev_rep,
            struct doca_flow_port **port)
{
    struct doca_flow_port_cfg *port_cfg;
    doca_error_t result;

    result = doca_flow_port_cfg_create(&port_cfg);
    if (result != DOCA_SUCCESS) return result;

    doca_flow_port_cfg_set_port_id(port_cfg, port_id);

    /* In DOCA 3.3, PF ports use set_dev() only; representor ports use
     * set_dev_rep() only.  They are mutually exclusive on a port config. */
    if (dev_rep) {
        result = doca_flow_port_cfg_set_dev_rep(port_cfg, dev_rep);
        if (result != DOCA_SUCCESS) {
            doca_flow_port_cfg_destroy(port_cfg);
            return result;
        }
    } else {
        result = doca_flow_port_cfg_set_dev(port_cfg, dev);
        if (result != DOCA_SUCCESS) {
            doca_flow_port_cfg_destroy(port_cfg);
            return result;
        }
    }

    /* Per-port meter resources */
    result = doca_flow_port_cfg_set_nr_resources(port_cfg,
        DOCA_FLOW_RESOURCE_METER, 4096);
    if (result != DOCA_SUCCESS) {
        doca_flow_port_cfg_destroy(port_cfg);
        return result;
    }

    result = doca_flow_port_start(port_cfg, port);
    doca_flow_port_cfg_destroy(port_cfg);
    return result;
}


/* ═══════════════════════════════════════════════════════════════════════
 *  Pipe builders
 * ═══════════════════════════════════════════════════════════════════════ */

/* ── TO_HOST: catch-all → forward to Host VF representor ──────────── */
static doca_error_t
build_to_host_pipe(dpu_pipeline_ctx_t *ctx)
{
    doca_error_t result;
    struct doca_flow_pipe_cfg *pipe_cfg;

    result = doca_flow_pipe_cfg_create(&pipe_cfg, ctx->switch_port);
    if (result != DOCA_SUCCESS) return result;

    doca_flow_pipe_cfg_set_name(pipe_cfg, "TO_HOST");
    doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_BASIC);
    doca_flow_pipe_cfg_set_is_root(pipe_cfg, false);
    doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 1);

    struct doca_flow_match match = {};
    doca_flow_pipe_cfg_set_match(pipe_cfg, &match, NULL);

    struct doca_flow_actions actions = {};
    struct doca_flow_actions *actions_arr[] = { &actions };
    doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, NULL, NULL, 1);

    struct doca_flow_fwd fwd = {
        .type = DOCA_FLOW_FWD_PORT,
        .port_id = ctx->port_cfg.host_vf_port_id,
    };

    result = doca_flow_pipe_create(pipe_cfg, &fwd, NULL, &ctx->to_host_pipe);
    doca_flow_pipe_cfg_destroy(pipe_cfg);
    if (result != DOCA_SUCCESS) return result;

    struct doca_flow_pipe_entry *entry;
    result = doca_flow_pipe_basic_add_entry(0, ctx->to_host_pipe,
                                       &match, 0, &actions, NULL, &fwd,
                                       0, NULL, &entry);
    if (result != DOCA_SUCCESS)
        DOCA_LOG_ERR("TO_HOST entry insert failed");

    /* In switch,hws mode (synchronous HW steering), entries_process with
     * nr_entries=0 and timeout=0 drains all pending completions.  This
     * is the standard NVIDIA pattern for DOCA_FLOW_NO_WAIT submissions.
     * If DOCA ever moved to purely async entry ops, this call would need
     * a non-zero timeout or a completion callback — but HWS mode
     * guarantees synchronous commit today (DOCA SDK v3.2.0). */
    doca_flow_entries_process(ctx->switch_port, 0, 0, 0);
    return result;
}


/* ── TO_DPU_ARM: RSS to ARM Rx queues for buffering ───────────── */
/*
 * Catch-all pipe that forwards every packet to ARM via RSS.
 * Entered when a per-entry fwd in xL_MATCH is swapped from
 * COLOR_GATE → TO_DPU_ARM on UpdateFAR(BUFF).
 * The pkt_meta set by the match pipe is preserved across RSS.
 */
static doca_error_t
build_to_dpu_arm_pipe(dpu_pipeline_ctx_t *ctx)
{
    doca_error_t result;
    struct doca_flow_pipe_cfg *pipe_cfg;

    result = doca_flow_pipe_cfg_create(&pipe_cfg, ctx->switch_port);
    if (result != DOCA_SUCCESS) return result;

    doca_flow_pipe_cfg_set_name(pipe_cfg, "TO_DPU_ARM");
    doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_BASIC);
    doca_flow_pipe_cfg_set_is_root(pipe_cfg, false);
    doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 1);

    struct doca_flow_match match = {};
    doca_flow_pipe_cfg_set_match(pipe_cfg, &match, NULL);

    struct doca_flow_actions actions = {};
    struct doca_flow_actions *actions_arr[] = { &actions };
    doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, NULL, NULL, 1);

    struct doca_flow_fwd fwd = {
        .type = DOCA_FLOW_FWD_RSS,
        .rss_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED,
        .rss = {
            .queues_array = ctx->rss_queues,
            .nr_queues = (int)ctx->nr_rss_queues,
            .outer_flags = DOCA_FLOW_RSS_IPV4 | DOCA_FLOW_RSS_UDP,
        },
    };

    result = doca_flow_pipe_create(pipe_cfg, &fwd, NULL,
                                    &ctx->to_dpu_arm_pipe);
    doca_flow_pipe_cfg_destroy(pipe_cfg);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("TO_DPU_ARM pipe creation failed: %s",
                     doca_error_get_descr(result));
        return result;
    }

    /* Insert a single wildcard catch-all entry */
    struct doca_flow_pipe_entry *entry;
    result = doca_flow_pipe_basic_add_entry(0, ctx->to_dpu_arm_pipe,
                                       &match, 0, &actions, NULL, &fwd,
                                       0, NULL, &entry);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("TO_DPU_ARM entry insert failed");
        return result;
    }

    doca_flow_entries_process(ctx->switch_port, 0, 0, 0);
    DOCA_LOG_INFO("TO_DPU_ARM: RSS to %u ARM Rx queues", ctx->nr_rss_queues);
    return DOCA_SUCCESS;
}


/* ── Color-gate POLICED: GREEN+YELLOW → wire, RED → DROP ─────────── */
/*
 * MBR-only flows (GBR == 0).  Both GREEN and YELLOW traffic forwards
 * to the wire port at line rate.  RED (above MBR) is dropped in HW.
 */
static doca_error_t
build_color_gate_policed_pipe(dpu_pipeline_ctx_t *ctx,
                              const char *name,
                              uint16_t fwd_port_id,
                              struct doca_flow_pipe *fwd_pipe,
                              struct doca_flow_pipe **pipe_out)
{
    doca_error_t result;
    struct doca_flow_pipe_cfg *pipe_cfg;

    result = doca_flow_pipe_cfg_create(&pipe_cfg, ctx->switch_port);
    if (result != DOCA_SUCCESS) return result;

    doca_flow_pipe_cfg_set_name(pipe_cfg, name);
    doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_BASIC);
    doca_flow_pipe_cfg_set_is_root(pipe_cfg, false);
    doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 4);

    struct doca_flow_match match = {};
    match.parser_meta.meter_color = UINT8_MAX;

    struct doca_flow_match mask = {};
    mask.parser_meta.meter_color = UINT8_MAX;

    doca_flow_pipe_cfg_set_match(pipe_cfg, &match, &mask);

    struct doca_flow_actions actions = {};
    struct doca_flow_actions *actions_arr[] = { &actions };
    doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, NULL, NULL, 1);

    struct doca_flow_fwd fwd = {};
    if (fwd_pipe) {
        fwd.type = DOCA_FLOW_FWD_PIPE;
        fwd.next_pipe = fwd_pipe;
    } else {
        fwd.type = DOCA_FLOW_FWD_PORT;
        fwd.port_id = fwd_port_id;
    }
    struct doca_flow_fwd fwd_miss = {
        .type = DOCA_FLOW_FWD_DROP,
    };

    result = doca_flow_pipe_create(pipe_cfg, &fwd, &fwd_miss, pipe_out);
    doca_flow_pipe_cfg_destroy(pipe_cfg);
    if (result != DOCA_SUCCESS) return result;

    /* GREEN and YELLOW entries both forward */
    struct doca_flow_pipe_entry *entry;

    struct doca_flow_match green = {};
    green.parser_meta.meter_color = DOCA_FLOW_METER_COLOR_GREEN;
    result = doca_flow_pipe_basic_add_entry(0, *pipe_out,
                                       &green, 0, &actions, NULL, &fwd,
                                       0, NULL, &entry);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("%s: GREEN entry failed", name);
        return result;
    }

    struct doca_flow_match yellow = {};
    yellow.parser_meta.meter_color = DOCA_FLOW_METER_COLOR_YELLOW;
    result = doca_flow_pipe_basic_add_entry(0, *pipe_out,
                                       &yellow, 0, &actions, NULL, &fwd,
                                       0, NULL, &entry);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("%s: YELLOW entry failed", name);
        return result;
    }

    doca_flow_entries_process(ctx->switch_port, 0, 0, 0);
    DOCA_LOG_INFO("%s: GREEN+YELLOW→%s, RED→drop (POLICED)",
                  name, fwd_pipe ? "pipe" : "wire");
    return DOCA_SUCCESS;
}


/* ── Color-gate SHAPED: GREEN → wire, YELLOW → ARM RSS, RED → DROP ── */
/*
 * GBR flows (GBR > 0).  GREEN traffic (≤ GBR) goes to wire at line rate.
 * YELLOW traffic (between GBR and MBR) is redirected to ARM via RSS for
 * software token-bucket shaping at EIR = MBR − GBR.  RED → DROP.
 */
static doca_error_t
build_color_gate_shaped_pipe(dpu_pipeline_ctx_t *ctx,
                             const char *name,
                             uint16_t fwd_port_id,
                             struct doca_flow_pipe *fwd_pipe,
                             uint16_t *rss_queues,
                             uint32_t nr_rss_queues,
                             struct doca_flow_pipe **pipe_out)
{
    doca_error_t result;
    struct doca_flow_pipe_cfg *pipe_cfg;

    result = doca_flow_pipe_cfg_create(&pipe_cfg, ctx->switch_port);
    if (result != DOCA_SUCCESS) return result;

    doca_flow_pipe_cfg_set_name(pipe_cfg, name);
    doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_BASIC);
    doca_flow_pipe_cfg_set_is_root(pipe_cfg, false);
    doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 4);

    struct doca_flow_match match = {};
    match.parser_meta.meter_color = UINT8_MAX;

    struct doca_flow_match mask = {};
    mask.parser_meta.meter_color = UINT8_MAX;

    doca_flow_pipe_cfg_set_match(pipe_cfg, &match, &mask);

    struct doca_flow_actions actions = {};
    struct doca_flow_actions *actions_arr[] = { &actions };
    doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, NULL, NULL, 1);

    /* Pipe-level fwd: CHANGEABLE allows different per-entry fwd types
     * (GREEN uses FWD_PORT, YELLOW uses FWD_RSS) */
    struct doca_flow_fwd fwd_changeable = {
        .type = DOCA_FLOW_FWD_CHANGEABLE,
    };
    struct doca_flow_fwd fwd_miss = {
        .type = DOCA_FLOW_FWD_DROP,
    };

    result = doca_flow_pipe_create(pipe_cfg, &fwd_changeable, &fwd_miss, pipe_out);
    doca_flow_pipe_cfg_destroy(pipe_cfg);
    if (result != DOCA_SUCCESS) return result;

    struct doca_flow_pipe_entry *entry;

    /* GREEN → wire port or pipe (if fwd_pipe provided) */
    struct doca_flow_fwd fwd_wire = {};
    if (fwd_pipe) {
        fwd_wire.type = DOCA_FLOW_FWD_PIPE;
        fwd_wire.next_pipe = fwd_pipe;
    } else {
        fwd_wire.type = DOCA_FLOW_FWD_PORT;
        fwd_wire.port_id = fwd_port_id;
    }
    struct doca_flow_match green = {};
    green.parser_meta.meter_color = DOCA_FLOW_METER_COLOR_GREEN;
    result = doca_flow_pipe_basic_add_entry(0, *pipe_out,
                                       &green, 0, &actions, NULL, &fwd_wire,
                                       0, NULL, &entry);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("%s: GREEN entry failed", name);
        return result;
    }

    /* YELLOW → RSS to ARM shaper Rx queues */
    struct doca_flow_fwd fwd_rss = {
        .type = DOCA_FLOW_FWD_RSS,
        .rss_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED,
        .rss = {
            .queues_array = rss_queues,
            .nr_queues = (int)nr_rss_queues,
            .outer_flags = DOCA_FLOW_RSS_IPV4 | DOCA_FLOW_RSS_UDP,
        },
    };
    struct doca_flow_match yellow = {};
    yellow.parser_meta.meter_color = DOCA_FLOW_METER_COLOR_YELLOW;
    result = doca_flow_pipe_basic_add_entry(0, *pipe_out,
                                       &yellow, 0, &actions, NULL, &fwd_rss,
                                       0, NULL, &entry);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("%s: YELLOW entry failed", name);
        return result;
    }

    doca_flow_entries_process(ctx->switch_port, 0, 0, 0);
    DOCA_LOG_INFO("%s: GREEN→%s, YELLOW→ARM RSS(%u queues), RED→drop (SHAPED)",
                  name, fwd_pipe ? "pipe" : "wire", nr_rss_queues);
    return DOCA_SUCCESS;
}


/* ── UL_MATCH pipes (4 priority buckets) ──────────────────────────── */
/*
 * Each pipe matches: GTP TEID + QFI + UE IP (inner src_ip).
 * SDF fields (dst_ip, proto, ports) are wildcarded at the pipe level.
 * Actions: GTP decap + L2 inject + pkt_meta + shared meter.
 * Chain: P0.miss → P1 → P2 → P3.miss → TO_HOST.
 */
static doca_error_t
build_ul_match_pipes(dpu_pipeline_ctx_t *ctx)
{
    doca_error_t result;

    /* Build from lowest priority (P3) up to highest (P0) */
    for (int p = NUM_PRIO_BUCKETS - 1; p >= 0; p--) {
        struct doca_flow_pipe_cfg *pipe_cfg;
        result = doca_flow_pipe_cfg_create(&pipe_cfg, ctx->switch_port);
        if (result != DOCA_SUCCESS) return result;

        char name[32];
        snprintf(name, sizeof(name), "UL_MATCH_P%d", p);
        doca_flow_pipe_cfg_set_name(pipe_cfg, name);
        doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_BASIC);
        doca_flow_pipe_cfg_set_is_root(pipe_cfg, false);
        doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 2048);

        /* Match: TEID only (CHANGEABLE per-entry).
         * BRINGUP: QFI + inner fields stripped — FW 32.43.2402 matcher
         * doesn't support inner/extension parsing in FDB HWS mode.
         * TODO: restore QFI + UE IP match after FW upgrade. */
        struct doca_flow_match match = {};
        match.tun.type = DOCA_FLOW_TUN_GTPU;
        match.tun.gtp_teid = UINT32_MAX;

        struct doca_flow_match mask = {};
        mask.tun.type = DOCA_FLOW_TUN_GTPU;
        mask.tun.gtp_teid = UINT32_MAX;

        doca_flow_pipe_cfg_set_match(pipe_cfg, &match, &mask);

        /* Actions: NONE for bringup (pkt_meta requires MODIFY_HEADER
         * which needs ARGUMENT_64B — not available on current FW).
         * TODO: restore pkt_meta + meter when FW is updated. */

        /* Monitor: NONE for bringup (meter disabled) */

        /* Hit → UL_DECAP directly (skip color gate for bringup) */
        struct doca_flow_fwd fwd = {
            .type = DOCA_FLOW_FWD_PIPE,
            .next_pipe = ctx->ul_decap_pipe,
        };

        /* Miss → next lower priority bucket, or TO_HOST */
        struct doca_flow_fwd fwd_miss;
        if (p == NUM_PRIO_BUCKETS - 1) {
            fwd_miss.type = DOCA_FLOW_FWD_PIPE;
            fwd_miss.next_pipe = ctx->to_host_pipe;
        } else {
            fwd_miss.type = DOCA_FLOW_FWD_PIPE;
            fwd_miss.next_pipe = ctx->ul_match_pipes[p + 1];
        }

        result = doca_flow_pipe_create(pipe_cfg, &fwd, &fwd_miss,
                                        &ctx->ul_match_pipes[p]);
        doca_flow_pipe_cfg_destroy(pipe_cfg);

        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("%s pipe creation failed: %s",
                         name, doca_error_get_descr(result));
            return result;
        }

        DOCA_LOG_INFO("%s: hit→CHANGEABLE(UL_COLOR_GATE), miss→%s",
                      name,
                      (p == NUM_PRIO_BUCKETS - 1) ? "TO_HOST"
                          : "next bucket");
    }

    return DOCA_SUCCESS;
}


/* ── DL_MATCH pipes (4 priority buckets) ──────────────────────────── */
/*
 * Each pipe matches: UE destination IP (outer dst_ip).
 * SDF fields (src_ip, proto, ports) are wildcarded at the pipe level.
 * Actions: pkt_meta + shared meter.
 * Chain: P0.miss → P1 → P2 → P3.miss → TO_HOST.
 */
static doca_error_t
build_dl_match_pipes(dpu_pipeline_ctx_t *ctx)
{
    doca_error_t result;

    for (int p = NUM_PRIO_BUCKETS - 1; p >= 0; p--) {
        struct doca_flow_pipe_cfg *pipe_cfg;
        result = doca_flow_pipe_cfg_create(&pipe_cfg, ctx->switch_port);
        if (result != DOCA_SUCCESS) return result;

        char name[32];
        snprintf(name, sizeof(name), "DL_MATCH_P%d", p);
        doca_flow_pipe_cfg_set_name(pipe_cfg, name);
        doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_BASIC);
        doca_flow_pipe_cfg_set_is_root(pipe_cfg, false);
        doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 2048);

        /* Match: UE destination IP only (CHANGEABLE per-entry).
         * SDF fields (src_ip, proto, ports) are intentionally omitted so
         * that their pipe-level mask is 0 → IGNORED (wildcard).  This
         * allows catch-all PDRs with no SDF filter to match all traffic. */
        struct doca_flow_match match = {};
        match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
        match.outer.ip4.dst_ip = UINT32_MAX;                 /* UE IP */

        struct doca_flow_match mask = {};
        mask.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
        mask.outer.ip4.dst_ip = UINT32_MAX;

        doca_flow_pipe_cfg_set_match(pipe_cfg, &match, &mask);

        /* Actions: NONE for bringup (pkt_meta requires MODIFY_HEADER
         * which needs ARGUMENT_64B — not available on current FW).
         * TODO: restore pkt_meta + meter when FW is updated. */

        /* Monitor: NONE for bringup (meter disabled) */

        /* Hit → DL_ENCAP directly (skip color gate for bringup) */
        struct doca_flow_fwd fwd = {
            .type = DOCA_FLOW_FWD_PIPE,
            .next_pipe = ctx->dl_encap_pipe,
        };

        /* Miss → next bucket or TO_HOST */
        struct doca_flow_fwd fwd_miss;
        if (p == NUM_PRIO_BUCKETS - 1) {
            fwd_miss.type = DOCA_FLOW_FWD_PIPE;
            fwd_miss.next_pipe = ctx->to_host_pipe;
        } else {
            fwd_miss.type = DOCA_FLOW_FWD_PIPE;
            fwd_miss.next_pipe = ctx->dl_match_pipes[p + 1];
        }

        result = doca_flow_pipe_create(pipe_cfg, &fwd, &fwd_miss,
                                        &ctx->dl_match_pipes[p]);
        doca_flow_pipe_cfg_destroy(pipe_cfg);

        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("%s pipe creation failed: %s",
                         name, doca_error_get_descr(result));
            return result;
        }

        DOCA_LOG_INFO("%s: hit→CHANGEABLE(DL_COLOR_GATE), miss→%s",
                      name,
                      (p == NUM_PRIO_BUCKETS - 1) ? "TO_HOST"
                          : "next bucket");
    }

    return DOCA_SUCCESS;
}


/* ── UL_DECAP pipe (FDB pass-through — REFORMAT disabled for bringup) ─ */
/*
 * TEMPORARY: No decap action.  Just forwards UL traffic to N6.
 * TODO: Re-enable GTP decap + L2 inject once ARGUMENT_64B is resolved.
 */
static doca_error_t
build_ul_decap_pipe(dpu_pipeline_ctx_t *ctx)
{
    doca_error_t result;
    struct doca_flow_pipe_cfg *pipe_cfg;

    result = doca_flow_pipe_cfg_create(&pipe_cfg, ctx->switch_port);
    if (result != DOCA_SUCCESS) return result;

    doca_flow_pipe_cfg_set_name(pipe_cfg, "UL_DECAP");
    doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_BASIC);
    doca_flow_pipe_cfg_set_is_root(pipe_cfg, false);
    doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 1);

    /* Match: GTP-U tunnel type (catch-all for UL traffic) */
    struct doca_flow_match match = {};
    match.tun.type = DOCA_FLOW_TUN_GTPU;

    struct doca_flow_match mask = {};
    mask.tun.type = DOCA_FLOW_TUN_GTPU;

    doca_flow_pipe_cfg_set_match(pipe_cfg, &match, &mask);

    /* NO actions — pure pass-through (decap disabled for bringup) */

    /* Forward: out the N6 port (still GTP-encapped, but pipeline runs) */
    struct doca_flow_fwd fwd = {
        .type = DOCA_FLOW_FWD_PORT,
        .port_id = ctx->port_cfg.n6_port_id,
    };

    struct doca_flow_fwd fwd_miss = {
        .type = DOCA_FLOW_FWD_DROP,
    };

    result = doca_flow_pipe_create(pipe_cfg, &fwd, &fwd_miss,
                                    &ctx->ul_decap_pipe);
    doca_flow_pipe_cfg_destroy(pipe_cfg);

    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("UL_DECAP pipe creation failed: %s",
                     doca_error_get_descr(result));
        return result;
    }

    /* Single catch-all entry */
    struct doca_flow_match entry_match = {};
    entry_match.tun.type = DOCA_FLOW_TUN_GTPU;

    struct doca_flow_pipe_entry *entry;
    result = doca_flow_pipe_basic_add_entry(0, ctx->ul_decap_pipe,
                                       &entry_match, 0, NULL, NULL, NULL,
                                       0, NULL, &entry);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("UL_DECAP: catch-all entry failed: %s",
                     doca_error_get_descr(result));
        return result;
    }

    doca_flow_entries_process(ctx->switch_port, 0, 0, 0);
    DOCA_LOG_INFO("UL_DECAP: FDB pass-through → N6 (decap DISABLED, 1 entry)");
    return DOCA_SUCCESS;
}


/* ── DL_ENCAP pipe (FDB pass-through — REFORMAT disabled for bringup) ─ */
/*
 * TEMPORARY: No encap action.  Just forwards DL traffic to N3.
 * TODO: Re-enable GTP encap once ARGUMENT_64B is resolved.
 */
static doca_error_t
build_dl_encap_pipe(dpu_pipeline_ctx_t *ctx)
{
    doca_error_t result;
    struct doca_flow_pipe_cfg *pipe_cfg;

    result = doca_flow_pipe_cfg_create(&pipe_cfg, ctx->switch_port);
    if (result != DOCA_SUCCESS) return result;

    doca_flow_pipe_cfg_set_name(pipe_cfg, "DL_ENCAP");
    doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_BASIC);
    doca_flow_pipe_cfg_set_is_root(pipe_cfg, false);
    doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 2048);

    /* Match pkt_meta (changeable) — keep this so entry add/update still works */
    struct doca_flow_match match = {};
    match.meta.pkt_meta = UINT32_MAX;

    struct doca_flow_match mask = {};
    mask.meta.pkt_meta = ~REINJECT_BITS_MASK;  /* 0xFFFFFFFC */

    doca_flow_pipe_cfg_set_match(pipe_cfg, &match, &mask);

    /* NO encap actions — pure pass-through (encap disabled for bringup) */

    /* Forward: out N3 wire (plain IP, no GTP encap, but pipeline runs) */
    struct doca_flow_fwd fwd = {
        .type = DOCA_FLOW_FWD_PORT,
        .port_id = ctx->port_cfg.n3_port_id,
    };

    struct doca_flow_fwd fwd_miss = {
        .type = DOCA_FLOW_FWD_DROP,
    };

    result = doca_flow_pipe_create(pipe_cfg, &fwd, &fwd_miss,
                                    &ctx->dl_encap_pipe);
    doca_flow_pipe_cfg_destroy(pipe_cfg);

    if (result != DOCA_SUCCESS)
        DOCA_LOG_ERR("DL_ENCAP pipe creation failed: %s",
                     doca_error_get_descr(result));
    return result;
}


/* ── ROOT control pipe ─────────────────────────────────────────────── */
/*
 * Matches parser_meta.port_id + protocol to steer traffic:
 *   Prio 0: N3 port + GTP-U → UL_MATCH[0]
 *   Prio 1: N6 port + IPv4  → DL_MATCH[0]
 *   Miss:   → TO_HOST
 */
static doca_error_t
build_root_pipe(dpu_pipeline_ctx_t *ctx)
{
    doca_error_t result;
    struct doca_flow_pipe_cfg *pipe_cfg;

    result = doca_flow_pipe_cfg_create(&pipe_cfg, ctx->switch_port);
    if (result != DOCA_SUCCESS) return result;

    doca_flow_pipe_cfg_set_name(pipe_cfg, "ROOT");
    doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_CONTROL);
    doca_flow_pipe_cfg_set_is_root(pipe_cfg, true);

    struct doca_flow_fwd fwd_miss = {
        .type = DOCA_FLOW_FWD_PIPE,
        .next_pipe = ctx->to_host_pipe,
    };

    result = doca_flow_pipe_create(pipe_cfg, NULL, &fwd_miss,
                                    &ctx->root_pipe);
    doca_flow_pipe_cfg_destroy(pipe_cfg);
    if (result != DOCA_SUCCESS) return result;

    /* Priority 0: GTP-U from N3 → UL_MATCH[0] */
    {
        struct doca_flow_match match = {};
        match.parser_meta.port_id = ctx->port_cfg.n3_port_id;
        match.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP;
        match.outer.udp.l4_port.dst_port = RTE_BE16(GTP_UDP_PORT);

        struct doca_flow_match mask = {};
        mask.parser_meta.port_id = UINT16_MAX;
        mask.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP;
        mask.outer.udp.l4_port.dst_port = UINT16_MAX;

        struct doca_flow_fwd fwd = {
            .type = DOCA_FLOW_FWD_PIPE,
            .next_pipe = ctx->ul_match_pipes[0],
        };

        struct doca_flow_pipe_entry *entry;
        result = doca_flow_pipe_control_add_entry(0, ctx->root_pipe,
                                                   &match, &mask,
                                                   NULL, NULL, NULL, NULL,
                                                   NULL, 0, &fwd, NULL, &entry);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("ROOT: UL control entry failed");
            return result;
        }
    }

    /* Priority 1: IPv4 from N6 → DL_MATCH[0] */
    {
        struct doca_flow_match match = {};
        match.parser_meta.port_id = ctx->port_cfg.n6_port_id;
        match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;

        struct doca_flow_match mask = {};
        mask.parser_meta.port_id = UINT16_MAX;
        mask.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;

        struct doca_flow_fwd fwd = {
            .type = DOCA_FLOW_FWD_PIPE,
            .next_pipe = ctx->dl_match_pipes[0],
        };

        struct doca_flow_pipe_entry *entry;
        result = doca_flow_pipe_control_add_entry(0, ctx->root_pipe,
                                                   &match, &mask,
                                                   NULL, NULL, NULL, NULL,
                                                   NULL, 1, &fwd, NULL, &entry);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("ROOT: DL control entry failed");
            return result;
        }
    }

    doca_flow_entries_process(ctx->switch_port, 0, 0, 0);

    DOCA_LOG_INFO("ROOT pipe: N3+GTP→UL_MATCH[0], N6+IPv4→DL_MATCH[0], "
                  "miss→TO_HOST");

    /* ---- Reinject entries for ARM buffer drain ---- */
    /* Two-bit pkt_meta scheme (no port_id matching needed):
     *   bit 0 = REINJECT_MARKER_BIT (set on ALL reinject pkts)
     *   bit 1 = REINJECT_UL_DIR_BIT (set only for UL reinject)
     * Normal wire traffic has pkt_meta == 0 at ROOT ingress,
     * so bits 0-1 are 00 and neither reinject entry matches. */

    if (ctx->to_dpu_arm_pipe != NULL) {
        /* Priority 2: pkt_meta bits 0-1 == 0x03 → UL_DECAP (UL reinject) */
        {
            struct doca_flow_match rmatch = {};
            rmatch.meta.pkt_meta = REINJECT_MARKER_BIT | REINJECT_UL_DIR_BIT;

            struct doca_flow_match rmask = {};
            rmask.meta.pkt_meta = REINJECT_BITS_MASK;

            struct doca_flow_fwd rfwd = {
                .type = DOCA_FLOW_FWD_PIPE,
                .next_pipe = ctx->ul_decap_pipe,
            };

            struct doca_flow_pipe_entry *rentry;
            result = doca_flow_pipe_control_add_entry(
                0, ctx->root_pipe,
                &rmatch, &rmask,
                NULL, NULL, NULL, NULL,
                NULL, 2, &rfwd, NULL, &rentry);
            if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("ROOT: UL reinject entry failed: %s",
                             doca_error_get_descr(result));
                return result;
            }
            DOCA_LOG_INFO("ROOT: prio 2 — pkt_meta & 0x03 == 0x03 → UL_DECAP (UL reinject)");
        }

        /* Priority 3: pkt_meta bits 0-1 == 0x01 → DL_ENCAP (DL reinject) */
        {
            struct doca_flow_match rmatch = {};
            rmatch.meta.pkt_meta = REINJECT_MARKER_BIT;

            struct doca_flow_match rmask = {};
            rmask.meta.pkt_meta = REINJECT_BITS_MASK;

            struct doca_flow_fwd rfwd = {
                .type = DOCA_FLOW_FWD_PIPE,
                .next_pipe = ctx->dl_encap_pipe,
            };

            struct doca_flow_pipe_entry *rentry;
            result = doca_flow_pipe_control_add_entry(
                0, ctx->root_pipe,
                &rmatch, &rmask,
                NULL, NULL, NULL, NULL,
                NULL, 3, &rfwd, NULL, &rentry);
            if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("ROOT: DL reinject entry failed: %s",
                             doca_error_get_descr(result));
                return result;
            }
            DOCA_LOG_INFO("ROOT: prio 3 — pkt_meta & 0x03 == 0x01 → DL_ENCAP (DL reinject)");
        }

        doca_flow_entries_process(ctx->switch_port, 0, 0, 0);
    }

    return DOCA_SUCCESS;
}


/* ═══════════════════════════════════════════════════════════════════════
 *  Meter creation helper (trTCM RFC 2698)
 * ═══════════════════════════════════════════════════════════════════════ */

/**
 * Create a shared trTCM meter (CIR=GBR, PIR=MBR).
 * Returns NO_METER_ID if both rates are 0 (no QER → skip metering).
 */
static doca_error_t
create_trtcm_meter(struct doca_flow_port *port,
                   uint32_t *meter_id,
                   uint64_t gbr_kbps,
                   uint64_t mbr_kbps)
{
    /* No QER / no rate limit → skip metering entirely */
    if (gbr_kbps == 0 && mbr_kbps == 0) {
        *meter_id = NO_METER_ID;
        return DOCA_SUCCESS;
    }

    doca_error_t result;

    uint64_t cir_bps = gbr_kbps * 1000 / 8;
    uint64_t pir_bps = mbr_kbps * 1000 / 8;

    /* PIR must be >= CIR per RFC 2698 */
    if (pir_bps < cir_bps)
        pir_bps = cir_bps;

    /* If only GBR is 0, set CIR to a reasonable floor */
    if (cir_bps == 0)
        cir_bps = 1;
    if (pir_bps == 0)
        pir_bps = 1;

    struct doca_flow_shared_resource_cfg cfg = {};
    cfg.meter_cfg.limit_type = DOCA_FLOW_METER_LIMIT_TYPE_BYTES;
    cfg.meter_cfg.color_mode = DOCA_FLOW_METER_COLOR_MODE_BLIND;
    cfg.meter_cfg.alg = DOCA_FLOW_METER_ALGORITHM_TYPE_RFC2698;
    cfg.meter_cfg.cir = cir_bps;
    cfg.meter_cfg.cbs = (cir_bps / 100 > 4096) ? cir_bps / 100 : 4096;
    cfg.meter_cfg.rfc2698.pir = pir_bps;
    cfg.meter_cfg.rfc2698.pbs = (pir_bps / 100 > 4096) ? pir_bps / 100 : 4096;

    result = doca_flow_port_shared_resource_get(port,
                                                 DOCA_FLOW_SHARED_RESOURCE_METER,
                                                 meter_id);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Meter alloc failed: %s", doca_error_get_descr(result));
        return result;
    }

    result = doca_flow_port_shared_resource_set_cfg(port,
                                                     DOCA_FLOW_SHARED_RESOURCE_METER,
                                                     *meter_id, &cfg);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Meter %u config failed: %s",
                     *meter_id, doca_error_get_descr(result));
    }
    return result;
}


/* ═══════════════════════════════════════════════════════════════════════
 *  Public API: Initialise the pipeline
 * ═══════════════════════════════════════════════════════════════════════ */

doca_error_t
dpu_pipeline_create_ports(dpu_pipeline_ctx_t *ctx,
                          const dpu_port_cfg_t *port_cfg,
                          uint16_t *rss_queues, uint32_t nr_rss_queues,
                          uint16_t *shaper_rss_queues,
                          uint32_t nr_shaper_rss_queues)
{
    doca_error_t result;

    memset(ctx, 0, sizeof(*ctx));
    ctx->port_cfg = *port_cfg;

    /* Store RSS config for TO_DPU_ARM pipe (idle UE buffering) */
    if (rss_queues && nr_rss_queues > 0) {
        uint32_t n = (nr_rss_queues > BUFFER_RX_QUEUES)
                         ? BUFFER_RX_QUEUES : nr_rss_queues;
        for (uint32_t i = 0; i < n; i++)
            ctx->rss_queues[i] = rss_queues[i];
        ctx->nr_rss_queues = n;
    }

    /* Store RSS config for SHAPED color-gate pipes (GBR shaping) */
    if (shaper_rss_queues && nr_shaper_rss_queues > 0) {
        uint32_t n = (nr_shaper_rss_queues > SHAPER_RX_QUEUES)
                         ? SHAPER_RX_QUEUES : nr_shaper_rss_queues;
        for (uint32_t i = 0; i < n; i++)
            ctx->shaper_rss_queues[i] = shaper_rss_queues[i];
        ctx->nr_shaper_rss_queues = n;
    }

    result = init_doca_flow(ctx->nr_rss_queues + ctx->nr_shaper_rss_queues);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("DOCA Flow init failed (pipe_queues=%u): %s",
                     ctx->nr_rss_queues + ctx->nr_shaper_rss_queues,
                     doca_error_get_descr(result));
        return result;
    }

    /* Create ports — each bound to a DOCA device */
    result = create_port(port_cfg->n3_port_id, port_cfg->n3_dev,
                          NULL, &ctx->ports[0]);
    if (result != DOCA_SUCCESS) return result;

    result = create_port(port_cfg->n6_port_id, port_cfg->n6_dev,
                          NULL, &ctx->ports[1]);
    if (result != DOCA_SUCCESS) return result;

    result = create_port(port_cfg->host_vf_port_id, port_cfg->host_vf_dev,
                          port_cfg->host_vf_rep, &ctx->ports[2]);
    if (result != DOCA_SUCCESS) return result;

    ctx->nb_ports = 3;

    ctx->switch_port = doca_flow_port_switch_get(ctx->ports[0]);
    if (!ctx->switch_port) {
        DOCA_LOG_ERR("Failed to get switch manager port");
        return DOCA_ERROR_INITIALIZATION;
    }

    /* In switch mode, port pairing is NOT used.  Forwarding between ports
     * is done via DOCA_FLOW_FWD_PORT with fwd.port_id.  Calling
     * doca_flow_port_pair() in switch mode causes a segfault. */

    DOCA_LOG_INFO("DOCA Flow ports created: %u ports (N3=%u, N6=%u, host=%u)",
                  ctx->nb_ports, port_cfg->n3_port_id,
                  port_cfg->n6_port_id, port_cfg->host_vf_port_id);
    return DOCA_SUCCESS;
}

doca_error_t
dpu_pipeline_build_pipes(dpu_pipeline_ctx_t *ctx)
{
    doca_error_t result;
    const dpu_port_cfg_t *port_cfg = &ctx->port_cfg;

    /* Build pipes in dependency order */
    uint32_t pipe_count = 14;  /* base: TO_HOST + UL_DECAP + DL_ENCAP + UL/DL POLICED + UL/DL MATCH(4+4) + ROOT */
    if (ctx->nr_rss_queues > 0) pipe_count++;       /* TO_DPU_ARM */
    if (ctx->nr_shaper_rss_queues > 0) pipe_count += 2; /* UL+DL shaped gates */
    DOCA_LOG_INFO("Building %u-pipe hierarchy...", pipe_count);

    result = build_to_host_pipe(ctx);
    if (result != DOCA_SUCCESS) return result;

    /* TO_DPU_ARM: built early (before match pipes) so it can be a fwd target.
     * Only built if RSS queues were provided (buffering enabled). */
    if (ctx->nr_rss_queues > 0) {
        result = build_to_dpu_arm_pipe(ctx);
        if (result != DOCA_SUCCESS) return result;
    }

    /* UL_DECAP: FDB pass-through (decap disabled for bringup).
     * Built before color gates so UL color gates can FWD_PIPE to it. */
    result = build_ul_decap_pipe(ctx);
    if (result != DOCA_SUCCESS) return result;

    /* DL_ENCAP: FDB pass-through (encap disabled for bringup).
     * Built before color gates so DL color gates can FWD_PIPE to it. */
    result = build_dl_encap_pipe(ctx);
    if (result != DOCA_SUCCESS) return result;

    /* POLICED color gates: GREEN+YELLOW → pipe (UL_DECAP/DL_ENCAP), RED → DROP */
    result = build_color_gate_policed_pipe(ctx, "UL_COLOR_GATE_POLICED",
                                           port_cfg->n6_port_id,
                                           ctx->ul_decap_pipe,
                                           &ctx->ul_color_gate_policed_pipe);
    if (result != DOCA_SUCCESS) return result;

    result = build_color_gate_policed_pipe(ctx, "DL_COLOR_GATE_POLICED",
                                           port_cfg->n3_port_id,
                                           ctx->dl_encap_pipe,
                                           &ctx->dl_color_gate_policed_pipe);
    if (result != DOCA_SUCCESS) return result;

    /* SHAPED color gates: GREEN → pipe, YELLOW → ARM RSS, RED → DROP (GBR flows) */
    if (ctx->nr_shaper_rss_queues > 0) {
        result = build_color_gate_shaped_pipe(ctx, "UL_COLOR_GATE_SHAPED",
                                              port_cfg->n6_port_id,
                                              ctx->ul_decap_pipe,
                                              ctx->shaper_rss_queues,
                                              ctx->nr_shaper_rss_queues,
                                              &ctx->ul_color_gate_shaped_pipe);
        if (result != DOCA_SUCCESS) return result;

        result = build_color_gate_shaped_pipe(ctx, "DL_COLOR_GATE_SHAPED",
                                              port_cfg->n3_port_id,
                                              ctx->dl_encap_pipe,
                                              ctx->shaper_rss_queues,
                                              ctx->nr_shaper_rss_queues,
                                              &ctx->dl_color_gate_shaped_pipe);
        if (result != DOCA_SUCCESS) return result;
    }

    result = build_ul_match_pipes(ctx);
    if (result != DOCA_SUCCESS) return result;

    result = build_dl_match_pipes(ctx);
    if (result != DOCA_SUCCESS) return result;

    result = build_root_pipe(ctx);
    if (result != DOCA_SUCCESS) return result;

    DOCA_LOG_INFO("Pipeline initialised: %u pipes, %u ports%s%s",
                  pipe_count, ctx->nb_ports,
                  ctx->nr_rss_queues > 0 ? ", buffering enabled" : "",
                  ctx->nr_shaper_rss_queues > 0 ? ", shaping enabled" : "");
    return DOCA_SUCCESS;
}


/* ═══════════════════════════════════════════════════════════════════════
 *  Public API: Insert a rule from hw_offload_msg
 * ═══════════════════════════════════════════════════════════════════════ */

doca_error_t
dpu_pipeline_insert_rule(dpu_pipeline_ctx_t *ctx, const hw_offload_msg_t *msg)
{
    doca_error_t result;

    if (!msg || msg->magic != HW_OFFLOAD_MAGIC) {
        DOCA_LOG_ERR("insert_rule: invalid message");
        return DOCA_ERROR_INVALID_VALUE;
    }

    /* Guard: reject hw_rule_id values whose htonl representation has
     * bits 0-1 set — these would collide with reinject markers and
     * cause DL_ENCAP pkt_meta aliasing (mask 0xFFFFFFFC). */
    if (htonl(msg->hw_rule_id) & REINJECT_BITS_MASK) {
        DOCA_LOG_ERR("insert_rule: hw_rule_id=%u unsafe — "
                     "htonl(id)=0x%08x has low bits set (reinject collision)",
                     msg->hw_rule_id, htonl(msg->hw_rule_id));
        return DOCA_ERROR_INVALID_VALUE;
    }

    /* Guard: reject duplicate hw_rule_id (24-bit wrapping can collide
     * with a still-active rule after 16.7M allocations) */
    if (find_record(ctx, msg->hw_rule_id)) {
        DOCA_LOG_ERR("insert_rule: hw_rule_id=%u already active — "
                     "ID collision after 24-bit wrap",
                     msg->hw_rule_id);
        return DOCA_ERROR_ALREADY_EXIST;
    }

    /* Select priority bucket from 3GPP precedence */
    int bucket = precedence_to_bucket(msg->precedence);

    if (msg->direction == HW_DIR_UPLINK) {
        /* ── UPLINK ──────────────────────────────────────────────────── */

        /* Meter: skip if no QER (GBR + MBR both 0) */
        uint32_t meter_id;
        result = create_trtcm_meter(ctx->switch_port, &meter_id,
                                     msg->gbr_ul, msg->mbr_ul);
        if (result != DOCA_SUCCESS) return result;

        /* Match: TEID only (bringup — QFI + UE IP stripped). */
        struct doca_flow_match match = {};
        match.tun.type = DOCA_FLOW_TUN_GTPU;
        match.tun.gtp_teid = htonl(msg->teid);

        /* Actions: NONE for bringup (no pkt_meta, no meter on pipe) */

        /* Monitor: NONE for bringup */

        /* Fwd: pipe fwd is fixed to UL_DECAP, no per-entry fwd needed */

        struct doca_flow_pipe_entry *entry;
        result = doca_flow_pipe_basic_add_entry(0, ctx->ul_match_pipes[bucket],
                                           &match, 0, NULL,
                                           NULL, NULL,
                                           0, NULL, &entry);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("UL entry failed hw_rule_id=%u bucket=%d: %s",
                         msg->hw_rule_id, bucket,
                         doca_error_get_descr(result));
            if (meter_id != NO_METER_ID)
                doca_flow_port_shared_resource_put(
                    ctx->switch_port, DOCA_FLOW_SHARED_RESOURCE_METER,
                    meter_id);
            return result;
        }

        doca_flow_entries_process(ctx->switch_port, 0, 0, 0);

        /* Store entry handle in record for future update/delete */
        dpu_rule_record_t *rec = alloc_record(ctx);
        if (!rec) {
            DOCA_LOG_ERR("UL rule pool exhausted for hw_rule_id=%u",
                         msg->hw_rule_id);
            doca_flow_pipe_remove_entry(0, DOCA_FLOW_NO_WAIT, entry);
            doca_flow_entries_process(ctx->switch_port, 0, 0, 0);
            if (meter_id != NO_METER_ID)
                doca_flow_port_shared_resource_put(
                    ctx->switch_port, DOCA_FLOW_SHARED_RESOURCE_METER,
                    meter_id);
            return DOCA_ERROR_FULL;
        }
        rec->in_use       = true;
        rec->hw_rule_id   = msg->hw_rule_id;
        rec->ul_entry     = entry;
        rec->dl_entry     = NULL;
        rec->dl_encap_entry = NULL;
        rec->pipe_bucket  = (uint8_t)bucket;
        rec->direction    = HW_DIR_UPLINK;
        rec->current_mode = DPU_MODE_FAST;
        rec->meter_id     = meter_id;
        rec->is_gbr_flow  = false;  /* bringup: no GBR distinction */

        doca_flow_entries_process(ctx->switch_port, 0, 0, 0);

        DOCA_LOG_INFO("UL rule: hw_rule=%u teid=0x%x qfi=%u bucket=P%d "
                      "meter=%s gbr=%s",
                      msg->hw_rule_id, msg->teid, msg->qfi, bucket,
                      (meter_id != NO_METER_ID) ? "yes" : "none",
                      "n/a(bringup)");

    } else {
        /* ── DOWNLINK ────────────────────────────────────────────────── */

        uint32_t meter_id;
        result = create_trtcm_meter(ctx->switch_port, &meter_id,
                                     msg->gbr_dl, msg->mbr_dl);
        if (result != DOCA_SUCCESS) return result;

        /* DL_MATCH entry: UE destination IP only.
         * SDF fields are wildcarded at the pipe level (mask=0). */
        struct doca_flow_match dl_match = {};
        dl_match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
        dl_match.outer.ip4.dst_ip = msg->ue_ipv4.s_addr;  /* NBO */

        /* Actions: NONE for bringup (no pkt_meta, no meter on pipe) */

        /* Monitor: NONE for bringup */

        /* Fwd: pipe fwd is fixed to DL_ENCAP, no per-entry fwd needed */

        struct doca_flow_pipe_entry *dl_entry;
        result = doca_flow_pipe_basic_add_entry(0, ctx->dl_match_pipes[bucket],
                                           &dl_match, 0, NULL,
                                           NULL, NULL,
                                           0, NULL, &dl_entry);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("DL_MATCH entry failed hw_rule_id=%u bucket=%d: %s",
                         msg->hw_rule_id, bucket,
                         doca_error_get_descr(result));
            if (meter_id != NO_METER_ID)
                doca_flow_port_shared_resource_put(
                    ctx->switch_port, DOCA_FLOW_SHARED_RESOURCE_METER,
                    meter_id);
            return result;
        }

        /* Allocate record early so we can store DL + ENCAP handles together */
        dpu_rule_record_t *rec = alloc_record(ctx);
        if (!rec) {
            DOCA_LOG_ERR("DL rule pool exhausted for hw_rule_id=%u",
                         msg->hw_rule_id);
            doca_flow_pipe_remove_entry(0, DOCA_FLOW_NO_WAIT, dl_entry);
            doca_flow_entries_process(ctx->switch_port, 0, 0, 0);
            if (meter_id != NO_METER_ID)
                doca_flow_port_shared_resource_put(
                    ctx->switch_port, DOCA_FLOW_SHARED_RESOURCE_METER,
                    meter_id);
            return DOCA_ERROR_FULL;
        }
        rec->in_use       = true;
        rec->hw_rule_id   = msg->hw_rule_id;
        rec->ul_entry     = NULL;
        rec->dl_entry     = dl_entry;
        rec->dl_encap_entry = NULL;
        rec->pipe_bucket  = (uint8_t)bucket;
        rec->direction    = HW_DIR_DOWNLINK;
        rec->current_mode = DPU_MODE_FAST;
        rec->meter_id     = meter_id;
        rec->is_gbr_flow  = false;  /* bringup: no GBR distinction */

        /* DL_ENCAP entry: pkt_meta tag for this rule (no encap for bringup) */
        if (msg->ohc_desc == HW_OHC_GTPU_UDP_IPV4) {
            struct doca_flow_match encap_match = {};
            encap_match.meta.pkt_meta = htonl(msg->hw_rule_id);

            /* TODO: restore encap_actions when REFORMAT is re-enabled */

            struct doca_flow_pipe_entry *encap_entry;
            result = doca_flow_pipe_basic_add_entry(0, ctx->dl_encap_pipe,
                                               &encap_match, 0, NULL,
                                               NULL, NULL,
                                               0, NULL, &encap_entry);
            if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("DL_ENCAP entry failed hw_rule_id=%u: %s",
                             msg->hw_rule_id, doca_error_get_descr(result));
                /* Roll back DL_MATCH entry, record, and meter */
                doca_flow_pipe_remove_entry(0, DOCA_FLOW_NO_WAIT, dl_entry);
                doca_flow_entries_process(ctx->switch_port, 0, 0, 0);
                if (meter_id != NO_METER_ID)
                    doca_flow_port_shared_resource_put(
                        ctx->switch_port, DOCA_FLOW_SHARED_RESOURCE_METER,
                        meter_id);
                free_record(rec);
                return result;
            }
            rec->dl_encap_entry = encap_entry;
        }

        doca_flow_entries_process(ctx->switch_port, 0, 0, 0);

        DOCA_LOG_INFO("DL rule: hw_rule=%u ue_ip=%08x ohc_teid=0x%x "
                      "bucket=P%d meter=%s gbr=%s",
                      msg->hw_rule_id, msg->ue_ipv4.s_addr, msg->ohc_teid,
                      bucket, (meter_id != NO_METER_ID) ? "yes" : "none",
                      "n/a(bringup)");
    }

    ctx->nb_entries++;
    return DOCA_SUCCESS;
}


/* ═══════════════════════════════════════════════════════════════════════
 *  Public API: Delete a rule
 * ═══════════════════════════════════════════════════════════════════════ */

doca_error_t
dpu_pipeline_delete_rule(dpu_pipeline_ctx_t *ctx, uint32_t hw_rule_id)
{
    dpu_rule_record_t *rec = find_record(ctx, hw_rule_id);
    if (!rec) {
        DOCA_LOG_WARN("delete_rule: hw_rule_id=%u not found", hw_rule_id);
        return DOCA_ERROR_NOT_FOUND;
    }

    doca_error_t result;
    bool any_remove_failed = false;

    /* Remove DOCA Flow entries (UL or DL+ENCAP).
     * On success, null out the handle so a retry after partial failure
     * skips already-removed entries instead of double-removing. */
    if (rec->ul_entry) {
        result = doca_flow_pipe_remove_entry(0, DOCA_FLOW_NO_WAIT,
                                              rec->ul_entry);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("delete_rule: UL remove failed hw_rule_id=%u: %s",
                         hw_rule_id, doca_error_get_descr(result));
            any_remove_failed = true;
        } else {
            rec->ul_entry = NULL;
        }
    }
    if (rec->dl_entry) {
        result = doca_flow_pipe_remove_entry(0, DOCA_FLOW_NO_WAIT,
                                              rec->dl_entry);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("delete_rule: DL remove failed hw_rule_id=%u: %s",
                         hw_rule_id, doca_error_get_descr(result));
            any_remove_failed = true;
        } else {
            rec->dl_entry = NULL;
        }
    }
    if (rec->dl_encap_entry) {
        result = doca_flow_pipe_remove_entry(0, DOCA_FLOW_NO_WAIT,
                                              rec->dl_encap_entry);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("delete_rule: ENCAP remove failed hw_rule_id=%u: %s",
                         hw_rule_id, doca_error_get_descr(result));
            any_remove_failed = true;
        } else {
            rec->dl_encap_entry = NULL;
        }
    }

    doca_flow_entries_process(ctx->switch_port, 0, 0, 0);

    /* If any entry removal failed, do NOT release meter or free record.
     * HW entries may still reference the meter — releasing it could cause
     * the meter ID to be reused, leading to data-plane corruption.
     * Return error so caller can handle the partial failure. */
    if (any_remove_failed) {
        DOCA_LOG_ERR("delete_rule: hw_rule_id=%u partially failed — "
                     "record and meter retained to prevent UAF",
                     hw_rule_id);
        return DOCA_ERROR_DRIVER;
    }

    /* Release shared meter if allocated */
    if (rec->meter_id != NO_METER_ID) {
        doca_flow_port_shared_resource_put(
            ctx->switch_port, DOCA_FLOW_SHARED_RESOURCE_METER, rec->meter_id);
    }

    free_record(rec);
    if (ctx->nb_entries > 0)
        ctx->nb_entries--;

    DOCA_LOG_INFO("Deleted rule hw_rule_id=%u", hw_rule_id);
    return DOCA_SUCCESS;
}


/* ═══════════════════════════════════════════════════════════════════════
 *  Public API: Update FAR (forwarding action change)
 *
 *  - BUFF: swap per-entry fwd from COLOR_GATE → TO_DPU_ARM so packets
 *    are redirected to ARM Rx queues for buffering.  Falls back to
 *    deleting the rule if TO_DPU_ARM pipe is not available.
 *  - FORW: if in BUFFER mode, swap per-entry fwd back to COLOR_GATE
 *    (caller is responsible for draining buffered packets first).
 *    If OHC params changed, update the DL_ENCAP entry in-place.
 *  - DROP: remove HW rule entirely (traffic falls to SW path).
 * ═══════════════════════════════════════════════════════════════════════ */

doca_error_t
dpu_pipeline_update_far(dpu_pipeline_ctx_t *ctx, const hw_offload_msg_t *msg)
{
    dpu_rule_record_t *rec = find_record(ctx, msg->hw_rule_id);
    if (!rec) {
        DOCA_LOG_WARN("update_far: hw_rule_id=%u not found", msg->hw_rule_id);
        return DOCA_ERROR_NOT_FOUND;
    }

    /* ── DROP: remove HW rule entirely ───────────────────────────── */
    if (msg->apply_action & HW_ACTION_DROP) {
        DOCA_LOG_INFO("update_far: DROP for hw_rule_id=%u — removing HW rule "
                      "(traffic falls to SW path)", msg->hw_rule_id);
        return dpu_pipeline_delete_rule(ctx, msg->hw_rule_id);
    }

    /* ── BUFF: swap per-entry fwd to TO_DPU_ARM ──────────────────── */
    if (msg->apply_action & HW_ACTION_BUFF) {
        if (rec->current_mode == DPU_MODE_BUFFER) {
            DOCA_LOG_DBG("update_far: hw_rule_id=%u already in BUFFER mode",
                         msg->hw_rule_id);
            return DOCA_SUCCESS;
        }

        /* If TO_DPU_ARM pipe is available, swap fwd. Otherwise, fall
         * back to deleting the rule (pre-Phase 2 behavior). */
        if (ctx->to_dpu_arm_pipe == NULL) {
            DOCA_LOG_WARN("update_far: BUFF for hw_rule_id=%u but "
                          "TO_DPU_ARM not available — deleting rule "
                          "(SW fallback)", msg->hw_rule_id);
            return dpu_pipeline_delete_rule(ctx, msg->hw_rule_id);
        }

        /* Determine which match pipe and entry handle */
        struct doca_flow_pipe *pipe;
        struct doca_flow_pipe_entry *entry;
        if (rec->direction == HW_DIR_UPLINK) {
            pipe = ctx->ul_match_pipes[rec->pipe_bucket];
            entry = rec->ul_entry;
        } else {
            pipe = ctx->dl_match_pipes[rec->pipe_bucket];
            entry = rec->dl_entry;
        }

        /* Swap fwd: COLOR_GATE → TO_DPU_ARM */
        struct doca_flow_fwd buf_fwd = {
            .type = DOCA_FLOW_FWD_PIPE,
            .next_pipe = ctx->to_dpu_arm_pipe,
        };

        doca_error_t result = doca_flow_pipe_basic_update_entry(
            0, pipe, 0,
            NULL,       /* actions: unchanged */
            NULL,       /* monitor: unchanged */
            &buf_fwd,   /* fwd: swap to TO_DPU_ARM */
            DOCA_FLOW_NO_WAIT, entry);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("update_far: fwd swap to TO_DPU_ARM failed "
                         "hw_rule_id=%u: %s",
                         msg->hw_rule_id, doca_error_get_descr(result));
            return result;
        }

        doca_flow_entries_process(ctx->switch_port, 0, 0, 0);
        rec->current_mode = DPU_MODE_BUFFER;

        DOCA_LOG_INFO("update_far: hw_rule_id=%u BUFF — fwd swapped to "
                      "TO_DPU_ARM (packets redirected to ARM)",
                      msg->hw_rule_id);
        return DOCA_SUCCESS;
    }

    /* ── FORW: restore fast path ─────────────────────────────────── */
    if (msg->apply_action & HW_ACTION_FORW) {
        /* If coming from BUFFER mode, swap fwd back to COLOR_GATE.
         * The caller (dpu_agent.c) is responsible for draining buffered
         * packets before calling this, so we don't drain here. */
        if (rec->current_mode == DPU_MODE_BUFFER) {
            struct doca_flow_pipe *pipe;
            struct doca_flow_pipe_entry *entry;
            struct doca_flow_pipe *color_gate;

            if (rec->direction == HW_DIR_UPLINK) {
                pipe = ctx->ul_match_pipes[rec->pipe_bucket];
                entry = rec->ul_entry;
                color_gate = rec->is_gbr_flow
                    ? ctx->ul_color_gate_shaped_pipe
                    : ctx->ul_color_gate_policed_pipe;
            } else {
                pipe = ctx->dl_match_pipes[rec->pipe_bucket];
                entry = rec->dl_entry;
                color_gate = rec->is_gbr_flow
                    ? ctx->dl_color_gate_shaped_pipe
                    : ctx->dl_color_gate_policed_pipe;
            }

            /* Swap fwd: TO_DPU_ARM → COLOR_GATE */
            struct doca_flow_fwd fast_fwd = {
                .type = DOCA_FLOW_FWD_PIPE,
                .next_pipe = color_gate,
            };

            doca_error_t result = doca_flow_pipe_basic_update_entry(
                0, pipe, 0,
                NULL,        /* actions: unchanged */
                NULL,        /* monitor: unchanged */
                &fast_fwd,   /* fwd: swap back to COLOR_GATE */
                DOCA_FLOW_NO_WAIT, entry);
            if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("update_far: fwd swap back to COLOR_GATE "
                             "failed hw_rule_id=%u: %s",
                             msg->hw_rule_id, doca_error_get_descr(result));
                return result;
            }

            doca_flow_entries_process(ctx->switch_port, 0, 0, 0);

            DOCA_LOG_INFO("update_far: hw_rule_id=%u FORW — fwd swapped "
                          "back to COLOR_GATE (fast path restored)",
                          msg->hw_rule_id);
        }

        /* OHC update: only meaningful for DL rules with an encap entry */
        if (rec->dl_encap_entry && msg->ohc_desc == HW_OHC_GTPU_UDP_IPV4) {
            struct doca_flow_actions encap_actions = {};
            encap_actions.encap_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;

            encap_actions.encap_cfg.encap.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
            encap_actions.encap_cfg.encap.outer.ip4.dst_ip =
                msg->ohc_ipv4.s_addr;
            encap_actions.encap_cfg.encap.outer.ip4.src_ip =
                ctx->port_cfg.upf_n3_ip;
            encap_actions.encap_cfg.encap.outer.ip4.ttl = 64;

            encap_actions.encap_cfg.encap.outer.l4_type_ext =
                DOCA_FLOW_L4_TYPE_EXT_UDP;
            encap_actions.encap_cfg.encap.outer.udp.l4_port.dst_port =
                RTE_BE16(GTP_UDP_PORT);

            encap_actions.encap_cfg.encap.tun.type = DOCA_FLOW_TUN_GTPU;
            encap_actions.encap_cfg.encap.tun.gtp_teid =
                htonl(msg->ohc_teid);
            encap_actions.encap_cfg.encap.tun.gtp_next_ext_hdr_type =
                GTP_EXT_PSC;
            encap_actions.encap_cfg.encap.tun.gtp_ext_psc_qfi =
                msg->encap_qfi;

            doca_error_t result = doca_flow_pipe_basic_update_entry(
                0, ctx->dl_encap_pipe, 0,
                &encap_actions, NULL, NULL,
                DOCA_FLOW_NO_WAIT, rec->dl_encap_entry);
            if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("update_far: encap update failed "
                             "hw_rule_id=%u: %s",
                             msg->hw_rule_id,
                             doca_error_get_descr(result));
                return result;
            }
            doca_flow_entries_process(ctx->switch_port, 0, 0, 0);

            DOCA_LOG_INFO("update_far: hw_rule_id=%u ENCAP updated "
                          "teid=0x%x dst_ip=%08x",
                          msg->hw_rule_id, msg->ohc_teid,
                          msg->ohc_ipv4.s_addr);
        }

        /* NOTE: current_mode is NOT set to FAST here.  The caller\n         * (comch_recv_cb) sets it after buffer quiesce completes,\n         * so that current_mode accurately reflects the lifecycle\n         * state during the quiesce window. */
        return DOCA_SUCCESS;
    }

    DOCA_LOG_WARN("update_far: unknown apply_action=%u for hw_rule_id=%u",
                  msg->apply_action, msg->hw_rule_id);
    return DOCA_SUCCESS;
}


/* ═══════════════════════════════════════════════════════════════════════
 *  Public API: Update QER (meter rate change)
 * ═══════════════════════════════════════════════════════════════════════ */

doca_error_t
dpu_pipeline_update_qer(dpu_pipeline_ctx_t *ctx, const hw_offload_msg_t *msg)
{
    dpu_rule_record_t *rec = find_record(ctx, msg->hw_rule_id);
    if (!rec) {
        DOCA_LOG_WARN("update_qer: hw_rule_id=%u not found", msg->hw_rule_id);
        return DOCA_ERROR_NOT_FOUND;
    }

    doca_error_t result;

    /* Pick direction-appropriate rates */
    uint64_t gbr_kbps = (rec->direction == HW_DIR_UPLINK)
                             ? msg->gbr_ul : msg->gbr_dl;
    uint64_t mbr_kbps = (rec->direction == HW_DIR_UPLINK)
                             ? msg->mbr_ul : msg->mbr_dl;

    uint32_t old_meter_id = rec->meter_id;

    /* Create new meter FIRST (may set NO_METER_ID if rates are 0).
     * Old meter stays valid until we confirm the entry update succeeds. */
    uint32_t new_meter_id;
    result = create_trtcm_meter(ctx->switch_port, &new_meter_id,
                                 gbr_kbps, mbr_kbps);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("update_qer: meter creation failed hw_rule_id=%u: %s",
                     msg->hw_rule_id, doca_error_get_descr(result));
        return result;
    }

    /* Update the entry's monitor via doca_flow_pipe_update_entry() */
    struct doca_flow_pipe_entry *entry = rec->ul_entry ? rec->ul_entry
                                                       : rec->dl_entry;
    struct doca_flow_pipe *pipe = (rec->direction == HW_DIR_UPLINK)
        ? ctx->ul_match_pipes[rec->pipe_bucket]
        : ctx->dl_match_pipes[rec->pipe_bucket];

    /*
     * Always pass a non-NULL monitor to update_entry so the entry's
     * meter attachment is explicitly updated.  When new_meter_id is
     * NO_METER_ID (rates → 0), the zeroed monitor detaches the meter
     * from the entry, making it safe to release the old meter below.
     * Passing NULL would leave the entry still referencing the old
     * meter — a use-after-release if we then free it.
     */
    struct doca_flow_monitor mon = {};
    if (new_meter_id != NO_METER_ID) {
        mon.meter_type = DOCA_FLOW_RESOURCE_TYPE_SHARED;
        mon.shared_meter.shared_meter_id = new_meter_id;
    }

    /* Detect GBR mode transition: does the per-entry fwd target need
     * to change between policed and shaped color gate? */
    bool was_gbr = rec->is_gbr_flow;
    bool now_gbr = (gbr_kbps > 0) &&
                   ((rec->direction == HW_DIR_UPLINK)
                    ? (ctx->ul_color_gate_shaped_pipe != NULL)
                    : (ctx->dl_color_gate_shaped_pipe != NULL));

    struct doca_flow_fwd *fwd_ptr = NULL;
    struct doca_flow_fwd gate_fwd = {};
    if (was_gbr != now_gbr) {
        /* If the rule is currently buffered, the entry's fwd points to
         * TO_DPU_ARM and must stay that way.  We still record the new
         * is_gbr_flow value below so that update_far(FORW) will pick the
         * correct color gate when the buffer drains.  Changing fwd here
         * would break the buffer path by redirecting traffic away from
         * ARM before the buffer has been drained. */
        if (rec->current_mode == DPU_MODE_BUFFER) {
            DOCA_LOG_INFO("update_qer: hw_rule_id=%u GBR transition "
                          "deferred — rule is in BUFFER mode",
                          msg->hw_rule_id);
        } else {
            struct doca_flow_pipe *new_gate;
            if (rec->direction == HW_DIR_UPLINK)
                new_gate = now_gbr ? ctx->ul_color_gate_shaped_pipe
                                   : ctx->ul_color_gate_policed_pipe;
            else
                new_gate = now_gbr ? ctx->dl_color_gate_shaped_pipe
                                   : ctx->dl_color_gate_policed_pipe;

            gate_fwd.type = DOCA_FLOW_FWD_PIPE;
            gate_fwd.next_pipe = new_gate;
            fwd_ptr = &gate_fwd;
        }
    }

    /* Single update_entry call: updates meter AND fwd atomically when
     * a GBR mode transition occurs, eliminating the window where the
     * meter generates YELLOW but the fwd still points to the wrong gate. */
    result = doca_flow_pipe_basic_update_entry(0, pipe, 0,
                                          NULL,      /* actions: unchanged */
                                          &mon,      /* monitor: new or zeroed */
                                          fwd_ptr,   /* fwd: new gate or NULL */
                                          DOCA_FLOW_NO_WAIT, entry);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("update_qer: update_entry failed hw_rule_id=%u: %s",
                     msg->hw_rule_id, doca_error_get_descr(result));
        /* Release the new meter we just created; old meter is still intact */
        if (new_meter_id != NO_METER_ID)
            doca_flow_port_shared_resource_put(
                ctx->switch_port, DOCA_FLOW_SHARED_RESOURCE_METER,
                new_meter_id);
        return result;
    }

    doca_flow_entries_process(ctx->switch_port, 0, 0, 0);

    /* Entry update succeeded — now safe to release the old meter */
    if (old_meter_id != NO_METER_ID) {
        doca_flow_port_shared_resource_put(
            ctx->switch_port, DOCA_FLOW_SHARED_RESOURCE_METER, old_meter_id);
    }
    rec->meter_id = new_meter_id;
    rec->is_gbr_flow = now_gbr;

    DOCA_LOG_INFO("update_qer: hw_rule_id=%u meter=%u→%u "
                  "mbr=%lu gbr=%lu kbps%s",
                  msg->hw_rule_id, old_meter_id, new_meter_id,
                  (unsigned long)mbr_kbps, (unsigned long)gbr_kbps,
                  (was_gbr != now_gbr)
                      ? (now_gbr ? " [policed→shaped]" : " [shaped→policed]")
                      : "");
    return DOCA_SUCCESS;
}


/* ═══════════════════════════════════════════════════════════════════════
 *  Public API: Downgrade a flow from shaped to policed color gate.
 *  Called when shaper registration fails — YELLOW packets will go to wire
 *  (slightly over-admitted) rather than being black-holed on ARM.
 * ═══════════════════════════════════════════════════════════════════════ */

doca_error_t
dpu_pipeline_downgrade_to_policed(dpu_pipeline_ctx_t *ctx, uint32_t hw_rule_id)
{
    dpu_rule_record_t *rec = find_record(ctx, hw_rule_id);
    if (!rec) {
        DOCA_LOG_WARN("downgrade_to_policed: hw_rule_id=%u not found",
                      hw_rule_id);
        return DOCA_ERROR_NOT_FOUND;
    }

    if (!rec->is_gbr_flow) {
        /* Already on policed gate — nothing to do */
        return DOCA_SUCCESS;
    }

    /* If the rule is currently buffered, fwd points to TO_DPU_ARM.
     * Don't touch the fwd — just clear is_gbr_flow so that
     * update_far(FORW) will restore to the policed gate later. */
    if (rec->current_mode == DPU_MODE_BUFFER) {
        rec->is_gbr_flow = false;
        DOCA_LOG_INFO("downgrade_to_policed: hw_rule_id=%u deferred — "
                      "rule is in BUFFER mode (is_gbr_flow cleared)",
                      hw_rule_id);
        return DOCA_SUCCESS;
    }

    struct doca_flow_pipe *pipe;
    struct doca_flow_pipe_entry *entry;
    struct doca_flow_pipe *policed_gate;

    if (rec->direction == HW_DIR_UPLINK) {
        pipe = ctx->ul_match_pipes[rec->pipe_bucket];
        entry = rec->ul_entry;
        policed_gate = ctx->ul_color_gate_policed_pipe;
    } else {
        pipe = ctx->dl_match_pipes[rec->pipe_bucket];
        entry = rec->dl_entry;
        policed_gate = ctx->dl_color_gate_policed_pipe;
    }

    struct doca_flow_fwd fwd = {
        .type = DOCA_FLOW_FWD_PIPE,
        .next_pipe = policed_gate,
    };

    doca_error_t result = doca_flow_pipe_basic_update_entry(
        0, pipe, 0,
        NULL,   /* actions: unchanged */
        NULL,   /* monitor: unchanged */
        &fwd,   /* fwd: shaped → policed */
        DOCA_FLOW_NO_WAIT, entry);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("downgrade_to_policed: update_entry failed "
                     "hw_rule_id=%u: %s",
                     hw_rule_id, doca_error_get_descr(result));
        return result;
    }

    doca_flow_entries_process(ctx->switch_port, 0, 0, 0);
    rec->is_gbr_flow = false;

    DOCA_LOG_INFO("downgrade_to_policed: hw_rule_id=%u fwd swapped "
                  "shaped→policed (shaper unavailable)", hw_rule_id);
    return DOCA_SUCCESS;
}


/* ═══════════════════════════════════════════════════════════════════════
 *  Public API: Set logical mode for a rule record
 * ═══════════════════════════════════════════════════════════════════════ */

void
dpu_pipeline_set_mode(dpu_pipeline_ctx_t *ctx,
                      uint32_t hw_rule_id,
                      uint8_t mode)
{
    dpu_rule_record_t *rec = find_record(ctx, hw_rule_id);
    if (rec)
        rec->current_mode = mode;
}


/* ═══════════════════════════════════════════════════════════════════════
 *  Public API: Update DL_ENCAP only (for BUFF→FORW handover)
 *
 *  Updates the DL_ENCAP entry's encap actions (target gNB IP, TEID, QFI)
 *  without changing the match entry fwd.  Called before begin_drain() so
 *  that drained packets get the new outer header.
 *
 *  No-op for UL rules, rules without a DL_ENCAP entry, or when encap
 *  params haven't changed.
 * ═══════════════════════════════════════════════════════════════════════ */

doca_error_t
dpu_pipeline_update_dlencap_only(dpu_pipeline_ctx_t *ctx,
                                const hw_offload_msg_t *msg)
{
    dpu_rule_record_t *rec = find_record(ctx, msg->hw_rule_id);
    if (!rec) {
        DOCA_LOG_WARN("update_dlencap_only: hw_rule_id=%u not found",
                      msg->hw_rule_id);
        return DOCA_ERROR_NOT_FOUND;
    }

    /* Only applies to DL rules with an existing encap entry */
    if (!rec->dl_encap_entry || msg->ohc_desc != HW_OHC_GTPU_UDP_IPV4)
        return DOCA_SUCCESS;

    struct doca_flow_actions encap_actions = {};
    encap_actions.encap_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;

    encap_actions.encap_cfg.encap.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
    encap_actions.encap_cfg.encap.outer.ip4.dst_ip = msg->ohc_ipv4.s_addr;
    encap_actions.encap_cfg.encap.outer.ip4.src_ip = ctx->port_cfg.upf_n3_ip;
    encap_actions.encap_cfg.encap.outer.ip4.ttl = 64;

    encap_actions.encap_cfg.encap.outer.l4_type_ext =
        DOCA_FLOW_L4_TYPE_EXT_UDP;
    encap_actions.encap_cfg.encap.outer.udp.l4_port.dst_port =
        RTE_BE16(GTP_UDP_PORT);

    encap_actions.encap_cfg.encap.tun.type = DOCA_FLOW_TUN_GTPU;
    encap_actions.encap_cfg.encap.tun.gtp_teid = htonl(msg->ohc_teid);
    encap_actions.encap_cfg.encap.tun.gtp_next_ext_hdr_type = GTP_EXT_PSC;
    encap_actions.encap_cfg.encap.tun.gtp_ext_psc_qfi = msg->encap_qfi;

    doca_error_t result = doca_flow_pipe_basic_update_entry(
        0, ctx->dl_encap_pipe, 0,
        &encap_actions, NULL, NULL,
        DOCA_FLOW_NO_WAIT, rec->dl_encap_entry);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("update_dlencap_only: encap update failed "
                     "hw_rule_id=%u: %s",
                     msg->hw_rule_id, doca_error_get_descr(result));
        return result;
    }
    doca_flow_entries_process(ctx->switch_port, 0, 0, 0);

    DOCA_LOG_INFO("update_dlencap_only: hw_rule_id=%u ENCAP updated "
                  "teid=0x%x dst_ip=%08x qfi=%u (before drain)",
                  msg->hw_rule_id, msg->ohc_teid,
                  msg->ohc_ipv4.s_addr, msg->encap_qfi);
    return DOCA_SUCCESS;
}


/* ═══════════════════════════════════════════════════════════════════════
 *  Public API: Update PDR (match criteria change → delete + re-insert)
 * ═══════════════════════════════════════════════════════════════════════ */

doca_error_t
dpu_pipeline_update_pdr(dpu_pipeline_ctx_t *ctx, const hw_offload_msg_t *msg)
{
    DOCA_LOG_INFO("update_pdr: delete+reinsert for hw_rule_id=%u",
                  msg->hw_rule_id);

    /* Delete old entries */
    doca_error_t result = dpu_pipeline_delete_rule(ctx, msg->hw_rule_id);
    if (result != DOCA_SUCCESS && result != DOCA_ERROR_NOT_FOUND) {
        DOCA_LOG_ERR("update_pdr: delete failed hw_rule_id=%u: %s",
                     msg->hw_rule_id, doca_error_get_descr(result));
        return result;
    }

    /* Re-insert with the same hw_rule_id (msg already contains it) */
    result = dpu_pipeline_insert_rule(ctx, msg);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("update_pdr: reinsert FAILED hw_rule_id=%u: %s — "
                     "rule has been deleted from HW and is NOT restored. "
                     "Traffic for this PDR falls to SW path until next "
                     "session modification.",
                     msg->hw_rule_id, doca_error_get_descr(result));
    }
    return result;
}


/* ═══════════════════════════════════════════════════════════════════════
 *  Public API: Teardown
 * ═══════════════════════════════════════════════════════════════════════ */

void
dpu_pipeline_destroy(dpu_pipeline_ctx_t *ctx)
{
    if (ctx->root_pipe)
        doca_flow_pipe_destroy(ctx->root_pipe);
    if (ctx->dl_encap_pipe)
        doca_flow_pipe_destroy(ctx->dl_encap_pipe);
    if (ctx->ul_decap_pipe)
        doca_flow_pipe_destroy(ctx->ul_decap_pipe);

    for (int p = 0; p < NUM_PRIO_BUCKETS; p++) {
        if (ctx->dl_match_pipes[p])
            doca_flow_pipe_destroy(ctx->dl_match_pipes[p]);
    }
    for (int p = 0; p < NUM_PRIO_BUCKETS; p++) {
        if (ctx->ul_match_pipes[p])
            doca_flow_pipe_destroy(ctx->ul_match_pipes[p]);
    }

    if (ctx->dl_color_gate_shaped_pipe)
        doca_flow_pipe_destroy(ctx->dl_color_gate_shaped_pipe);
    if (ctx->ul_color_gate_shaped_pipe)
        doca_flow_pipe_destroy(ctx->ul_color_gate_shaped_pipe);
    if (ctx->dl_color_gate_policed_pipe)
        doca_flow_pipe_destroy(ctx->dl_color_gate_policed_pipe);
    if (ctx->ul_color_gate_policed_pipe)
        doca_flow_pipe_destroy(ctx->ul_color_gate_policed_pipe);
    if (ctx->to_dpu_arm_pipe)
        doca_flow_pipe_destroy(ctx->to_dpu_arm_pipe);
    if (ctx->to_host_pipe)
        doca_flow_pipe_destroy(ctx->to_host_pipe);

    for (int i = 0; i < ctx->nb_ports; i++) {
        if (ctx->ports[i])
            doca_flow_port_stop(ctx->ports[i]);
    }

    doca_flow_destroy();

    DOCA_LOG_INFO("Pipeline destroyed (%u entries were active)",
                  ctx->nb_entries);
}
