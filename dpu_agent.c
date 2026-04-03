/*
 * dpu_agent.c — DPU Offload Agent (standalone DOCA application on BF3 ARM)
 *
 * Runs natively on the BlueField-3 ARM cores. Naturally initialises as the
 * primary owner of the physical HW devices (no --proc-type flag needed).
 *
 * Lifecycle:
 *   1. doca_argp parses CLI / JSON config, calls DPDK EAL init callback
 *   2. Open DOCA Comch server — waits for Host Agent connection
 *   3. Initialise DOCA Flow pipeline (16-pipe switch,hws hierarchy)
 *   4. Main loop: drive DOCA PE for Comch events
 *      - On recv: deserialise hw_offload_msg → dpu_pipeline_insert_rule()
 *   5. On SIGINT: destroy pipeline, close Comch, exit
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_mbuf.h>
#include <rte_flow.h>
#include <rte_lcore.h>

#include <doca_argp.h>
#include <doca_comch.h>
#include <doca_compat.h>  /* Must precede doca_ctx.h — defines DOCA_STABLE macro */
#include <doca_ctx.h>
#include <doca_dev.h>
#include <doca_dpdk.h>    /* doca_dpdk_port_probe — DOCA↔DPDK bridge */
#include <doca_error.h>
#include <doca_log.h>
#include <doca_pe.h>

#include "hw_offload_msg.h"
#include "dpu_pipeline.h"
#include "dpu_buffer.h"
#include "dpu_shaper.h"
#include "dpu_agent_config.h"

DOCA_LOG_REGISTER(DPU_AGENT);

/* ── Globals ────────────────────────────────────────────────────────── */
static volatile bool g_running = true;
static dpu_pipeline_ctx_t g_pipeline;
static dpu_buffer_ctx_t g_buffer;
static shaper_ctx_t g_shaper;

/* DOCA Comch server state */
static struct doca_dev          *g_comch_dev;
static struct doca_dev_rep      *g_comch_rep;   /* host PF/VF representor */
static struct doca_comch_server *g_comch_server;
static struct doca_pe           *g_comch_pe;

/* Counters */
static uint64_t g_msgs_received;
static uint64_t g_rules_inserted;
static uint64_t g_rules_failed;

/* Opened DOCA devices for Flow ports */
static struct doca_dev *g_n3_dev;
static struct doca_dev *g_n6_dev;
static struct doca_dev *g_vf_dev;
static struct doca_dev_rep *g_vf_rep;  /* host VF/PF representor for Flow port 2 */

/* DPDK resources for ARM buffering */
static struct rte_mempool *g_mbuf_pool;
static uint16_t g_proxy_port_id;     /* DPDK port ID for switch proxy port */
static unsigned int g_buffer_lcore;  /* lcore for buffer Rx loop */
static unsigned int g_shaper_lcore;  /* lcore for shaper Rx loop */

/* ── Configuration (populated by doca_argp from CLI / JSON) ─────────── */
static dpu_agent_cfg_t g_cfg = {
    .comch_pci       = "03:00.0",
    .rep_pci         = "",
    .server_name     = "dpu_agent",
    .n3_pci          = "03:00.0",
    .n6_pci          = "03:00.1",
    .vf_pci          = "",
    .n3_port_id      = 0,
    .n6_port_id      = 1,
    .host_vf_port_id = 2,
    .upf_n3_ip_str   = "",
    .upf_n3_mac_str  = "00:00:00:00:00:03",
    .gnb_mac_str     = "00:00:00:00:00:04",
    .upf_n6_mac_str  = "00:00:00:00:00:01",
    .dn_gw_mac_str   = "00:00:00:00:00:02",
};


/* ── Signal handler ─────────────────────────────────────────────────── */
static void
signal_handler(int sig)
{
    (void)sig;
    DOCA_LOG_INFO("Signal received — shutting down");
    g_running = false;
}


/* ═══════════════════════════════════════════════════════════════════════
 *  DOCA Comch callbacks
 * ═══════════════════════════════════════════════════════════════════════ */

static void
comch_server_connection_cb(struct doca_comch_event_connection_status_changed *event,
                           struct doca_comch_connection *conn,
                           uint8_t change_successful)
{
    if (change_successful)
        DOCA_LOG_INFO("Host Agent connected via Comch");
    else
        DOCA_LOG_WARN("Comch connection status change failed");
    (void)event;
    (void)conn;
}

static void
comch_server_disconnect_cb(struct doca_comch_event_connection_status_changed *event,
                           struct doca_comch_connection *conn,
                           uint8_t change_successful)
{
    DOCA_LOG_WARN("Host Agent disconnected from Comch");
    (void)event;
    (void)conn;
    (void)change_successful;
}

/**
 * Main Comch recv callback — this is where hw_offload_msg arrives
 * from the Host Agent and gets programmed into DOCA Flow silicon.
 */
static void
comch_recv_cb(struct doca_comch_event_msg_recv *event,
              uint8_t *recv_buffer,
              uint32_t msg_len,
              struct doca_comch_connection *conn)
{
    (void)event;
    (void)conn;

    g_msgs_received++;

    if (msg_len < sizeof(hw_offload_msg_t)) {
        DOCA_LOG_WARN("Comch recv: msg too short (%u < %zu)",
                      msg_len, sizeof(hw_offload_msg_t));
        return;
    }

    const hw_offload_msg_t *msg = (const hw_offload_msg_t *)recv_buffer;

    if (msg->magic != HW_OFFLOAD_MAGIC) {
        DOCA_LOG_WARN("Comch recv: bad magic 0x%08x", msg->magic);
        return;
    }

    DOCA_LOG_INFO("Comch recv: op=%u dir=%s pdr=%u hw_rule=%u",
                  msg->op,
                  msg->direction == HW_DIR_UPLINK ? "UL" : "DL",
                  msg->pdr_id, msg->hw_rule_id);

    switch (msg->op) {
    case HW_OP_CREATE: {
        doca_error_t result = dpu_pipeline_insert_rule(&g_pipeline, msg);
        if (result == DOCA_SUCCESS) {
            g_rules_inserted++;
            /* Register GBR flow in shaper if applicable */
            uint64_t gbr = (msg->direction == HW_DIR_UPLINK)
                           ? msg->gbr_ul : msg->gbr_dl;
            uint64_t mbr = (msg->direction == HW_DIR_UPLINK)
                           ? msg->mbr_ul : msg->mbr_dl;
            if (gbr > 0) {
                if (shaper_register_flow(&g_shaper, msg->hw_rule_id,
                                         msg->direction, gbr, mbr) != 0) {
                    DOCA_LOG_ERR("shaper register failed hw_rule_id=%u "
                                 "— downgrading to policed gate",
                                 msg->hw_rule_id);
                    dpu_pipeline_downgrade_to_policed(&g_pipeline,
                                                      msg->hw_rule_id);
                }
            }
        } else {
            g_rules_failed++;
            DOCA_LOG_ERR("Rule insert failed for hw_rule_id=%u: %s",
                         msg->hw_rule_id, doca_error_get_descr(result));
        }
        break;
    }
    case HW_OP_DELETE: {
        /* HW commit first (cut packet source), then quiesce + discard.
         * Order: delete HW rule → NIC drain delay → begin_close →
         *        quiesce_and_drain(discard)
         * Buffer close is ONLY attempted if HW commit succeeds.
         * If delete fails, the HW rule still forwards to ARM, so the
         * buffer must stay ACTIVE to avoid black-holing packets.
         * Shaper unregister is AFTER successful HW delete to prevent
         * YELLOW traffic black-hole if delete fails. */
        doca_error_t result = dpu_pipeline_delete_rule(&g_pipeline,
                                                        msg->hw_rule_id);
        if (result == DOCA_SUCCESS) {
            shaper_unregister_flow(&g_shaper, msg->hw_rule_id);
            DOCA_LOG_INFO("Rule deleted hw_rule_id=%u", msg->hw_rule_id);
            /* Brief delay for NIC DMA pipeline to deliver any packets
             * matched before the HW commit.  BF3 DMA < 10µs; 50µs is
             * ample margin and negligible vs. PFCP round-trip. */
            rte_delay_us_block(50);
            dpu_buffer_begin_close(&g_buffer, msg->hw_rule_id);
            if (dpu_buffer_quiesce_and_drain(&g_buffer, msg->hw_rule_id,
                                              true) < 0)
                DOCA_LOG_ERR("quiesce timeout hw_rule_id=%u (DELETE) "
                             "— flow stays CLOSING",
                             msg->hw_rule_id);
        } else {
            DOCA_LOG_ERR("Rule delete failed hw_rule_id=%u: %s "
                         "— buffer stays ACTIVE",
                         msg->hw_rule_id, doca_error_get_descr(result));
        }
        break;
    }
    case HW_OP_UPDATE_FAR: {
        /* State-machine lifecycle for buffer transitions:
         * FAST→BUFF: swap fwd to TO_DPU_ARM, register for buffering.
         * BUFF→FORW: update_dlencap_only → begin_drain → wait_drain_done → HW commit → close.
         * BUFF→DROP: HW commit → CLOSING → quiesce → discard → CLOSED. */
        if (msg->apply_action & HW_ACTION_BUFF) {
            /* Enter BUFFER mode: swap fwd, then register for buffering.
             * If register fails, rollback the fwd swap to prevent
             * a black-hole (packets sent to ARM with no buffer). */
            doca_error_t result = dpu_pipeline_update_far(&g_pipeline, msg);
            if (result == DOCA_SUCCESS) {
                if (dpu_buffer_register_flow(&g_buffer, msg->hw_rule_id,
                                             msg->direction) != 0) {
                    DOCA_LOG_ERR("buffer register failed hw_rule_id=%u "
                                 "— rolling back fwd swap",
                                 msg->hw_rule_id);
                    hw_offload_msg_t rollback = *msg;
                    rollback.apply_action = HW_ACTION_FORW;
                    dpu_pipeline_update_far(&g_pipeline, &rollback);
                    /* Rollback restores COLOR_GATE; mode stays FAST
                     * (update_far(BUFF) set BUFFER, but the BUFF failed,
                     *  so revert to FAST). */
                    dpu_pipeline_set_mode(&g_pipeline, msg->hw_rule_id,
                                          DPU_MODE_FAST);
                }
            } else {
                DOCA_LOG_ERR("update_far(BUFF) failed hw_rule_id=%u: %s",
                             msg->hw_rule_id, doca_error_get_descr(result));
            }
        } else if (msg->apply_action & HW_ACTION_FORW) {
            /*
             * Exit BUFFER mode with near-ordered delivery:
             *
             * 1. update_dlencap_only:  commit NEW gNB IP/TEID to DL_ENCAP
             *    HW match entry still forwards to TO_DPU_ARM, so no
             *    fast-path traffic hits DL_ENCAP for this rule yet.
             *    This ensures drained/reinjected DL packets get the
             *    correct outer header (critical for handover).
             *    No-op for UL rules or unchanged encap params.
             *
             * 2. begin_drain:      ACTIVE → DRAINING
             *    HW still points to TO_DPU_ARM.  Rx lcore bounded-drains
             *    old ring packets; while ring non-empty, new arrivals are
             *    re-enqueued at tail (FIFO-preserving).  Once ring is
             *    empty, new arrivals pass-through reinject directly.
             *    DL reinjects hit DL_ENCAP on N3 egress with the NEW
             *    encap params committed in step 1.
             *
             * 3. wait_drain_done:  spin until Rx lcore signals ring empty
             *    At this point all old buffered packets have been
             *    reinjected and new packets are pass-through.
             *
             * 4. update_far(FORW): swap HW fwd TO_DPU_ARM → COLOR_GATE
             *    New wire packets now take the fast path directly.
             *    DL_ENCAP already has the new params from step 1.
             *
             * 5. delay:            50µs for HW propagation
             *    Last few in-flight DMA packets are handled by Rx lcore
             *    pass-through (state is still DRAINING).
             *
             * 6. close_flow:       DRAINING → CLOSED
             *    Rx lcore stops accepting; residual packets flushed.
             *
             * 7. set_mode(FAST):   pipeline record updated
             */

            /* Step 1: update DL_ENCAP before drain so reinjected packets
             * get the new target gNB IP/TEID (handover correctness). */
            doca_error_t encap_result =
                dpu_pipeline_update_dlencap_only(&g_pipeline, msg);
            if (encap_result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("update_dlencap_only failed hw_rule_id=%u: %s "
                             "(FORW aborted, flow stays BUFFER)",
                             msg->hw_rule_id,
                             doca_error_get_descr(encap_result));
                break;
            }

            if (dpu_buffer_begin_drain(&g_buffer, msg->hw_rule_id) < 0) {
                DOCA_LOG_ERR("begin_drain failed hw_rule_id=%u "
                             "(FORW aborted)", msg->hw_rule_id);
                break;
            }

            if (dpu_buffer_wait_drain_done(&g_buffer,
                                            msg->hw_rule_id) < 0) {
                DOCA_LOG_ERR("wait_drain_done timeout hw_rule_id=%u "
                             "(FORW aborted, flow stays DRAINING)",
                             msg->hw_rule_id);
                break;
            }

            doca_error_t result = dpu_pipeline_update_far(&g_pipeline, msg);
            if (result == DOCA_SUCCESS) {
                rte_delay_us_block(50);
                if (dpu_buffer_close_flow(&g_buffer, msg->hw_rule_id) < 0)
                    DOCA_LOG_WARN("close_flow failed hw_rule_id=%u "
                                 "(unexpected state)", msg->hw_rule_id);
                dpu_pipeline_set_mode(&g_pipeline, msg->hw_rule_id,
                                      DPU_MODE_FAST);
            } else {
                DOCA_LOG_ERR("update_far(FORW) failed hw_rule_id=%u: %s "
                             "— flow stays DRAINING (pass-through)",
                             msg->hw_rule_id, doca_error_get_descr(result));
            }
        } else {
            /* DROP or other: HW commit first, then quiesce + discard.
             * Buffer close is ONLY attempted if HW commit succeeds.
             * If update_far fails, HW still forwards to ARM, so the
             * buffer must stay ACTIVE to avoid black-holing packets. */
            doca_error_t result = dpu_pipeline_update_far(&g_pipeline, msg);
            if (result == DOCA_SUCCESS) {
                /* Flow is now DROP — unregister from shaper so the slot
                 * is freed.  No YELLOW traffic can arrive after DROP. */
                shaper_unregister_flow(&g_shaper, msg->hw_rule_id);
                rte_delay_us_block(50);
                dpu_buffer_begin_close(&g_buffer, msg->hw_rule_id);
                if (dpu_buffer_quiesce_and_drain(&g_buffer, msg->hw_rule_id,
                                                  true) < 0)
                    DOCA_LOG_ERR("quiesce timeout hw_rule_id=%u (DROP) "
                                 "— flow stays CLOSING",
                                 msg->hw_rule_id);
            } else {
                DOCA_LOG_ERR("update_far(DROP) failed hw_rule_id=%u: %s "
                             "— buffer stays ACTIVE",
                             msg->hw_rule_id, doca_error_get_descr(result));
            }
        }
        break;
    }
    case HW_OP_UPDATE_QER: {
        doca_error_t result = dpu_pipeline_update_qer(&g_pipeline, msg);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("update_qer failed hw_rule_id=%u: %s",
                         msg->hw_rule_id, doca_error_get_descr(result));
            break;
        }
        /* Synchronise shaper registration with the new QER rates.
         * update_qer already handled the HW meter+fwd transition;
         * here we keep the ARM-side shaper in sync.
         *  - gbr>0: try update; if not found, register (0→gbr).
         *  - gbr==0: unregister (gbr→0 or no-op). */
        uint64_t qer_gbr = (msg->direction == HW_DIR_UPLINK)
                           ? msg->gbr_ul : msg->gbr_dl;
        uint64_t qer_mbr = (msg->direction == HW_DIR_UPLINK)
                           ? msg->mbr_ul : msg->mbr_dl;
        if (qer_gbr > 0) {
            if (shaper_update_rate(&g_shaper, msg->hw_rule_id,
                                   qer_gbr, qer_mbr) != 0) {
                /* Flow was not registered yet (policed→shaped) */
                if (shaper_register_flow(&g_shaper, msg->hw_rule_id,
                                         msg->direction,
                                         qer_gbr, qer_mbr) != 0) {
                    DOCA_LOG_ERR("shaper register failed on QER update "
                                 "hw_rule_id=%u — downgrading to policed",
                                 msg->hw_rule_id);
                    dpu_pipeline_downgrade_to_policed(&g_pipeline,
                                                      msg->hw_rule_id);
                }
            }
        } else {
            /* GBR dropped to 0 — shaped→policed transition */
            shaper_unregister_flow(&g_shaper, msg->hw_rule_id);
        }
        break;
    }
    case HW_OP_UPDATE_PDR: {
        doca_error_t result = dpu_pipeline_update_pdr(&g_pipeline, msg);
        if (result != DOCA_SUCCESS)
            DOCA_LOG_ERR("update_pdr failed hw_rule_id=%u: %s",
                         msg->hw_rule_id, doca_error_get_descr(result));
        break;
    }
    default:
        DOCA_LOG_WARN("Unknown op=%u", msg->op);
        break;
    }
}

/* Comch send task completion callbacks (task-based model) */
static void
comch_send_complete_cb(struct doca_comch_task_send *task,
                       union doca_data task_user_data,
                       union doca_data ctx_user_data)
{
    (void)task;
    (void)task_user_data;
    (void)ctx_user_data;
}

static void
comch_send_error_cb(struct doca_comch_task_send *task,
                    union doca_data task_user_data,
                    union doca_data ctx_user_data)
{
    (void)task_user_data;
    (void)ctx_user_data;
    DOCA_LOG_WARN("Comch send task failed");
    doca_task_free(doca_comch_task_send_as_task(task));
}


/* ═══════════════════════════════════════════════════════════════════════
 *  DOCA Comch server init
 * ═══════════════════════════════════════════════════════════════════════ */

/**
 * Compare PCI addresses tolerating short (03:00.0) vs full (0000:03:00.0).
 * If one string is shorter, compare against the tail of the longer one.
 */
static bool
pci_addr_match(const char *a, const char *b)
{
    if (strcmp(a, b) == 0)
        return true;
    size_t la = strlen(a), lb = strlen(b);
    if (la > lb)
        return strcmp(a + (la - lb), b) == 0;
    if (lb > la)
        return strcmp(b + (lb - la), a) == 0;
    return false;
}

/* Open device by PCI address */
static doca_error_t
open_doca_device_by_pci(const char *pci_addr, struct doca_dev **dev)
{
    struct doca_devinfo **dev_list;
    uint32_t nb_devs;
    doca_error_t result;

    result = doca_devinfo_create_list(&dev_list, &nb_devs);
    if (result != DOCA_SUCCESS) return result;

    for (uint32_t i = 0; i < nb_devs; i++) {
        char addr_buf[DOCA_DEVINFO_PCI_ADDR_SIZE] = {};
        result = doca_devinfo_get_pci_addr_str(dev_list[i], addr_buf);
        if (result != DOCA_SUCCESS)
            continue;
        if (pci_addr_match(addr_buf, pci_addr)) {
            result = doca_dev_open(dev_list[i], dev);
            doca_devinfo_destroy_list(dev_list);
            return result;
        }
    }

    doca_devinfo_destroy_list(dev_list);
    return DOCA_ERROR_NOT_FOUND;
}

/* Open representor device by PCI address (server-side, for Comch) */
static doca_error_t
open_doca_device_rep_by_pci(struct doca_dev *dev, const char *rep_pci_addr,
                            struct doca_dev_rep **rep_dev)
{
    struct doca_devinfo_rep **rep_list;
    uint32_t nb_reps;
    doca_error_t result;

    result = doca_devinfo_rep_create_list(dev, DOCA_DEVINFO_REP_FILTER_NET,
                                          &rep_list, &nb_reps);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to list representors: %s",
                     doca_error_get_descr(result));
        return result;
    }

    for (uint32_t i = 0; i < nb_reps; i++) {
        char addr_buf[DOCA_DEVINFO_REP_PCI_ADDR_SIZE] = {};
        result = doca_devinfo_rep_get_pci_addr_str(rep_list[i], addr_buf);
        if (result != DOCA_SUCCESS)
            continue;
        if (pci_addr_match(addr_buf, rep_pci_addr)) {
            result = doca_dev_rep_open(rep_list[i], rep_dev);
            doca_devinfo_rep_destroy_list(rep_list);
            return result;
        }
    }

    doca_devinfo_rep_destroy_list(rep_list);
    DOCA_LOG_ERR("Representor %s not found on device", rep_pci_addr);
    return DOCA_ERROR_NOT_FOUND;
}

static int
comch_server_init(void)
{
    doca_error_t result;

    result = open_doca_device_by_pci(g_cfg.comch_pci, &g_comch_dev);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Cannot open device %s: %s",
                     g_cfg.comch_pci, doca_error_get_descr(result));
        return -1;
    }

    result = doca_pe_create(&g_comch_pe);
    if (result != DOCA_SUCCESS) return -1;

    /* Open the host PF/VF representor — required by DOCA Comch server to
     * identify which host-side PCIe function is allowed to connect.
     * See DOCA Comch docs §"Security Considerations": "Only clients on the
     * PF/VF/SF represented by the doca_dev_rep provided upon server creation
     * can connect to the server." */
    result = open_doca_device_rep_by_pci(g_comch_dev, g_cfg.rep_pci, &g_comch_rep);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Cannot open representor %s: %s",
                     g_cfg.rep_pci, doca_error_get_descr(result));
        return -1;
    }

    result = doca_comch_server_create(g_comch_dev, g_comch_rep, g_cfg.server_name,
                                      &g_comch_server);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Comch server create failed: %s",
                     doca_error_get_descr(result));
        return -1;
    }

    struct doca_ctx *ctx = doca_comch_server_as_ctx(g_comch_server);

    /* Connect PE to server context */
    result = doca_pe_connect_ctx(g_comch_pe, ctx);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to connect PE to server ctx: %s",
                     doca_error_get_descr(result));
        return -1;
    }

    /* Set max message size */
    result = doca_comch_server_set_max_msg_size(g_comch_server,
                                                 sizeof(hw_offload_msg_t) + 64);
    if (result != DOCA_SUCCESS) return -1;

    /* Configure send task callbacks (success + error) */
    result = doca_comch_server_task_send_set_conf(g_comch_server,
                                                   comch_send_complete_cb,
                                                   comch_send_error_cb,
                                                   8);
    if (result != DOCA_SUCCESS) return -1;

    /* Register recv event callback */
    result = doca_comch_server_event_msg_recv_register(g_comch_server,
                                                        comch_recv_cb);
    if (result != DOCA_SUCCESS) return -1;

    /* Register connection + disconnection callbacks (both in one call) */
    result = doca_comch_server_event_connection_status_changed_register(
                g_comch_server,
                comch_server_connection_cb,
                comch_server_disconnect_cb);
    if (result != DOCA_SUCCESS) return -1;

    /* Start the server context */
    result = doca_ctx_start(ctx);
    if (result != DOCA_SUCCESS && result != DOCA_ERROR_IN_PROGRESS) {
        DOCA_LOG_ERR("Comch server start failed: %s",
                     doca_error_get_descr(result));
        return -1;
    }

    DOCA_LOG_INFO("Comch server started: name=%s dev=%s rep=%s",
                  g_cfg.server_name, g_cfg.comch_pci, g_cfg.rep_pci);
    return 0;
}

static void
comch_server_destroy(void)
{
    if (g_comch_server) {
        doca_ctx_stop(doca_comch_server_as_ctx(g_comch_server));
        doca_comch_server_destroy(g_comch_server);
        g_comch_server = NULL;
    }
    if (g_comch_pe) {
        doca_pe_destroy(g_comch_pe);
        g_comch_pe = NULL;
    }
    if (g_comch_rep) {
        doca_dev_rep_close(g_comch_rep);
        g_comch_rep = NULL;
    }
    if (g_comch_dev) {
        doca_dev_close(g_comch_dev);
        g_comch_dev = NULL;
    }
}


/* ═══════════════════════════════════════════════════════════════════════
 *  DPDK EAL init callback + config finalization
 * ═══════════════════════════════════════════════════════════════════════ */

static int
parse_mac(const char *str, uint8_t mac[6])
{
    unsigned int m[6];
    if (sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
               &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++)
        mac[i] = (uint8_t)m[i];
    return 0;
}

/**
 * DPDK EAL init callback — registered via doca_argp_set_dpdk_program().
 * Called by doca_argp_start() after it separates DPDK flags from app flags.
 *
 * IMPORTANT: At this point only EAL is available.  DPDK ethdev ports do
 * NOT exist yet — they are created later by doca_dpdk_port_probe() which
 * establishes the DOCA↔DPDK bridge mapping.  Any port configuration
 * (queues, mbuf pool, etc.) must happen after the probe, not here.
 */
static doca_error_t
dpdk_init_cb(int argc, char **argv)
{
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        DOCA_LOG_ERR("EAL initialization failed");
        return DOCA_ERROR_DRIVER;
    }
    DOCA_LOG_INFO("EAL initialized successfully");
    return DOCA_SUCCESS;
}

/**
 * Setup the switch proxy port for ARM-side buffering and shaping.
 *
 * Must be called AFTER rte_eal_init() (DPDK port 0 exists from -a probe)
 * but BEFORE dpu_pipeline_create_ports(), because doca_flow_port_start()
 * snapshots the queue state — queues added after port_start are invisible
 * to DOCA Flow RSS pipes.
 *
 * Creates mbuf pool, configures Rx/Tx queues on the proxy port, starts it,
 * and registers the dynamic metadata field used by reinject paths.
 */
static doca_error_t
setup_proxy_port(void)
{
    int ret;

    /* Create mbuf pool for ARM buffer Rx/Tx */
    g_mbuf_pool = rte_pktmbuf_pool_create("BUFFER_POOL",
                                           BUFFER_NB_MBUFS,
                                           BUFFER_MBUF_CACHE, 0,
                                           RTE_MBUF_DEFAULT_BUF_SIZE,
                                           rte_socket_id());
    if (!g_mbuf_pool) {
        DOCA_LOG_ERR("Failed to create mbuf pool for buffering");
        return DOCA_ERROR_NO_MEMORY;
    }

    /*
     * Configure Rx/Tx queues on the switch proxy port (DPDK port 0).
     * In switch,hws mode the proxy port is the first DPDK port.
     * Rx queues 0..3 are used by TO_DPU_ARM RSS (buffering).
     * Rx queues 4..7 are used by COLOR_GATE_SHAPED RSS (shaping).
     * Tx queue 0 for buffer reinject, Tx queue 1 for shaper reinject.
     */
    g_proxy_port_id = 0;

    struct rte_eth_conf port_conf;
    memset(&port_conf, 0, sizeof(port_conf));
    port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;

    ret = rte_eth_dev_configure(g_proxy_port_id,
                                 TOTAL_RX_QUEUES, TOTAL_TX_QUEUES,
                                 &port_conf);
    if (ret < 0) {
        DOCA_LOG_ERR("Failed to configure proxy port %u: %d",
                     g_proxy_port_id, ret);
        return DOCA_ERROR_DRIVER;
    }

    /* Setup buffer Rx queues (0 .. BUFFER_RX_QUEUES-1) */
    for (int q = 0; q < BUFFER_RX_QUEUES; q++) {
        ret = rte_eth_rx_queue_setup(g_proxy_port_id, q, 512,
                                      rte_socket_id(), NULL, g_mbuf_pool);
        if (ret < 0) {
            DOCA_LOG_ERR("Failed to setup Rx queue %d on proxy port: %d",
                         q, ret);
            return DOCA_ERROR_DRIVER;
        }
    }

    /* Setup shaper Rx queues (BUFFER_RX_QUEUES .. TOTAL_RX_QUEUES-1) */
    for (int q = BUFFER_RX_QUEUES; q < TOTAL_RX_QUEUES; q++) {
        ret = rte_eth_rx_queue_setup(g_proxy_port_id, q, 512,
                                      rte_socket_id(), NULL, g_mbuf_pool);
        if (ret < 0) {
            DOCA_LOG_ERR("Failed to setup shaper Rx queue %d on proxy: %d",
                         q, ret);
            return DOCA_ERROR_DRIVER;
        }
    }

    /* Tx queue 0: buffer reinject */
    ret = rte_eth_tx_queue_setup(g_proxy_port_id, 0, 512,
                                  rte_socket_id(), NULL);
    if (ret < 0) {
        DOCA_LOG_ERR("Failed to setup Tx queue 0 on proxy port: %d", ret);
        return DOCA_ERROR_DRIVER;
    }

    /* Tx queue 1: shaper reinject */
    ret = rte_eth_tx_queue_setup(g_proxy_port_id, SHAPER_TX_QUEUE_ID, 512,
                                  rte_socket_id(), NULL);
    if (ret < 0) {
        DOCA_LOG_ERR("Failed to setup Tx queue %d on proxy port: %d",
                     SHAPER_TX_QUEUE_ID, ret);
        return DOCA_ERROR_DRIVER;
    }

    ret = rte_eth_dev_start(g_proxy_port_id);
    if (ret < 0) {
        DOCA_LOG_ERR("Failed to start proxy port %u: %d",
                     g_proxy_port_id, ret);
        return DOCA_ERROR_DRIVER;
    }

    /* Register dynamic metadata field for reinject markers.
     * This MUST succeed — dpu_buffer Rx/Tx and drain paths use
     * rte_flow_dynf_metadata_get/set unconditionally. */
    ret = rte_flow_dynf_metadata_register();
    if (ret < 0) {
        DOCA_LOG_ERR("rte_flow_dynf_metadata_register failed (%d) — "
                     "buffer reinject requires dynamic metadata", ret);
        rte_eth_dev_stop(g_proxy_port_id);
        return DOCA_ERROR_DRIVER;
    }

    DOCA_LOG_INFO("Proxy port setup: port=%u, %d Rx queues (%d buffer + %d shaper), "
                  "%d Tx queues, mbuf_pool=%u mbufs",
                  g_proxy_port_id, TOTAL_RX_QUEUES,
                  BUFFER_RX_QUEUES, SHAPER_RX_QUEUES,
                  TOTAL_TX_QUEUES, BUFFER_NB_MBUFS);
    return DOCA_SUCCESS;
}

/**
 * Parse string config values → binary after doca_argp_start() completes.
 * MAC strings → 6-byte arrays, IP string → NBO uint32_t.
 * Also validates required fields as defence-in-depth (doca_argp_param_set_mandatory
 * already ensures they are provided, but an empty string could slip through).
 */
static int
finalize_config(dpu_agent_cfg_t *cfg)
{
    /* MAC strings → binary */
    if (cfg->upf_n3_mac_str[0] != '\0' &&
        parse_mac(cfg->upf_n3_mac_str, cfg->upf_n3_mac) < 0) {
        DOCA_LOG_ERR("Invalid upf-n3-mac: %s", cfg->upf_n3_mac_str);
        return -1;
    }
    if (cfg->gnb_mac_str[0] != '\0' &&
        parse_mac(cfg->gnb_mac_str, cfg->gnb_mac) < 0) {
        DOCA_LOG_ERR("Invalid gnb-mac: %s", cfg->gnb_mac_str);
        return -1;
    }
    if (cfg->upf_n6_mac_str[0] != '\0' &&
        parse_mac(cfg->upf_n6_mac_str, cfg->upf_n6_mac) < 0) {
        DOCA_LOG_ERR("Invalid upf-n6-mac: %s", cfg->upf_n6_mac_str);
        return -1;
    }
    if (cfg->dn_gw_mac_str[0] != '\0' &&
        parse_mac(cfg->dn_gw_mac_str, cfg->dn_gw_mac) < 0) {
        DOCA_LOG_ERR("Invalid dn-gw-mac: %s", cfg->dn_gw_mac_str);
        return -1;
    }

    /* IP string → NBO */
    if (cfg->upf_n3_ip_str[0] != '\0') {
        struct in_addr a;
        if (inet_pton(AF_INET, cfg->upf_n3_ip_str, &a) == 1) {
            cfg->upf_n3_ip = a.s_addr;
        } else {
            DOCA_LOG_ERR("Invalid upf-n3-ip: %s", cfg->upf_n3_ip_str);
            return -1;
        }
    }

    /* Validate required fields (defence-in-depth) */
    if (cfg->rep_pci[0] == '\0') {
        DOCA_LOG_ERR("rep-pci is required (--rep-pci or JSON doca_program_flags)");
        return -1;
    }
    if (cfg->upf_n3_ip == 0) {
        DOCA_LOG_ERR("upf-n3-ip is required (--upf-n3-ip or JSON doca_program_flags)");
        return -1;
    }

    return 0;
}

static const char *
get_json_path_arg(int argc, char *argv[])
{
    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "-j") == 0) ||
            (strcmp(argv[i], "--json") == 0)) {
            if (i + 1 < argc)
                return argv[i + 1];
            return "";
        }
        if (strncmp(argv[i], "-j=", 3) == 0)
            return argv[i] + 3;
        if (strncmp(argv[i], "--json=", 7) == 0)
            return argv[i] + 7;
    }
    return NULL;
}

static int
validate_json_path_arg(int argc, char *argv[])
{
    const char *json_path = get_json_path_arg(argc, argv);
    if (json_path == NULL)
        return 0;

    if (json_path[0] == '\0') {
        fprintf(stderr, "dpu_agent: --json/-j requires a path\n");
        return -1;
    }

    if (access(json_path, R_OK) == 0)
        return 0;

    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)) == NULL)
        snprintf(cwd, sizeof(cwd), "<unknown>");

    fprintf(stderr,
            "dpu_agent: cannot read JSON file '%s' (cwd: %s): %s\n",
            json_path, cwd, strerror(errno));
    return -1;
}


/* ═══════════════════════════════════════════════════════════════════════
 *  main
 * ═══════════════════════════════════════════════════════════════════════ */

int
main(int argc, char *argv[])
{
    doca_error_t result;
    struct doca_log_backend *sdk_log = NULL;

    if (validate_json_path_arg(argc, argv) < 0)
        return EXIT_FAILURE;

    result = doca_log_backend_create_standard();
    if (result != DOCA_SUCCESS) {
        fprintf(stderr, "dpu_agent: failed to init log backend: %s\n",
                doca_error_get_descr(result));
        return EXIT_FAILURE;
    }

    result = doca_log_backend_create_with_file_sdk(stderr, &sdk_log);
    if (result != DOCA_SUCCESS) {
        fprintf(stderr, "dpu_agent: failed to init SDK log backend: %s\n",
                doca_error_get_descr(result));
        return EXIT_FAILURE;
    }

    result = doca_log_backend_set_sdk_level(sdk_log, DOCA_LOG_LEVEL_WARNING);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("failed to set SDK log level: %s",
                     doca_error_get_descr(result));
        return EXIT_FAILURE;
    }

    signal(SIGINT,  signal_handler);
    signal(SIGTERM, signal_handler);

    /* ── doca_argp: init → register → start ────────────────────────── */
    result = doca_argp_init(NULL, &g_cfg);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("doca_argp_init failed: %s", doca_error_get_descr(result));
        return EXIT_FAILURE;
    }

    doca_argp_set_dpdk_program(dpdk_init_cb);

    result = register_dpu_agent_params();
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to register argp params: %s",
                     doca_error_get_descr(result));
        doca_argp_destroy();
        return EXIT_FAILURE;
    }

    result = doca_argp_start(argc, argv);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("doca_argp_start failed: %s",
                     doca_error_get_descr(result));
        DOCA_LOG_ERR("If using -j/--json, ensure the path is relative to current cwd");
        doca_argp_destroy();
        return EXIT_FAILURE;
    }

    /* Parse string config values → binary (MACs, IP) and validate */
    if (finalize_config(&g_cfg) < 0) {
        doca_argp_destroy();
        return EXIT_FAILURE;
    }

    /* ── Open DOCA devices for Flow ports ──────────────────────────── */
    doca_error_t dev_result;
    dev_result = open_doca_device_by_pci(g_cfg.n3_pci, &g_n3_dev);
    if (dev_result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Cannot open N3 device %s: %s",
                     g_cfg.n3_pci, doca_error_get_descr(dev_result));
        doca_argp_destroy();
        return EXIT_FAILURE;
    }
    /* Establish DOCA↔DPDK bridge mapping for N3 PF.
     * Without this, doca_flow_port_start() cannot find the DPDK port's
     * Rx queues — RSS pipe creation will fail with "queue id not exist". */
    dev_result = doca_dpdk_port_probe(g_n3_dev, "dv_flow_en=2");
    if (dev_result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to probe N3 DPDK port: %s",
                     doca_error_get_descr(dev_result));
        doca_argp_destroy();
        return EXIT_FAILURE;
    }

    dev_result = open_doca_device_by_pci(g_cfg.n6_pci, &g_n6_dev);
    if (dev_result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Cannot open N6 device %s: %s",
                     g_cfg.n6_pci, doca_error_get_descr(dev_result));
        doca_argp_destroy();
        return EXIT_FAILURE;
    }
    dev_result = doca_dpdk_port_probe(g_n6_dev, "dv_flow_en=2");
    if (dev_result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to probe N6 DPDK port: %s",
                     doca_error_get_descr(dev_result));
        doca_argp_destroy();
        return EXIT_FAILURE;
    }
    /* VF device: open by PCI if specified, else use N3 device as parent.
     * In switch mode, port 2 (host VF) needs a representor device — it
     * shares the parent PF dev but gets its own queue mapping via the rep. */
    if (g_cfg.vf_pci[0] != '\0') {
        dev_result = open_doca_device_by_pci(g_cfg.vf_pci, &g_vf_dev);
        if (dev_result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Cannot open VF device %s: %s",
                         g_cfg.vf_pci, doca_error_get_descr(dev_result));
            doca_argp_destroy();
            return EXIT_FAILURE;
        }
    } else {
        g_vf_dev = g_n3_dev;  /* parent PF — port 2 uses representor */
    }
    /* Open the host PF/VF representor for Flow port 2.
     * This provides DOCA Flow with a separate queue mapping context
     * even when the parent dev is shared with port 0 (N3). */
    dev_result = open_doca_device_rep_by_pci(g_vf_dev, g_cfg.rep_pci, &g_vf_rep);
    if (dev_result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Cannot open host representor %s for Flow port 2: %s",
                     g_cfg.rep_pci, doca_error_get_descr(dev_result));
        doca_argp_destroy();
        return EXIT_FAILURE;
    }

    /* ── Comch server ──────────────────────────────────────────────── */
    if (comch_server_init() < 0) {
        DOCA_LOG_ERR("Failed to init Comch server");
        doca_argp_destroy();
        return EXIT_FAILURE;
    }

    /* ── DOCA Flow pipeline ────────────────────────────────────────── */
    dpu_port_cfg_t port_cfg = {};
    port_cfg.n3_port_id      = (uint16_t)g_cfg.n3_port_id;
    port_cfg.n6_port_id      = (uint16_t)g_cfg.n6_port_id;
    port_cfg.host_vf_port_id = (uint16_t)g_cfg.host_vf_port_id;
    port_cfg.n3_dev          = g_n3_dev;
    port_cfg.n6_dev          = g_n6_dev;
    port_cfg.host_vf_dev     = g_vf_dev;
    port_cfg.host_vf_rep     = g_vf_rep;
    port_cfg.upf_n3_ip       = g_cfg.upf_n3_ip;
    memcpy(port_cfg.upf_n6_mac, g_cfg.upf_n6_mac, 6);
    memcpy(port_cfg.dn_gw_mac,  g_cfg.dn_gw_mac,  6);
    memcpy(port_cfg.upf_n3_mac, g_cfg.upf_n3_mac, 6);
    memcpy(port_cfg.gnb_mac,    g_cfg.gnb_mac,    6);

    /* RSS queue IDs for TO_DPU_ARM pipe (buffering) */
    uint16_t rss_queues[BUFFER_RX_QUEUES];
    for (int q = 0; q < BUFFER_RX_QUEUES; q++)
        rss_queues[q] = (uint16_t)q;

    /* RSS queue IDs for COLOR_GATE_SHAPED pipe (shaper) */
    uint16_t shaper_rss_queues[SHAPER_RX_QUEUES];
    for (int q = 0; q < SHAPER_RX_QUEUES; q++)
        shaper_rss_queues[q] = (uint16_t)(BUFFER_RX_QUEUES + q);

    /* ── Setup proxy port for ARM buffering/shaping ────────────────── *
     * DPDK port 0 exists after EAL probe (-a flags).  We MUST configure
     * Rx/Tx queues and start the port BEFORE doca_flow_port_start(),
     * because port_start snapshots the queue state.  RSS pipes built
     * later will only see queues that existed at port_start time.      */
    result = setup_proxy_port();
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Proxy port setup failed: %s", doca_error_get_descr(result));
        comch_server_destroy();
        doca_argp_destroy();
        return EXIT_FAILURE;
    }

    result = dpu_pipeline_create_ports(&g_pipeline, &port_cfg,
                                       rss_queues, BUFFER_RX_QUEUES,
                                       shaper_rss_queues, SHAPER_RX_QUEUES);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Pipeline port creation failed: %s",
                     doca_error_get_descr(result));
        comch_server_destroy();
        doca_argp_destroy();
        return EXIT_FAILURE;
    }

    /* ── Build the pipe hierarchy (requires proxy port queues) ──── */
    result = dpu_pipeline_build_pipes(&g_pipeline);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Pipeline pipe build failed: %s",
                     doca_error_get_descr(result));
        dpu_pipeline_destroy(&g_pipeline);
        comch_server_destroy();
        doca_argp_destroy();
        return EXIT_FAILURE;
    }

    /* ── ARM buffer context ────────────────────────────────────────── */
    dpu_buffer_init(&g_buffer, g_proxy_port_id,
                    BUFFER_RX_QUEUES, 0 /* tx_queue */, &g_pipeline);

    /* ── ARM shaper context ────────────────────────────────────────── */
    shaper_init(&g_shaper, g_proxy_port_id,
                BUFFER_RX_QUEUES /* rx_queue_base */,
                SHAPER_RX_QUEUES, SHAPER_TX_QUEUE_ID);

    /* ── Launch buffer Rx lcore ────────────────────────────────────── */
    g_buffer_lcore = rte_get_next_lcore(rte_lcore_id(), 1, 0);
    if (g_buffer_lcore < RTE_MAX_LCORE) {
        rte_eal_remote_launch(dpu_buffer_rx_loop, &g_buffer, g_buffer_lcore);
        DOCA_LOG_INFO("Buffer Rx loop launched on lcore %u", g_buffer_lcore);
    } else {
        DOCA_LOG_WARN("No spare lcore for buffer Rx loop — "
                      "buffering will queue but not drain proactively");
    }

    /* ── Launch shaper Rx lcore ────────────────────────────────────── */
    g_shaper_lcore = rte_get_next_lcore(g_buffer_lcore, 1, 0);
    if (g_shaper_lcore < RTE_MAX_LCORE) {
        rte_eal_remote_launch(shaper_loop, &g_shaper, g_shaper_lcore);
        DOCA_LOG_INFO("Shaper loop launched on lcore %u", g_shaper_lcore);
    } else {
        DOCA_LOG_WARN("No spare lcore for shaper loop — "
                      "GBR YELLOW packets will not be shaped");
    }

    /* ── Main loop: drive Comch event loop ─────────────────────────── */
    DOCA_LOG_INFO("DPU Agent running — waiting for hw_offload_msg from Host");

    while (g_running) {
        doca_pe_progress(g_comch_pe);
        /* Optionally add usleep(100) to reduce CPU burn on ARM cores */
    }

    /* ── Cleanup ───────────────────────────────────────────────────── */
    /* Stop shaper Rx lcore */
    shaper_stop(&g_shaper);
    if (g_shaper_lcore < RTE_MAX_LCORE)
        rte_eal_wait_lcore(g_shaper_lcore);
    shaper_destroy(&g_shaper);

    /* Stop buffer Rx lcore */
    dpu_buffer_stop(&g_buffer);
    if (g_buffer_lcore < RTE_MAX_LCORE)
        rte_eal_wait_lcore(g_buffer_lcore);

    /* Free rte_ring objects and flush residual packets */
    dpu_buffer_destroy(&g_buffer);

    dpu_pipeline_destroy(&g_pipeline);
    comch_server_destroy();

    /* Stop proxy port */
    rte_eth_dev_stop(g_proxy_port_id);

    /* Close port devices (VF may alias N3, only close if distinct) */
    if (g_vf_rep)
        doca_dev_rep_close(g_vf_rep);
    if (g_vf_dev && g_vf_dev != g_n3_dev)
        doca_dev_close(g_vf_dev);
    if (g_n6_dev)
        doca_dev_close(g_n6_dev);
    if (g_n3_dev)
        doca_dev_close(g_n3_dev);

    rte_eal_cleanup();
    doca_argp_destroy();

    DOCA_LOG_INFO("DPU Agent exiting: recv=%lu inserted=%lu failed=%lu",
                  g_msgs_received, g_rules_inserted, g_rules_failed);
    return EXIT_SUCCESS;
}
