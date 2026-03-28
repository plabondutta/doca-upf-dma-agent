# DPU Agent — standalone DOCA application (runs on BF3 ARM cores)
# NOT an ONVM NF — does not link against onvm_nflib.
# Uses DPDK (rte_eal, rte_ethdev, rte_ring, rte_hash, etc.) via the
# DOCA SDK transitive dependency.  Built on the DPU with DOCA installed.
#
# DOCA 3.x dropped the monolithic 'doca' pkg-config name and replaced it with
# per-library packages.  List only the ones this binary actually uses:
#   doca-common      — doca_dev, doca_devinfo, doca_pe, doca_ctx, doca_task
#   doca-flow        — doca_flow_* (eSwitch pipeline, pipe/entry management)
#   doca-comch       — doca_comch_server_* (host<->DPU channel)
#   doca-dpdk-bridge — rte_mbuf <-> doca_buf bridge; DPDK EAL init integration
#   doca-argp        — DOCA Arg Parser

project('dpu_agent', 'c',
    version: '0.1.0',
    default_options: ['c_std=c11', 'warning_level=2'],
)

doca_common_dep      = dependency('doca-common',      required: true)
doca_flow_dep        = dependency('doca-flow',        required: true)
doca_comch_dep       = dependency('doca-comch',       required: true)
doca_dpdk_bridge_dep = dependency('doca-dpdk-bridge', required: true)
doca_argp_dep        = dependency('doca-argp',        required: true)

# hw_offload_msg.h lives in onvm/upf/ — include that path
upf_inc = include_directories('../../onvm/upf')

executable('dpu_agent',
    sources: files(
        'dpu_agent.c',
        'dpu_agent_config.c',
        'dpu_pipeline.c',
        'dpu_buffer.c',
        'dpu_shaper.c',
    ),
    include_directories: [upf_inc],
    dependencies: [
        doca_common_dep,
        doca_flow_dep,
        doca_comch_dep,
        doca_dpdk_bridge_dep,
        doca_argp_dep,
    ],
    install: true,
)