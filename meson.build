# DPU Agent — standalone DOCA application (runs on BF3 ARM cores)
# NOT an ONVM NF — does not link against onvm_nflib.
# Uses DPDK (rte_eal, rte_ethdev, rte_ring, rte_hash, etc.) via the
# DOCA SDK transitive dependency.  Built on the DPU with DOCA installed.

project('dpu_agent', 'c',
    version: '0.1.0',
    default_options: ['c_std=c11', 'warning_level=2'],
)

doca_dep = dependency('doca', required: true)
argp_dep = dependency('doca-argp', required: true)  # DOCA Arg Parser (ships with SDK)

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
    dependencies: [doca_dep, argp_dep],
    install: true,
)
