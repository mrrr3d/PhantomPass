#!/bin/bash
# meant to be run from coord dir ..
source "config/examples/example-common.sh"
tcp_connections_per_thread_pair='1'

# ===================== General Settingss =====================
max_threads='24'

# ===================== Common Parameters =====================
# topology_file_l='4-hosts.yaml'
topology_file_l='9leaf-4spine.yaml'
trace_last_ratio='1.0' # the % of the total simulation duration that will be traced / monitored
trace_cc='1'

state_polling_ival_s='0.000008' # sample switch queue lengths every 1us

# req_interval_distr='manual'
# req_target_distr='manual' # manual or uniform
# req_size_distr='manual'
manual_req_interval_file_l='9leaf-4spine-manual-dctcp.csv'

client_injection_rate_gbps_list="15" #host<->tor 0.6load
duration_modifier_l="0.072" # 0.072<->0.12s 0.054<->0.09s
mean_req_size_B_l='4427.35'
req_size_distr='w3'

# ===================== R2P2 Parameters =====================
# BDP = 162500B
# B = 1.5BDP = 243750B
r2p2_budgets_intra_max_bytes_l='243750'
r2p2_elet_srpb_l='162500'
# UnschT = 1BDP = 162500B, or 1MTU = 1500B
r2p2_unsolicited_thresh_bytes_l="1500"
# r2p2_unsolicited_thresh_bytes_l="162500"

r2p2_hybrid_sender_policy_l="1"
r2p2_sender_policy_ratio_l='0.5'
# SThresh = 5BDP = 812500B = 542pkt
r2p2_sender_ecn_threshold_l="542"
# NThresh = 1.5BDP = 243750B = 162pkts
r2p2_ecn_threshold_min_l='162' # packets
r2p2_ecn_threshold_max_l='162' # packets


# PThresh = 1.0BDP = 162500B
ppass_pthresh_l='162500'
ppass_rho_l='0.2'

# 2pkt
ppass_egress_queue_thresh_bytes_l='3076'
# ===================== DCTCP Parameters =====================
# dctcp_K_l="7" # DCTCP's ECN marking threshold in packets
dctcp_init_cwnd_l='108' # in packet

# ===================== HOMA Parametrs =====================
homa_workload_type=5

# ===================== Protocols =====================
transp_prots='micro-hybrid'
simulation_name_l='ppass-dctcp-w3'
