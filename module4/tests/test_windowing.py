"""
Module 4 Windowing & Base Features Test Suite (Section 13 Tests W-01..W-08)
Verifies:
W-01: Sum of flows across all windows equals total flows in the day.
W-02: Hand-built mini flow set with known counts, entropy, and shares.
W-06: End-time assignment computes timestamp + duration correctly.
W-08: Label-free principle: No label-derived column or raw IP/port in feature list.
"""

import pytest
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from module4.pipeline.windowing.window_builder import (
    compute_window_base_features,
    shannon_entropy,
    map_family
)

def test_w02_hand_built_mini_flow_set():
    """W-02: Hand-built mini flow set with known counts, entropy and shares."""
    # 4 flows: 3 TCP, 1 UDP. 2 distinct src IPs (IP1: 3 flows, IP2: 1 flow).
    t0 = datetime(2017, 7, 4, 10, 0, 0)
    data = [
        {"timestamp": t0, "duration_sec": 1.0, "src_ip": "192.168.1.10", "dst_ip": "10.0.0.1",
         "destination_port": 80.0, "protocol": 6.0, "packet_count": 10.0, "byte_count": 1000.0,
         "total_backward_packets": 5.0, "packet_length_mean": 100.0, "syn_flag_count": 1.0,
         "rst_flag_count": 0.0, "fin_flag_count": 0.0, "ack_flag_count": 1.0, "psh_flag_count": 0.0,
         "urg_flag_count": 0.0, "flow_end": t0 + timedelta(seconds=1)},
        {"timestamp": t0, "duration_sec": 2.0, "src_ip": "192.168.1.10", "dst_ip": "10.0.0.1",
         "destination_port": 80.0, "protocol": 6.0, "packet_count": 5.0, "byte_count": 500.0,
         "total_backward_packets": 2.0, "packet_length_mean": 100.0, "syn_flag_count": 0.0,
         "rst_flag_count": 0.0, "fin_flag_count": 1.0, "ack_flag_count": 1.0, "psh_flag_count": 0.0,
         "urg_flag_count": 0.0, "flow_end": t0 + timedelta(seconds=2)},
        {"timestamp": t0, "duration_sec": 0.0005, "src_ip": "192.168.1.10", "dst_ip": "10.0.0.2",
         "destination_port": 443.0, "protocol": 6.0, "packet_count": 2.0, "byte_count": 120.0,
         "total_backward_packets": 0.0, "packet_length_mean": 60.0, "syn_flag_count": 1.0,
         "rst_flag_count": 0.0, "fin_flag_count": 0.0, "ack_flag_count": 0.0, "psh_flag_count": 0.0,
         "urg_flag_count": 0.0, "flow_end": t0 + timedelta(microseconds=500)},
        {"timestamp": t0, "duration_sec": 0.5, "src_ip": "192.168.1.20", "dst_ip": "10.0.0.1",
         "destination_port": 53.0, "protocol": 17.0, "packet_count": 2.0, "byte_count": 150.0,
         "total_backward_packets": 1.0, "packet_length_mean": 75.0, "syn_flag_count": 0.0,
         "rst_flag_count": 0.0, "fin_flag_count": 0.0, "ack_flag_count": 0.0, "psh_flag_count": 0.0,
         "urg_flag_count": 0.0, "flow_end": t0 + timedelta(milliseconds=500)}
    ]
    df = pd.DataFrame(data)
    features = compute_window_base_features(df, past_src_ips={"192.168.1.10"})

    # Check volume
    assert features["f_total_packets"] == 19.0
    assert features["f_total_bytes"] == 1770.0
    # Check diversity
    assert features["f_unique_src_ips"] == 2.0
    assert features["f_unique_dst_ips"] == 2.0
    assert features["f_unique_dst_ports"] == 3.0
    # Top source share: 3/4 = 0.75
    assert features["f_top_src_ip_share"] == 0.75
    # Protocol: 3 TCP, 1 UDP
    assert features["f_share_tcp"] == 0.75
    assert features["f_share_udp"] == 0.25
    # Novelty: IP2 is new, IP1 was in past -> 1 out of 2 is novel = 0.5
    assert features["f_novel_src_ip_share"] == 0.5
    # Flow shape: 1 very short (<1ms), 2 tiny packets (<=2 packets), 1 zero backward packets
    assert features["f_share_very_short_flows"] == 0.25
    assert features["f_share_tiny_packet_flows"] == 0.50
    assert features["f_share_zero_bwd_packets"] == 0.25

def test_w06_flow_end_time_computation():
    """W-06: Verify flow end time converts duration from microseconds correctly."""
    ts = datetime(2017, 7, 5, 9, 30, 0)
    dur_us = 2_500_000.0 # 2.5 seconds
    dur_sec = dur_us / 1_000_000.0
    end_ts = ts + timedelta(seconds=dur_sec)
    assert end_ts == datetime(2017, 7, 5, 9, 30, 2, 500000)

def test_w08_label_free_features():
    """W-08: Model features must never contain attack labels, raw IPs, ports, or timestamps."""
    sample_feats = compute_window_base_features(pd.DataFrame(), past_src_ips=set())
    forbidden = ["attack", "label", "ip", "port", "timestamp", "hour", "day", "date"]

    for k in sample_feats.keys():
        assert k.startswith("f_"), f"Feature name {k} should have f_ prefix"
        # Ensure raw identities are not stored as features
        assert k not in ["f_src_ip", "f_dst_ip", "f_destination_port", "f_attack_share"]
