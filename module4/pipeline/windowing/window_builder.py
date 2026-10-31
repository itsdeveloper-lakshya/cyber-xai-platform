"""
Module 4 Step N2 & N3: Flow-to-Window Assignment and Base Feature Extractor
Processes network_flows_clean day-by-day:
1. Computes Flow End Time: timestamp + (duration_us / 1,000,000.0).
2. Floors end time into fixed time windows (e.g., 60s, 300s, 600s).
3. Computes 28 label-free base traffic features (Section 7.3).
4. Records ground-truth attack share and family counts for evaluation only.
5. Populates PostgreSQL net_window_base table.
"""

import math
from datetime import datetime, timedelta
from typing import Dict, Any, List
import numpy as np
import pandas as pd
from sqlalchemy import create_engine, text

FAMILY_MAP = {
    "benign": "benign",
    "ftp-patator": "brute_force",
    "ssh-patator": "brute_force",
    "dos hulk": "dos",
    "dos goldeneye": "dos",
    "dos slowloris": "dos",
    "dos slowhttptest": "dos",
    "heartbleed": "dos",
    "ddos": "ddos",
    "portscan": "portscan",
    "bot": "bot",
    "web attack - brute force": "web_attack",
    "web attack - xss": "web_attack",
    "web attack - sql injection": "web_attack",
    "infiltration": "infiltration"
}

def map_family(lbl: str) -> str:
    if not lbl:
        return "benign"
    lbl_lower = lbl.lower()
    for k, v in FAMILY_MAP.items():
        if k in lbl_lower:
            return v
    return "other"

def shannon_entropy(series: pd.Series) -> float:
    """Calculates Shannon entropy in bits for categorical distribution."""
    if len(series) == 0:
        return 0.0
    counts = series.value_counts()
    probs = counts / len(series)
    return float(-np.sum(probs * np.log2(probs + 1e-12)))

def compute_window_base_features(df_window: pd.DataFrame, past_src_ips: set) -> Dict[str, Any]:
    """Computes the 28 label-free features for a single time window."""
    n_flows = len(df_window)
    if n_flows == 0:
        return {
            "f_total_packets": 0.0, "f_total_bytes": 0.0,
            "f_mean_flow_duration": 0.0, "f_median_flow_duration": 0.0,
            "f_unique_src_ips": 0.0, "f_unique_dst_ips": 0.0,
            "f_unique_dst_ports": 0.0, "f_unique_src_dst_pairs": 0.0,
            "f_entropy_src_ip": 0.0, "f_entropy_dst_ip": 0.0, "f_entropy_dst_port": 0.0,
            "f_top_src_ip_share": 0.0, "f_top_dst_port_share": 0.0,
            "f_share_tcp": 0.0, "f_share_udp": 0.0, "f_share_other": 0.0,
            "f_syn_count_per_flow": 0.0, "f_rst_count_per_flow": 0.0,
            "f_fin_count_per_flow": 0.0, "f_ack_count_per_flow": 0.0,
            "f_psh_count_per_flow": 0.0, "f_urg_count_per_flow": 0.0,
            "f_share_very_short_flows": 0.0, "f_share_tiny_packet_flows": 0.0,
            "f_share_zero_bwd_packets": 0.0, "f_mean_packet_length": 0.0,
            "f_fwd_bwd_packet_ratio": 1.0, "f_novel_src_ip_share": 0.0,
            "f_per_sec_arrival_std": 0.0
        }

    # Volume
    tot_packets = float(df_window["packet_count"].fillna(0).sum())
    tot_bytes = float(df_window["byte_count"].fillna(0).sum())
    dur_sec = df_window["duration_sec"].clip(lower=0.0)
    mean_dur = float(dur_sec.mean())
    median_dur = float(dur_sec.median())

    # Diversity
    n_src_ip = float(df_window["src_ip"].nunique())
    n_dst_ip = float(df_window["dst_ip"].nunique())
    n_dst_port = float(df_window["destination_port"].nunique())
    src_dst_pairs = df_window["src_ip"].astype(str) + "->" + df_window["dst_ip"].astype(str)
    n_pairs = float(src_dst_pairs.nunique())

    # Entropy & Concentration
    ent_src_ip = shannon_entropy(df_window["src_ip"])
    ent_dst_ip = shannon_entropy(df_window["dst_ip"])
    ent_dst_port = shannon_entropy(df_window["destination_port"])
    top_src_share = float(df_window["src_ip"].value_counts().iloc[0] / n_flows)
    top_dst_port_share = float(df_window["destination_port"].value_counts().iloc[0] / n_flows)

    # Protocol mix
    tcp_count = (df_window["protocol"] == 6.0).sum()
    udp_count = (df_window["protocol"] == 17.0).sum()
    other_proto_count = n_flows - tcp_count - udp_count
    share_tcp = float(tcp_count / n_flows)
    share_udp = float(udp_count / n_flows)
    share_other = float(other_proto_count / n_flows)

    # TCP Flags per flow
    syn_pf = float(df_window["syn_flag_count"].fillna(0).sum() / n_flows)
    rst_pf = float(df_window["rst_flag_count"].fillna(0).sum() / n_flows)
    fin_pf = float(df_window["fin_flag_count"].fillna(0).sum() / n_flows)
    ack_pf = float(df_window["ack_flag_count"].fillna(0).sum() / n_flows)
    psh_pf = float(df_window["psh_flag_count"].fillna(0).sum() / n_flows)
    urg_pf = float(df_window["urg_flag_count"].fillna(0).sum() / n_flows)

    # Flow shape
    short_flows = (dur_sec < 0.001).sum() # < 1 ms
    share_short = float(short_flows / n_flows)
    tiny_pkt = (df_window["packet_count"].fillna(0) <= 2.0).sum()
    share_tiny = float(tiny_pkt / n_flows)
    zero_bwd = (df_window["total_backward_packets"].fillna(0) == 0.0).sum()
    share_zero_bwd = float(zero_bwd / n_flows)

    mean_pkt_len = float(df_window["packet_length_mean"].fillna(0).mean())
    fwd_pkts = float(df_window["packet_count"].fillna(0).sum()) - float(df_window["total_backward_packets"].fillna(0).sum())
    bwd_pkts = float(df_window["total_backward_packets"].fillna(0).sum())
    fwd_bwd_ratio = float(fwd_pkts / max(1.0, bwd_pkts))

    # Novelty (Share of source IPs not seen in prior windows of this segment)
    cur_src_ips = set(df_window["src_ip"].dropna().unique())
    if len(cur_src_ips) > 0 and len(past_src_ips) > 0:
        novel_count = sum(1 for ip in cur_src_ips if ip not in past_src_ips)
        novel_share = float(novel_count / len(cur_src_ips))
    else:
        novel_share = 1.0 if len(past_src_ips) == 0 else 0.0

    # Burstiness (arrival std per second within window)
    sec_counts = df_window["flow_end"].dt.floor("1s").value_counts()
    per_sec_std = float(sec_counts.std()) if len(sec_counts) > 1 else 0.0

    return {
        "f_total_packets": tot_packets,
        "f_total_bytes": tot_bytes,
        "f_mean_flow_duration": mean_dur,
        "f_median_flow_duration": median_dur,
        "f_unique_src_ips": n_src_ip,
        "f_unique_dst_ips": n_dst_ip,
        "f_unique_dst_ports": n_dst_port,
        "f_unique_src_dst_pairs": n_pairs,
        "f_entropy_src_ip": ent_src_ip,
        "f_entropy_dst_ip": ent_dst_ip,
        "f_entropy_dst_port": ent_dst_port,
        "f_top_src_ip_share": top_src_share,
        "f_top_dst_port_share": top_dst_port_share,
        "f_share_tcp": share_tcp,
        "f_share_udp": share_udp,
        "f_share_other": share_other,
        "f_syn_count_per_flow": syn_pf,
        "f_rst_count_per_flow": rst_pf,
        "f_fin_count_per_flow": fin_pf,
        "f_ack_count_per_flow": ack_pf,
        "f_psh_count_per_flow": psh_pf,
        "f_urg_count_per_flow": urg_pf,
        "f_share_very_short_flows": share_short,
        "f_share_tiny_packet_flows": share_tiny,
        "f_share_zero_bwd_packets": share_zero_bwd,
        "f_mean_packet_length": mean_pkt_len,
        "f_fwd_bwd_packet_ratio": fwd_bwd_ratio,
        "f_novel_src_ip_share": novel_share,
        "f_per_sec_arrival_std": per_sec_std
    }

def process_day_windows(day_name: str, window_size_sec: int, engine) -> pd.DataFrame:
    """Loads one day of flows, calculates flow_end, aggregates into fixed windows."""
    print(f"  [-] Loading flows for {day_name}...")
    cols = [
        "timestamp", "duration", "src_ip", "dst_ip", "destination_port",
        "protocol", "packet_count", "byte_count", "total_backward_packets",
        "packet_length_mean", "syn_flag_count", "rst_flag_count",
        "fin_flag_count", "ack_flag_count", "psh_flag_count", "urg_flag_count",
        "attack_label"
    ]
    query = f"""
    SELECT {', '.join(cols)}
    FROM network_flows_clean
    WHERE source_day = '{day_name}'
    ORDER BY timestamp ASC;
    """
    df = pd.read_sql(query, engine)
    if len(df) == 0:
        return pd.DataFrame()

    # Flow end time computation (Section 7.2 N2)
    # duration is in microseconds; clip negative anomalies to 0
    df["duration_sec"] = df["duration"].clip(lower=0.0) / 1_000_000.0
    df["flow_end"] = df["timestamp"] + pd.to_timedelta(df["duration_sec"], unit="s")
    df["family"] = df["attack_label"].apply(map_family)

    # Window flooring
    freq_str = f"{window_size_sec}s"
    min_end = df["flow_end"].min().floor(freq_str)
    max_end = df["flow_end"].max().ceil(freq_str)

    window_starts = pd.date_range(min_end, max_end, freq=freq_str, inclusive="left")
    
    rows = []
    past_src_ips = set()
    total_assigned_flows = 0

    # Index by flow_end for efficient slicing
    df_sorted = df.sort_values("flow_end").reset_index(drop=True)
    end_times = df_sorted["flow_end"].values

    for w_start in window_starts:
        w_end = w_start + timedelta(seconds=window_size_sec)
        
        # Binary search slice for speed
        idx_start = np.searchsorted(end_times, np.datetime64(w_start), side="left")
        idx_end = np.searchsorted(end_times, np.datetime64(w_end), side="left")
        
        df_win = df_sorted.iloc[idx_start:idx_end]
        n_flows = len(df_win)
        total_assigned_flows += n_flows

        if n_flows > 0:
            attack_flows = (df_win["family"] != "benign").sum()
            attack_share = float(attack_flows / n_flows)
            family_counts = df_win[df_win["family"] != "benign"]["family"].value_counts().to_dict()
            features = compute_window_base_features(df_win, past_src_ips)
            past_src_ips.update(df_win["src_ip"].dropna().unique())
        else:
            attack_flows = 0
            attack_share = 0.0
            family_counts = {}
            features = compute_window_base_features(df_win, past_src_ips)

        row_dict = {
            "window_size_sec": window_size_sec,
            "window_start": w_start,
            "window_end": w_end,
            "source_day": day_name,
            "segment_id": 1,
            "flow_count": n_flows,
            "attack_flow_count": int(attack_flows),
            "attack_share": float(attack_share),
            "family_counts": family_counts,
            **features
        }
        rows.append(row_dict)

    # Verification: W-01 No flows lost
    assert total_assigned_flows == len(df), f"W-01 FAILED: Assigned {total_assigned_flows} != Loaded {len(df)}"
    print(f"  [PASS] W-01: All {len(df):,} flows assigned into {len(rows)} windows without loss.")
    return pd.DataFrame(rows)

def build_all_windows(window_size_sec: int, db_url: str):
    """Generates and writes windows for all days into net_window_base."""
    import json
    from psycopg2.extras import execute_values
    import psycopg2

    engine = create_engine(db_url)
    print(f"\n[+] Building windows for window_size = {window_size_sec}s...")

    days_query = "SELECT DISTINCT source_day FROM network_flows_clean ORDER BY source_day;"
    days = [r[0] for r in engine.connect().execute(text(days_query)).fetchall()]

    all_window_dfs = []
    for d in days:
        df_win = process_day_windows(d, window_size_sec, engine)
        if len(df_win) > 0:
            all_window_dfs.append(df_win)

    df_all = pd.concat(all_window_dfs, ignore_index=True)
    # Deduplicate any boundary windows between split sub-captures
    df_all = df_all.drop_duplicates(subset=["window_size_sec", "window_start"], keep="last")
    print(f"\n[+] Total windows computed: {len(df_all):,}. Writing to net_window_base...")

    # Write to database using efficient upsert
    conn = psycopg2.connect(db_url)
    cur = conn.cursor()

    insert_sql = """
    INSERT INTO net_window_base (
        window_size_sec, window_start, window_end, source_day, segment_id,
        flow_count, attack_flow_count, attack_share, family_counts,
        f_total_packets, f_total_bytes, f_mean_flow_duration, f_median_flow_duration,
        f_unique_src_ips, f_unique_dst_ips, f_unique_dst_ports, f_unique_src_dst_pairs,
        f_entropy_src_ip, f_entropy_dst_ip, f_entropy_dst_port,
        f_top_src_ip_share, f_top_dst_port_share,
        f_share_tcp, f_share_udp, f_share_other,
        f_syn_count_per_flow, f_rst_count_per_flow, f_fin_count_per_flow,
        f_ack_count_per_flow, f_psh_count_per_flow, f_urg_count_per_flow,
        f_share_very_short_flows, f_share_tiny_packet_flows, f_share_zero_bwd_packets,
        f_mean_packet_length, f_fwd_bwd_packet_ratio, f_novel_src_ip_share, f_per_sec_arrival_std
    ) VALUES %s
    ON CONFLICT (window_size_sec, window_start) DO UPDATE SET
        flow_count = EXCLUDED.flow_count,
        attack_flow_count = EXCLUDED.attack_flow_count,
        attack_share = EXCLUDED.attack_share,
        family_counts = EXCLUDED.family_counts,
        f_total_packets = EXCLUDED.f_total_packets,
        f_total_bytes = EXCLUDED.f_total_bytes,
        f_mean_flow_duration = EXCLUDED.f_mean_flow_duration,
        f_median_flow_duration = EXCLUDED.f_median_flow_duration,
        f_unique_src_ips = EXCLUDED.f_unique_src_ips,
        f_unique_dst_ips = EXCLUDED.f_unique_dst_ips,
        f_unique_dst_ports = EXCLUDED.f_unique_dst_ports,
        f_unique_src_dst_pairs = EXCLUDED.f_unique_src_dst_pairs,
        f_entropy_src_ip = EXCLUDED.f_entropy_src_ip,
        f_entropy_dst_ip = EXCLUDED.f_entropy_dst_ip,
        f_entropy_dst_port = EXCLUDED.f_entropy_dst_port,
        f_top_src_ip_share = EXCLUDED.f_top_src_ip_share,
        f_top_dst_port_share = EXCLUDED.f_top_dst_port_share,
        f_share_tcp = EXCLUDED.f_share_tcp,
        f_share_udp = EXCLUDED.f_share_udp,
        f_share_other = EXCLUDED.f_share_other,
        f_syn_count_per_flow = EXCLUDED.f_syn_count_per_flow,
        f_rst_count_per_flow = EXCLUDED.f_rst_count_per_flow,
        f_fin_count_per_flow = EXCLUDED.f_fin_count_per_flow,
        f_ack_count_per_flow = EXCLUDED.f_ack_count_per_flow,
        f_psh_count_per_flow = EXCLUDED.f_psh_count_per_flow,
        f_urg_count_per_flow = EXCLUDED.f_urg_count_per_flow,
        f_share_very_short_flows = EXCLUDED.f_share_very_short_flows,
        f_share_tiny_packet_flows = EXCLUDED.f_share_tiny_packet_flows,
        f_share_zero_bwd_packets = EXCLUDED.f_share_zero_bwd_packets,
        f_mean_packet_length = EXCLUDED.f_mean_packet_length,
        f_fwd_bwd_packet_ratio = EXCLUDED.f_fwd_bwd_packet_ratio,
        f_novel_src_ip_share = EXCLUDED.f_novel_src_ip_share,
        f_per_sec_arrival_std = EXCLUDED.f_per_sec_arrival_std;
    """

    data_tuples = []
    for _, r in df_all.iterrows():
        tup = (
            int(r["window_size_sec"]), r["window_start"].to_pydatetime(), r["window_end"].to_pydatetime(),
            str(r["source_day"]), int(r["segment_id"]), int(r["flow_count"]),
            int(r["attack_flow_count"]), float(r["attack_share"]), json.dumps(r["family_counts"]),
            float(r["f_total_packets"]), float(r["f_total_bytes"]),
            float(r["f_mean_flow_duration"]), float(r["f_median_flow_duration"]),
            float(r["f_unique_src_ips"]), float(r["f_unique_dst_ips"]),
            float(r["f_unique_dst_ports"]), float(r["f_unique_src_dst_pairs"]),
            float(r["f_entropy_src_ip"]), float(r["f_entropy_dst_ip"]), float(r["f_entropy_dst_port"]),
            float(r["f_top_src_ip_share"]), float(r["f_top_dst_port_share"]),
            float(r["f_share_tcp"]), float(r["f_share_udp"]), float(r["f_share_other"]),
            float(r["f_syn_count_per_flow"]), float(r["f_rst_count_per_flow"]), float(r["f_fin_count_per_flow"]),
            float(r["f_ack_count_per_flow"]), float(r["f_psh_count_per_flow"]), float(r["f_urg_count_per_flow"]),
            float(r["f_share_very_short_flows"]), float(r["f_share_tiny_packet_flows"]), float(r["f_share_zero_bwd_packets"]),
            float(r["f_mean_packet_length"]), float(r["f_fwd_bwd_packet_ratio"]),
            float(r["f_novel_src_ip_share"]), float(r["f_per_sec_arrival_std"])
        )
        data_tuples.append(tup)

    execute_values(cur, insert_sql, data_tuples, page_size=1000)
    conn.commit()
    cur.close()
    conn.close()
    engine.dispose()
    print(f"[PASS] Successfully stored {len(df_all):,} windows into PostgreSQL net_window_base.")

if __name__ == "__main__":
    import yaml
    from pathlib import Path
    config_p = Path(__file__).resolve().parent.parent.parent / "config.yaml"
    with open(config_p, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    db = cfg["database"]["connection_url"]
    # Build default 300s (5-minute) windows
    build_all_windows(300, db)
