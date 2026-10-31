"""
Module 4 Step N5: Feature Dictionary Seeder
Populates net_feature_dictionary with human-readable metadata, groupings,
and natural language direction hints for downstream Module 5 (SHAP) and Module 6 (XAI).
"""

import psycopg2
import yaml
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
CONFIG_PATH = REPO_ROOT / "module4" / "config.yaml"

with open(CONFIG_PATH, "r", encoding="utf-8") as f:
    config = yaml.safe_load(f)

DB_URL = config["database"]["connection_url"]

DICTIONARY_ENTRIES = [
    # Volume
    ("f_total_packets", "Total Packets", "volume", "Total number of network packets observed in window", "higher means traffic volume increase"),
    ("f_total_bytes", "Total Bytes", "volume", "Total bytes transferred across all flows in window", "higher means high bandwidth surge"),
    ("f_mean_flow_duration", "Mean Flow Duration", "volume", "Average duration of completed flows in seconds", "lower indicates rapid flood or scan connections"),
    ("f_median_flow_duration", "Median Flow Duration", "volume", "Median duration of completed flows in seconds", "lower indicates typical short-lived attack flows"),

    # Diversity
    ("f_unique_src_ips", "Unique Source IPs", "diversity", "Number of distinct originating IP addresses", "higher indicates distributed source activity or DDoS"),
    ("f_unique_dst_ips", "Unique Destination IPs", "diversity", "Number of distinct target IP addresses", "higher indicates horizontal scanning or sweeping"),
    ("f_unique_dst_ports", "Unique Target Ports", "diversity", "Number of distinct destination ports probed", "higher strongly indicates port scanning activity"),
    ("f_unique_src_dst_pairs", "Unique Source-Dest Pairs", "diversity", "Count of distinct communicating IP pairs", "higher indicates broad network engagement"),

    # Concentration & Entropy
    ("f_entropy_src_ip", "Source IP Entropy", "concentration", "Shannon entropy of source IP distribution", "lower indicates concentrated traffic from a single attacker"),
    ("f_entropy_dst_ip", "Destination IP Entropy", "concentration", "Shannon entropy of destination IP distribution", "lower indicates concentrated targeting of one victim server"),
    ("f_entropy_dst_port", "Target Port Entropy", "concentration", "Shannon entropy of destination port distribution", "lower indicates single-service attack like HTTP flood"),
    ("f_top_src_ip_share", "Top Source IP Share", "concentration", "Proportion of total window flows originating from single most active IP", "higher means single IP dominates the traffic"),
    ("f_top_dst_port_share", "Top Target Port Share", "concentration", "Proportion of total window flows directed to most targeted port", "higher indicates targeted service flood"),

    # Protocol Mix
    ("f_share_tcp", "TCP Flow Share", "protocol", "Fraction of flows utilizing TCP protocol", "high TCP ratio common in SYN floods and web attacks"),
    ("f_share_udp", "UDP Flow Share", "protocol", "Fraction of flows utilizing UDP protocol", "high UDP ratio common in reflection or amplification attacks"),
    ("f_share_other", "Non-TCP/UDP Share", "protocol", "Fraction of flows using ICMP or other protocols", "higher indicates potential tunneling or ping floods"),

    # Flags
    ("f_syn_count_per_flow", "SYN Flags Per Flow", "flags", "Average SYN flags per flow", "higher indicates TCP SYN flood or stealth half-open scan"),
    ("f_rst_count_per_flow", "RST Flags Per Flow", "flags", "Average RST abort flags per flow", "higher indicates connections rejected or aborted"),
    ("f_fin_count_per_flow", "FIN Flags Per Flow", "flags", "Average FIN close flags per flow", "indicates teardown behavior"),
    ("f_ack_count_per_flow", "ACK Flags Per Flow", "flags", "Average ACK flags per flow", "indicates normal or ACK flood traffic"),
    ("f_psh_count_per_flow", "PSH Flags Per Flow", "flags", "Average PSH push flags per flow", "higher indicates rapid payload delivery"),
    ("f_urg_count_per_flow", "URG Flags Per Flow", "flags", "Average URG urgent flags per flow", "abnormal flag usage"),

    # Flow Shape
    ("f_share_very_short_flows", "Very Short Flows Share", "shape", "Fraction of flows lasting under 1 millisecond", "higher indicates rapid connection attempts or scans"),
    ("f_share_tiny_packet_flows", "Tiny Packet Flows Share", "shape", "Fraction of flows with 2 or fewer packets", "higher indicates handshake-only or probe traffic"),
    ("f_share_zero_bwd_packets", "Zero Backward Packets Share", "shape", "Fraction of flows receiving zero response packets", "higher indicates unanswered probes or dropped traffic"),
    ("f_mean_packet_length", "Mean Packet Length", "shape", "Average packet payload size in bytes", "very small suggests probes, very large suggests exfil or buffer overflow"),
    ("f_fwd_bwd_packet_ratio", "Forward/Backward Packet Ratio", "shape", "Ratio of outgoing forward packets to incoming backward packets", "higher indicates one-way flooding without receiving replies"),

    # Novelty & Burstiness
    ("f_novel_src_ip_share", "Novel Source IP Share", "novelty", "Proportion of source IPs never previously seen in this capture segment", "higher indicates influx of new unknown hosts"),
    ("f_per_sec_arrival_std", "Arrival Rate Standard Deviation", "burstiness", "Second-by-second variance in flow arrivals within window", "higher indicates sharp bursty arrival spikes")
]

def seed_feature_dictionary():
    print("=" * 70)
    print(" >>> SEEDING net_feature_dictionary IN POSTGRESQL")
    print("=" * 70)
    conn = psycopg2.connect(DB_URL)
    cur = conn.cursor()

    q = """
    INSERT INTO net_feature_dictionary (feature_name, display_name, feature_group, description, direction_hint)
    VALUES (%s, %s, %s, %s, %s)
    ON CONFLICT (feature_name) DO UPDATE SET
        display_name = EXCLUDED.display_name,
        feature_group = EXCLUDED.feature_group,
        description = EXCLUDED.description,
        direction_hint = EXCLUDED.direction_hint;
    """
    for entry in DICTIONARY_ENTRIES:
        cur.execute(q, entry)

    conn.commit()
    print(f"[PASS] Successfully seeded {len(DICTIONARY_ENTRIES)} base features into net_feature_dictionary.")
    cur.close()
    conn.close()

if __name__ == "__main__":
    seed_feature_dictionary()
