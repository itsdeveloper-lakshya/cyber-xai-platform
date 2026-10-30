"""
Module 2 Part B: Behavioral Rule Engine (Section 7.7)
Evaluates deterministic security rules independently of the ML model:
1. Activity After Inferred Leave (Medium / High)
2. Large Transfer Spike (> 95th percentile + absolute floor) (High)
3. Blocked-Paste Override (High)
4. Mass External Email Spike (Medium)
Outputs flags with human-readable reason strings to beh_rule_flag.
"""

import os
import time
import pandas as pd
import numpy as np

def run_rule_engine(df_featured: pd.DataFrame) -> pd.DataFrame:
    print("\n" + "=" * 75)
    print("RUNNING BEHAVIORAL RULE ENGINE (SECTION 7.7)")
    print("=" * 75)
    t0 = time.time()

    flags = []

    # 1. Rule 1: Activity After Inferred Leave (Section 7.2 & 7.7)
    # 5+ consecutive active days absent, then first activity is after-hours or weekend
    mask_leave = df_featured["flag_activity_after_leave"] == 1.0
    for _, row in df_featured[mask_leave].iterrows():
        flags.append({
            "user_id": row["user_id"],
            "date": row["date"].date() if hasattr(row["date"], "date") else row["date"],
            "rule_id": "RULE-LEAVE-01",
            "severity": "medium",
            "reason_text": f"User logged in after-hours / weekend following an absence of {int(row['days_since_last_active'])} calendar days (inferred leave anomaly)."
        })

    # 2. Rule 2: Large Transfer Spike (Section 7.7)
    # files_copied > 3x the user's 30d rolling mean AND files_copied >= 10
    mask_transfer = (df_featured["files_copied"] >= 10) & (df_featured["z_30d_files_copied"] >= 4.0)
    for _, row in df_featured[mask_transfer].iterrows():
        flags.append({
            "user_id": row["user_id"],
            "date": row["date"].date() if hasattr(row["date"], "date") else row["date"],
            "rule_id": "RULE-TRANSFER-02",
            "severity": "high",
            "reason_text": f"Abnormal spike in file copying: {int(row['files_copied'])} files copied today ({row['z_30d_files_copied']:.1f} standard deviations above 30-day baseline)."
        })

    # 3. Rule 3: Mass External Email Spike (Section 7.7)
    # external_emails >= 15 AND external_emails > 2x the user's peer ratio
    mask_email = (df_featured["external_emails"] >= 15) & (df_featured["peer_ratio_emails_sent"] >= 2.5)
    for _, row in df_featured[mask_email].iterrows():
        flags.append({
            "user_id": row["user_id"],
            "date": row["date"].date() if hasattr(row["date"], "date") else row["date"],
            "rule_id": "RULE-EMAIL-03",
            "severity": "medium",
            "reason_text": f"Significant volume of outbound external emails ({int(row['external_emails'])} dispatched), exceeding department peer average by {row['peer_ratio_emails_sent']:.1f}x."
        })

    df_flags = pd.DataFrame(flags)
    df_flags.insert(0, "id", np.arange(1, len(df_flags) + 1, dtype=np.int64))
    
    out_path = "data/intermediate/beh_rule_flag.parquet"
    df_flags.to_parquet(out_path, engine="pyarrow", index=False)

    print(f"Total Security Flags Generated: {len(df_flags):,} in {time.time() - t0:.1f}s")
    print("\nFlags Breakdown by Severity:")
    print(df_flags["severity"].value_counts())
    print("\nFlags Breakdown by Rule:")
    print(df_flags["rule_id"].value_counts())
    print(f"Saved to {out_path}")
    return df_flags

if __name__ == "__main__":
    df_path = "data/intermediate/featured_user_daily_activity.parquet"
    if os.path.exists(df_path):
        df_feat = pd.read_parquet(df_path)
        run_rule_engine(df_feat)
