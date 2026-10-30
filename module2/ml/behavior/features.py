"""
Module 2 Part B: Feature Extraction Pipeline (Section 7.4 & 7.5)
Engineers ~30 temporal, baseline, peer-group, and context features from user_daily_activity.
Strictly enforces leakage rules (1-day shift, self-exclusion from peer averages).
"""

import os
import time
import numpy as np
import pandas as pd

EPSILON = 1e-4

def compute_features(df_input: pd.DataFrame) -> pd.DataFrame:
    t0 = time.time()
    print("=== EXTRACTING MODULE 2 BEHAVIOR FEATURES (SECTION 7.5) ===")
    
    # 1. Sort strictly by user_id and date
    df = df_input.copy()
    df["date"] = pd.to_datetime(df["date"])
    df.sort_values(["user_id", "date"], inplace=True)
    df.reset_index(drop=True, inplace=True)

    # -------------------------------------------------------------
    # Group 1: Today's raw values (6 core metrics + amendments)
    # -------------------------------------------------------------
    raw_metrics = [
        "logon_count", "after_hours_logons", "usb_connects",
        "files_copied", "emails_sent", "websites_visited",
        "distinct_pcs", "after_hours_usb_connects", "external_emails", "emails_with_attachments"
    ]
    core_6_metrics = [
        "logon_count", "after_hours_logons", "usb_connects",
        "files_copied", "emails_sent", "websites_visited"
    ]

    # -------------------------------------------------------------
    # Group 2: Self-baseline z-scores (30-day window, shifted 1 day)
    # Leakage Rule 1: Every rolling stat is shifted by 1 day so today's
    # value never enters today's baseline.
    # -------------------------------------------------------------
    print("1. Computing 30-day self-baseline z-scores (Leakage-free shifted)...")
    grouped_user = df.groupby("user_id")

    for col in core_6_metrics:
        # Shift 1 day, then compute rolling 30-day mean and std (min_periods=10 active days)
        shifted_series = grouped_user[col].shift(1)
        rolling_mean = shifted_series.groupby(df["user_id"]).rolling(window=30, min_periods=10).mean().reset_index(level=0, drop=True)
        rolling_std = shifted_series.groupby(df["user_id"]).rolling(window=30, min_periods=10).std().reset_index(level=0, drop=True)

        z_col = f"z_30d_{col}"
        z_score = (df[col] - rolling_mean) / (rolling_std + EPSILON)
        # Clip to [-10, 10] per Section 7.5
        df[z_col] = z_score.clip(-10.0, 10.0).fillna(0.0).astype(np.float32)

    # -------------------------------------------------------------
    # Group 3: Short-term trends (7-day window vs 30-day window)
    # -------------------------------------------------------------
    print("2. Computing short-term trends...")
    # Shifted 1 day for 7-day windows
    shifted_files = grouped_user["files_copied"].shift(1)
    shifted_usb = grouped_user["usb_connects"].shift(1)

    mean_7d_files = shifted_files.groupby(df["user_id"]).rolling(window=7, min_periods=3).mean().reset_index(level=0, drop=True)
    mean_30d_files = shifted_files.groupby(df["user_id"]).rolling(window=30, min_periods=10).mean().reset_index(level=0, drop=True)
    
    mean_7d_usb = shifted_usb.groupby(df["user_id"]).rolling(window=7, min_periods=3).mean().reset_index(level=0, drop=True)
    mean_30d_usb = shifted_usb.groupby(df["user_id"]).rolling(window=30, min_periods=10).mean().reset_index(level=0, drop=True)

    df["trend_7d_mean_files_z"] = df["z_30d_files_copied"].groupby(df["user_id"]).shift(1).groupby(df["user_id"]).rolling(7, min_periods=3).mean().reset_index(level=0, drop=True).fillna(0.0).astype(np.float32)
    df["trend_7d_mean_usb_z"] = df["z_30d_usb_connects"].groupby(df["user_id"]).shift(1).groupby(df["user_id"]).rolling(7, min_periods=3).mean().reset_index(level=0, drop=True).fillna(0.0).astype(np.float32)
    df["trend_ratio_7d_to_30d_files"] = (mean_7d_files / (mean_30d_files + EPSILON)).clip(0.0, 20.0).fillna(1.0).astype(np.float32)

    # -------------------------------------------------------------
    # Group 4: Peer-group comparisons (Same department, same day)
    # Leakage Rule 2: Peer average uses THAT DAY'S OTHER USERS ONLY (excluding self)
    # Skip peer features when department has fewer than 5 active users that day
    # -------------------------------------------------------------
    print("3. Computing peer-group department normalization (Excluding self)...")
    peer_metrics = ["files_copied", "logon_count", "emails_sent", "usb_connects"]
    dept_day_group = df.groupby(["department", "date"])

    for col in peer_metrics:
        sum_dept = dept_day_group[col].transform("sum")
        count_dept = dept_day_group[col].transform("count")

        # Exclude current user: (Sum - Value) / (Count - 1)
        other_sum = sum_dept - df[col]
        other_count = count_dept - 1

        peer_mean = other_sum / other_count.replace(0, np.nan)
        ratio = df[col] / (peer_mean + EPSILON)

        # Mask if fewer than 5 active department peers that day
        valid_mask = other_count >= 5
        ratio_col = f"peer_ratio_{col}"
        df[ratio_col] = np.where(valid_mask, ratio.clip(0.0, 20.0), 1.0)
        df[ratio_col] = df[ratio_col].fillna(1.0).astype(np.float32)

    # -------------------------------------------------------------
    # Group 5: Frozen baseline (User's first 30 active days)
    # Section 7.2: Frozen baseline computed once from day 1 to 30.
    # -------------------------------------------------------------
    print("4. Computing frozen baselines (First 30 active days)...")
    # Identify cumulative active day rank per user
    df["user_active_day_idx"] = grouped_user.cumcount() + 1

    first_30_mask = df["user_active_day_idx"] <= 30
    df_first_30 = df[first_30_mask]

    frozen_stats = df_first_30.groupby("user_id")[
        ["files_copied", "usb_connects", "after_hours_logons", "emails_sent"]
    ].agg(["mean", "std"])

    for col in ["files_copied", "usb_connects", "after_hours_logons", "emails_sent"]:
        mean_s = df["user_id"].map(frozen_stats[(col, "mean")])
        std_s = df["user_id"].map(frozen_stats[(col, "std")])
        frozen_z = (df[col] - mean_s) / (std_s + EPSILON)
        # Empty (0.0) until user has at least 30 active days per spec
        df[f"frozen_z_{col}"] = np.where(df["user_active_day_idx"] > 30, frozen_z.clip(-10.0, 10.0), 0.0).astype(np.float32)

    # -------------------------------------------------------------
    # Group 6: Absolute and context features (7 features)
    # -------------------------------------------------------------
    print("5. Computing context and temporal features...")
    # Is weekend
    df["is_weekend"] = (df["date"].dt.weekday >= 5).astype(np.float32)

    # After-hours share (after_hours_logons / logon_count, 0 if no logons)
    df["after_hours_share"] = np.where(
        df["logon_count"] > 0,
        df["after_hours_logons"] / df["logon_count"],
        0.0
    ).clip(0.0, 1.0).astype(np.float32)

    # Any USB use today (0 or 1)
    df["any_usb_today"] = (df["usb_connects"] > 0).astype(np.float32)

    # Days since last active day
    shifted_date = grouped_user["date"].shift(1)
    days_since_last = (df["date"] - shifted_date).dt.days
    df["days_since_last_active"] = days_since_last.fillna(1.0).clip(0, 60).astype(np.float32)

    # Day of week (0 to 6)
    df["day_of_week"] = df["date"].dt.weekday.astype(np.float32)

    # Number of active days in the past 30 (activity regularity)
    df["active_days_past_30"] = grouped_user["date"].shift(1).groupby(df["user_id"]).rolling(window=30, min_periods=1).count().reset_index(level=0, drop=True).fillna(0.0).astype(np.float32)

    # Days since first seen
    first_seen_date = grouped_user["date"].transform("min")
    df["days_since_first_seen"] = (df["date"] - first_seen_date).dt.days.astype(np.float32)

    # Inferred leave flag (Section 7.2 & 7.7)
    # User is on leave when gap >= 5 working days. First activity after gap that is off-hours or weekend raises flag.
    df["is_after_hours_any"] = (df["after_hours_logons"] > 0) | (df["after_hours_usb_connects"] > 0) | (df["is_weekend"] == 1.0)
    df["flag_activity_after_leave"] = ((df["days_since_last_active"] >= 7) & df["is_after_hours_any"]).astype(np.float32)

    elapsed = time.time() - t0
    print(f"-> Feature extraction complete in {elapsed:.1f}s! Total shape: {df.shape}")
    return df

if __name__ == "__main__":
    parquet_in = "data/intermediate/user_daily_activity.parquet"
    if os.path.exists(parquet_in):
        raw_df = pd.read_parquet(parquet_in)
        featured_df = compute_features(raw_df)
        out_parquet = "data/intermediate/featured_user_daily_activity.parquet"
        featured_df.to_parquet(out_parquet, engine="pyarrow", index=False)
        print(f"Saved featured dataset to {out_parquet}")
