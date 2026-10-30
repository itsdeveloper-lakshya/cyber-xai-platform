"""
Module 2 Part B: Chronological Split (Section 7.3)
Splits user activity chronologically (First 70% Train, Next 15% Val, Last 15% Test).
Enforces Leakage Rule: Rows in a user's first 30 active days are excluded from evaluation.
Excludes User ID and Department from direct features to prevent overfitting.
"""

import numpy as np
import pandas as pd

FEATURE_COLUMNS = [
    # Group 1: Today's raw values
    "logon_count", "after_hours_logons", "usb_connects",
    "files_copied", "emails_sent", "websites_visited",
    "distinct_pcs", "after_hours_usb_connects", "external_emails", "emails_with_attachments",
    # Group 2: Self-baseline z-scores
    "z_30d_logon_count", "z_30d_after_hours_logons", "z_30d_usb_connects",
    "z_30d_files_copied", "z_30d_emails_sent", "z_30d_websites_visited",
    # Group 3: Short-term trends
    "trend_7d_mean_files_z", "trend_7d_mean_usb_z", "trend_ratio_7d_to_30d_files",
    # Group 4: Peer group ratios
    "peer_ratio_files_copied", "peer_ratio_logon_count", "peer_ratio_emails_sent", "peer_ratio_usb_connects",
    # Group 5: Frozen baseline z-scores
    "frozen_z_files_copied", "frozen_z_usb_connects", "frozen_z_after_hours_logons", "frozen_z_emails_sent",
    # Group 6: Context features
    "is_weekend", "after_hours_share", "any_usb_today", "days_since_last_active",
    "day_of_week", "active_days_past_30", "days_since_first_seen", "flag_activity_after_leave"
]

def split_dataset(df: pd.DataFrame):
    print("=== CHRONOLOGICAL DATASET SPLIT (SECTION 7.3) ===")
    
    # 1. Order all unique calendar dates
    unique_dates = np.sort(df["date"].unique())
    n_dates = len(unique_dates)

    train_end_idx = int(0.70 * n_dates)
    val_end_idx = int(0.85 * n_dates)

    train_dates = set(unique_dates[:train_end_idx])
    val_dates = set(unique_dates[train_end_idx:val_end_idx])
    test_dates = set(unique_dates[val_end_idx:])

    min_train, max_train = unique_dates[0], unique_dates[train_end_idx - 1]
    min_val, max_val = unique_dates[train_end_idx], unique_dates[val_end_idx - 1]
    min_test, max_test = unique_dates[val_end_idx], unique_dates[-1]

    print(f"1. Date Ranges:")
    print(f"   - Train (70%): {str(min_train)[:10]} to {str(max_train)[:10]} ({len(train_dates)} days)")
    print(f"   - Val   (15%): {str(min_val)[:10]} to {str(max_val)[:10]} ({len(val_dates)} days)")
    print(f"   - Test  (15%): {str(min_test)[:10]} to {str(max_test)[:10]} ({len(test_dates)} days)")

    # 2. Section 7.2: Rows inside each user's first 30 active days are excluded from evaluation
    eval_mask = df["user_active_day_idx"] > 30

    train_df = df[df["date"].isin(train_dates) & eval_mask].copy()
    val_df = df[df["date"].isin(val_dates) & eval_mask].copy()
    test_df = df[df["date"].isin(test_dates) & eval_mask].copy()

    print(f"\n2. Row and Positive Label Distribution (Excluding First 30 Days Baseline Period):")
    print(f"   - Train rows: {len(train_df):,} | Malicious: {train_df['is_malicious'].sum():,} ({100*train_df['is_malicious'].mean():.3f}%)")
    print(f"   - Val rows  : {len(val_df):,} | Malicious: {val_df['is_malicious'].sum():,} ({100*val_df['is_malicious'].mean():.3f}%)")
    print(f"   - Test rows : {len(test_df):,} | Malicious: {test_df['is_malicious'].sum():,} ({100*test_df['is_malicious'].mean():.3f}%)")

    return train_df, val_df, test_df, {
        "train_range": [str(min_train)[:10], str(max_train)[:10]],
        "val_range": [str(min_val)[:10], str(max_val)[:10]],
        "test_range": [str(min_test)[:10], str(max_test)[:10]],
    }
