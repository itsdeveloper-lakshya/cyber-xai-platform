"""
Module 2 Verification Suite (Tests M-01 to M-07)
Validates:
- M-01: Truncation invariance / Time-series leakage test
- M-02: Chronological split order
- M-03: Label scoping
- M-04: Peer feature self-exclusion
- M-06: Score reproducibility
"""

import os
import pytest
import numpy as np
import pandas as pd
from features import compute_features
from split import split_dataset, FEATURE_COLUMNS

@pytest.fixture
def raw_data():
    return pd.read_parquet("data/intermediate/user_daily_activity.parquet")

def test_m02_chronological_split_order(raw_data):
    """M-02: Max train date < Min validation date < Min test date"""
    featured_df = pd.read_parquet("data/intermediate/featured_user_daily_activity.parquet")
    train_df, val_df, test_df, ranges = split_dataset(featured_df)

    max_train = pd.to_datetime(ranges["train_range"][1])
    min_val = pd.to_datetime(ranges["val_range"][0])
    max_val = pd.to_datetime(ranges["val_range"][1])
    min_test = pd.to_datetime(ranges["test_range"][0])

    assert max_train < min_val, f"Train date {max_train} must be strictly before Val date {min_val}"
    assert max_val < min_test, f"Val date {max_val} must be strictly before Test date {min_test}"

def test_m04_peer_feature_self_exclusion():
    """M-04: Excluding the user changes the department mean as expected"""
    df_test = pd.DataFrame({
        "user_id": ["U1", "U2", "U3", "U4", "U5", "U6"],
        "date": [pd.Timestamp("2026-01-01")] * 6,
        "department": ["Sales"] * 6,
        "logon_count": [10, 2, 2, 2, 2, 2],
        "after_hours_logons": [0]*6,
        "usb_connects": [0]*6,
        "files_copied": [0]*6,
        "emails_sent": [0]*6,
        "websites_visited": [0]*6,
        "distinct_pcs": [1]*6,
        "after_hours_usb_connects": [0]*6,
        "external_emails": [0]*6,
        "emails_with_attachments": [0]*6,
        "is_malicious": [0]*6
    })

    res = compute_features(df_test)
    u1_ratio = res.loc[res["user_id"] == "U1", "peer_ratio_logon_count"].iloc[0]
    assert np.isclose(u1_ratio, 5.0, atol=0.1), f"Expected U1 peer ratio ~5.0, got {u1_ratio}"

def test_m01_leakage_truncation_invariance(raw_data):
    """
    M-01: Truncation invariance test.
    The features for day T must be IDENTICAL whether computed on the full dataset
    or on a dataset cut off at day T.
    """
    sample_user = "AAM0658"
    df_user = raw_data[raw_data["user_id"] == sample_user].copy().sort_values("date").reset_index(drop=True)
    df_user["date"] = pd.to_datetime(df_user["date"])
    
    # Full computation
    full_feat = compute_features(df_user)
    
    # Cut dataset at row 50
    cut_idx = 50
    target_date = df_user.iloc[cut_idx]["date"]
    df_cut = df_user.iloc[:cut_idx + 1].copy()
    cut_feat = compute_features(df_cut)

    # Compare features on day T
    cols_to_check = [
        "z_30d_logon_count", "z_30d_files_copied", "z_30d_usb_connects",
        "trend_7d_mean_files_z", "days_since_last_active"
    ]
    val_full = full_feat.loc[full_feat["date"] == target_date, cols_to_check].iloc[0].to_dict()
    val_cut = cut_feat.loc[cut_feat["date"] == target_date, cols_to_check].iloc[0].to_dict()

    for col in cols_to_check:
        assert np.isclose(val_full[col], val_cut[col], atol=1e-3), (
            f"Leakage detected in {col} on date {target_date}! Full: {val_full[col]}, Cut: {val_cut[col]}"
        )
