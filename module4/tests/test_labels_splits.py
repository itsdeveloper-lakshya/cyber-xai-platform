"""
Module 4 Labels & Splits Test Suite (Section 13 Tests L-01..L-03, S-01..S-02)
Verifies:
L-01: Surge flag is computed strictly from attack_share >= 0.20 and flow_count >= 30.
L-02: Horizon target y(t, k) looks ahead k windows without lookbehind leakage.
L-03: Onset flag fires ONLY on calm windows preceding a surge, excluding ongoing surges.
S-01: Chronological splits are strictly disjoint (train ∩ val ∩ test = ∅).
S-02: Last k windows before split boundaries are purged.
"""

import pytest
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from module4.pipeline.labels.surge_labeler import compute_surge_labels
from module4.pipeline.splits.split_manager import split_chronological_day

def test_l01_surge_flags_hand_calculation():
    """L-01: Surge flag matches hand calculation."""
    t0 = datetime(2017, 7, 4, 10, 0, 0)
    data = [
        {"window_start": t0, "attack_share": 0.25, "flow_count": 50}, # Surge (share >= 0.2, count >= 30)
        {"window_start": t0 + timedelta(minutes=5), "attack_share": 0.15, "flow_count": 100}, # Not surge (share < 0.2)
        {"window_start": t0 + timedelta(minutes=10), "attack_share": 0.80, "flow_count": 10}, # Not surge (count < 30)
        {"window_start": t0 + timedelta(minutes=15), "attack_share": 0.50, "flow_count": 35}, # Surge
    ]
    df = pd.DataFrame(data)
    labeled = compute_surge_labels(df, share_threshold=0.20, flow_floor=30, horizons_k=[1])

    assert labeled["is_surge"].tolist() == [True, False, False, True]

def test_l02_horizon_target_synthetic_series():
    """L-02: Target y(t, k) looks ahead k windows correctly."""
    t0 = datetime(2017, 7, 4, 10, 0, 0)
    # 6 windows. Window 3 is surge.
    data = []
    for i in range(6):
        data.append({
            "window_start": t0 + timedelta(minutes=5 * i),
            "attack_share": 0.50 if i == 3 else 0.0,
            "flow_count": 100
        })
    df = pd.DataFrame(data)
    labeled = compute_surge_labels(df, share_threshold=0.20, flow_floor=30, horizons_k=[1, 2])

    # For k=1: y should be 1 at window 2 (since window 3 is surge).
    # Window 5 is last window, horizon passes segment end -> sentinel -1.
    assert labeled["y_k1"].iloc[2] == 1
    assert labeled["y_k1"].iloc[3] == 0 # Ongoing surge itself, next is window 4 (not surge)
    assert labeled["y_k1"].iloc[5] == -1 # Dropped / purged

    # For k=2: y should be 1 at window 1 and window 2
    assert labeled["y_k2"].iloc[1] == 1
    assert labeled["y_k2"].iloc[2] == 1
    assert labeled["y_k2"].iloc[4] == -1 # Last 2 windows dropped for k=2
    assert labeled["y_k2"].iloc[5] == -1

def test_l03_onset_flag_excludes_ongoing():
    """L-03: Onset flag requires window t to be calm; ongoing surges cannot be onsets."""
    t0 = datetime(2017, 7, 4, 10, 0, 0)
    # Window 0: calm
    # Window 1: calm -> looks ahead to window 2 (surge) => ONSET!
    # Window 2: surge (ongoing) => NOT ONSET
    # Window 3: surge (ongoing) => NOT ONSET
    # Window 4: not surge, but not calm yet (cooldown) => NOT ONSET
    data = [
        {"window_start": t0, "attack_share": 0.0, "flow_count": 50},
        {"window_start": t0 + timedelta(minutes=5), "attack_share": 0.0, "flow_count": 50},
        {"window_start": t0 + timedelta(minutes=10), "attack_share": 0.5, "flow_count": 50},
        {"window_start": t0 + timedelta(minutes=15), "attack_share": 0.5, "flow_count": 50},
        {"window_start": t0 + timedelta(minutes=20), "attack_share": 0.0, "flow_count": 50},
        {"window_start": t0 + timedelta(minutes=25), "attack_share": 0.0, "flow_count": 50},
        {"window_start": t0 + timedelta(minutes=30), "attack_share": 0.0, "flow_count": 50},
    ]
    df = pd.DataFrame(data)
    labeled = compute_surge_labels(df, calm_history_h=2, horizons_k=[1])

    # Window 1 is the ONLY onset event
    assert labeled["is_onset_k1"].tolist() == [False, True, False, False, False, False, False]
    assert labeled["is_ongoing"].tolist() == [False, False, True, True, False, False, False]

def test_s01_and_s02_chronological_splits_and_purging():
    """S-01 & S-02: Splits are chronological, disjoint, and last k windows are purged."""
    t0 = datetime(2017, 7, 4, 10, 0, 0)
    data = [{"window_start": t0 + timedelta(minutes=5 * i), "val": i} for i in range(100)]
    df = pd.DataFrame(data)

    splits = split_chronological_day(df, horizon_k=2, train_pct=0.60, val_pct=0.20)
    train, val, test = splits["train"], splits["val"], splits["test"]

    # S-01: Disjoint
    s_train = set(train["val"])
    s_val = set(val["val"])
    s_test = set(test["val"])
    assert len(s_train.intersection(s_val)) == 0
    assert len(s_val.intersection(s_test)) == 0
    assert len(s_train.intersection(s_test)) == 0

    # S-02: Purged k=2 windows before boundaries
    # train end is at 60 -> purged 2 means train has 58 windows (0..57)
    assert len(train) == 58
    assert train["val"].max() == 57
    # val starts at 60 -> purged 2 before 80 means val has 18 windows (60..77)
    assert len(val) == 18
    assert val["val"].min() == 60
    assert val["val"].max() == 77
    # test starts at 80
    assert test["val"].min() == 80
