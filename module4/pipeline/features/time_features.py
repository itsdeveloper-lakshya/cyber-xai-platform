"""
Module 4 Step N4: Engineered Time Features
Computes temporal dynamics strictly within continuous segments (per-day capture):
1. Lags: values at t-1, t-2, t-3
2. Change: difference and ratio vs t-1
3. Rolling Statistics: mean and std over previous L windows (excluding window t)
4. Z-scores: (current - rolling_mean) / (rolling_std + 1e-6)
5. Slope: linear regression slope over last 5 windows

Guarantees:
- Segment isolation: Lags and baselines NEVER cross overnight gaps (first L windows are warm-up).
- Zero lookahead: Rolling windows are strictly shifted backwards.
- Correlation pruning: Identifies and removes features correlated > 0.95 on training data.
"""

from typing import List, Tuple
import numpy as np
import pandas as pd

CORE_FEATURE_SUBSET = [
    "f_total_packets", "f_total_bytes", "f_unique_src_ips",
    "f_unique_dst_ports", "f_entropy_src_ip", "f_entropy_dst_port",
    "f_top_src_ip_share", "f_share_tcp", "f_syn_count_per_flow",
    "f_rst_count_per_flow", "f_share_very_short_flows",
    "f_share_tiny_packet_flows", "f_novel_src_ip_share", "f_per_sec_arrival_std"
]

def compute_slope_5(series: pd.Series) -> pd.Series:
    """Computes the 5-point rolling linear regression slope."""
    x = np.arange(5)
    x_mean = 2.0
    x_dev = x - x_mean
    denom = np.sum(x_dev ** 2) # 10.0

    def calc_slope(window):
        if len(window) < 5 or window.isna().any():
            return np.nan
        y = window.values
        y_mean = np.mean(y)
        return np.sum(x_dev * (y - y_mean)) / denom

    return series.rolling(5).apply(calc_slope, raw=False)

def add_time_features_to_segment(df_seg: pd.DataFrame, lag_steps: List[int] = [1, 2, 3], rolling_l: int = 5) -> pd.DataFrame:
    """Computes time features for one continuous day/segment without DataFrame fragmentation."""
    df = df_seg.copy().sort_values("window_start").reset_index(drop=True)

    new_cols = {}
    for col in CORE_FEATURE_SUBSET:
        if col not in df.columns:
            continue

        s = df[col]

        # 1. Lags
        for lag in lag_steps:
            new_cols[f"{col}_lag{lag}"] = s.shift(lag)

        # 2. Change (diff and ratio vs t-1)
        lag1 = s.shift(1)
        new_cols[f"{col}_diff1"] = s - lag1
        new_cols[f"{col}_ratio1"] = (s + 1e-5) / (lag1 + 1e-5)

        # 3. Rolling mean and std (shifted so window t is excluded)
        roll = s.shift(1).rolling(rolling_l, min_periods=rolling_l)
        r_mean = roll.mean()
        r_std = roll.std().fillna(0.0)

        new_cols[f"{col}_roll_mean{rolling_l}"] = r_mean
        new_cols[f"{col}_roll_std{rolling_l}"] = r_std

        # 4. Z-score
        new_cols[f"{col}_zscore{rolling_l}"] = (s - r_mean) / (r_std + 1e-4)

        # 5. Slope over last 5 windows
        new_cols[f"{col}_slope5"] = compute_slope_5(s)

    # Concat all new columns in one shot
    df_new = pd.DataFrame(new_cols, index=df.index)
    df_combined = pd.concat([df, df_new], axis=1)

    # First rolling_l windows of the segment are warm-up
    df_combined["is_warmup"] = df_combined.index < rolling_l

    return df_combined

def prune_correlated_features(df_train: pd.DataFrame, feature_cols: List[str], threshold: float = 0.95) -> Tuple[List[str], List[str]]:
    """Identifies and removes features with Pearson correlation > threshold on training data."""
    corr_matrix = df_train[feature_cols].corr().abs()
    upper = corr_matrix.where(np.triu(np.ones(corr_matrix.shape), k=1).astype(bool))
    
    to_drop = [column for column in upper.columns if any(upper[column] > threshold)]
    retained = [col for col in feature_cols if col not in to_drop]
    
    return retained, to_drop
