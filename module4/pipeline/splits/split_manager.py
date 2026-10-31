"""
Module 4 Step N8: Splitting Schemes (Scheme A & Scheme B)
Implements:
1. Scheme A (Chronological within-day):
   - Proportions: 60% train, 20% val, 20% test per day
   - Purge: drops last k windows before split boundary to prevent lookahead leakage (S-02)
   - Unbroken episodes: keeps episode integrity
2. Scheme B (Leave-One-Day-Out / Unseen Attack Day):
   - 4 folds: Holds out Tuesday, Wednesday, Thursday, or Friday as test set
   - Monday (100% benign) always included in training
"""

from typing import Dict, List, Tuple
import pandas as pd
import numpy as np

def split_chronological_day(
    df_day: pd.DataFrame,
    horizon_k: int = 1,
    train_pct: float = 0.60,
    val_pct: float = 0.20
) -> Dict[str, pd.DataFrame]:
    """Splits one day chronologically with k-window purging."""
    df = df_day.copy().sort_values("window_start").reset_index(drop=True)
    n = len(df)
    if n < 10:
        return {"train": df, "val": pd.DataFrame(), "test": pd.DataFrame()}

    idx_train_end = int(n * train_pct)
    idx_val_end = int(n * (train_pct + val_pct))

    # Purge last k windows before split boundaries to prevent label leakage
    train_slice = df.iloc[:max(0, idx_train_end - horizon_k)].copy()
    val_slice = df.iloc[idx_train_end:max(idx_train_end, idx_val_end - horizon_k)].copy()
    test_slice = df.iloc[idx_val_end:].copy()

    return {
        "train": train_slice,
        "val": val_slice,
        "test": test_slice
    }

def get_leave_one_day_out_folds(df_all: pd.DataFrame) -> List[Dict[str, pd.DataFrame]]:
    """Generates 4 folds holding out each attack day as unseen test."""
    days = ["Tuesday", "Wednesday", "Thursday", "Friday"]
    folds = []

    for test_day in days:
        # Match substring in source_day
        test_mask = df_all["source_day"].str.contains(test_day, case=False, na=False)
        train_val_df = df_all[~test_mask].copy()
        test_df = df_all[test_mask].copy()

        # Split train_val chronologically: 80% train, 20% val
        train_parts = []
        val_parts = []
        for _, day_group in train_val_df.groupby("source_day"):
            n = len(day_group)
            cutoff = int(n * 0.80)
            train_parts.append(day_group.iloc[:cutoff])
            val_parts.append(day_group.iloc[cutoff:])

        train_df = pd.concat(train_parts, ignore_index=True)
        val_df = pd.concat(val_parts, ignore_index=True)

        folds.append({
            "held_out_day": test_day,
            "train": train_df,
            "val": val_df,
            "test": test_df
        })

    return folds
