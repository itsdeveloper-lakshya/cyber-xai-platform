"""
Module 4 Step N6 & N7: Ground-Truth Surge Labels & Target Horizon Builder
Implements Idea B + E:
1. Surge Window: attack_share >= share_threshold AND flow_count >= flow_floor.
2. Horizon Target y(t, k): y = 1 if any window in [t+1, t+k] is a surge window.
3. Calm Window: window t is not a surge and none of the past H windows were surge.
4. Onset Event: calm window t with y(t, k) == 1 (the genuine early-warning test).
5. Ongoing Window: window t is already inside a surge.

Rules:
- Purging: Windows whose horizon extends past the segment end have unknown targets and are dropped.
- Dual Evaluation: Metrics reported on all windows AND onset-only view.
"""

from typing import List
import numpy as np
import pandas as pd

def compute_surge_labels(
    df_seg: pd.DataFrame,
    share_threshold: float = 0.20,
    flow_floor: int = 30,
    calm_history_h: int = 3,
    horizons_k: List[int] = [1, 3, 5]
) -> pd.DataFrame:
    """Computes surge flags, horizon targets, and onset masks for a continuous segment."""
    df = df_seg.copy().sort_values("window_start").reset_index(drop=True)
    n = len(df)

    # 1. Base Surge Definition (Idea B + E)
    df["is_surge"] = (df["attack_share"] >= share_threshold) & (df["flow_count"] >= flow_floor)

    # 2. Calm Window definition (Section 8 N7)
    # Window t is calm if neither t nor any of past calm_history_h windows were a surge
    surge_hist = df["is_surge"].rolling(calm_history_h + 1, min_periods=1).sum()
    df["is_calm"] = surge_hist == 0

    # 3. Ongoing Window definition
    df["is_ongoing"] = df["is_surge"]

    # 4. Target for each horizon k
    for k in horizons_k:
        y_col = f"y_k{k}"
        onset_col = f"is_onset_k{k}"
        valid_col = f"valid_target_k{k}"

        # y(t, k) = 1 if any of t+1..t+k is surge
        # Rolling forward by reversing, rolling, and reversing back
        reversed_surge = df["is_surge"][::-1]
        roll_forward = reversed_surge.rolling(k, min_periods=1).max()[::-1].shift(-1)
        
        df[y_col] = roll_forward.fillna(0).astype(int)

        # Drop windows whose horizon passes segment end (last k windows of the day)
        df[valid_col] = df.index < (n - k)
        df.loc[~df[valid_col], y_col] = -1 # Sentinel for invalid

        # Onset event: calm window with upcoming surge
        df[onset_col] = df["is_calm"] & (df[y_col] == 1) & df[valid_col]

    return df
