"""
Module 4 Step N9: Baselines (Persistence, Rolling Average, Traffic Logistic Regression)
Implements:
1. Persistence Baseline (Oracle): Predicts y(t, k) = 1 if current window is a surge.
2. Rolling Average Baseline (Oracle): Predicts surge if rolling attack share exceeds threshold.
3. Traffic-Only Logistic Regression (Fair Label-Free Baseline): Trained strictly on base/time features.
"""

from typing import Dict, Any, Tuple
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_recall_curve, auc, brier_score_loss

class PersistenceBaseline:
    """Predicts y(t, k) = 1 if current window t is a surge."""
    def predict_proba(self, df: pd.DataFrame) -> np.ndarray:
        # Returns [P(0), P(1)]
        probs = df["is_surge"].astype(float).values
        return np.column_stack([1.0 - probs, probs])

class RollingAverageBaseline:
    """Predicts a surge if rolling mean attack share of past L windows exceeds threshold."""
    def __init__(self, rolling_l: int = 3, threshold: float = 0.20):
        self.rolling_l = rolling_l
        self.threshold = threshold

    def predict_proba(self, df: pd.DataFrame) -> np.ndarray:
        roll_share = df["attack_share"].rolling(self.rolling_l, min_periods=1).mean().values
        probs = np.clip(roll_share / max(1e-5, self.threshold), 0.0, 1.0)
        return np.column_stack([1.0 - probs, probs])

class TrafficLogisticRegression:
    """Fair label-free baseline trained on label-free traffic features."""
    def __init__(self):
        self.model = LogisticRegression(class_weight="balanced", max_iter=500, random_state=42)

    def fit(self, X_train: np.ndarray, y_train: np.ndarray):
        # Fill any residual NaNs with column medians
        X_clean = np.nan_to_num(X_train, nan=0.0)
        self.model.fit(X_clean, y_train)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        X_clean = np.nan_to_num(X, nan=0.0)
        return self.model.predict_proba(X_clean)
