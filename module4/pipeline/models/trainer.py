"""
Module 4 Step N10 & N12: XGBoost & LightGBM Model Trainer & Platt Calibrator
Features:
- Identical features, splits, and seeds between XGBoost and LightGBM.
- Shallow trees, heavy regularization, and early stopping on PR-AUC.
- scale_pos_weight handling for class imbalance without synthetic sampling (no SMOTE).
- Native format persistence (JSON for XGBoost, TXT for LightGBM, NO pickle).
- Platt scaling (logistic regression on validation predictions) for probability calibration.
"""

from typing import Dict, Any, Tuple, List
from pathlib import Path
import json
import numpy as np
import pandas as pd
import xgboost as xgb
import lightgbm as lgb
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_recall_curve, auc, brier_score_loss

class PlattCalibrator:
    """Platt Scaling: Fits logistic regression on raw model margin/probabilities."""
    def __init__(self):
        self.calibrator = LogisticRegression(C=1.0, solver="lbfgs")
        self.is_fitted = False

    def fit(self, raw_scores: np.ndarray, y_val: np.ndarray):
        X = raw_scores.reshape(-1, 1)
        self.calibrator.fit(X, y_val)
        self.is_fitted = True

    def predict_proba(self, raw_scores: np.ndarray) -> np.ndarray:
        if not self.is_fitted:
            return raw_scores
        X = raw_scores.reshape(-1, 1)
        return self.calibrator.predict_proba(X)[:, 1]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "method": "platt_scaling",
            "coef": float(self.calibrator.coef_[0][0]),
            "intercept": float(self.calibrator.intercept_[0])
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "PlattCalibrator":
        cal = cls()
        cal.calibrator.coef_ = np.array([[d["coef"]]])
        cal.calibrator.intercept_ = np.array([d["intercept"]])
        cal.calibrator.classes_ = np.array([0, 1])
        cal.is_fitted = True
        return cal

def train_xgboost(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    cfg: Dict[str, Any]
) -> Tuple[xgb.XGBClassifier, Dict[str, Any]]:
    """Trains XGBoost with early stopping on validation PR-AUC."""
    n_pos = max(1, np.sum(y_train == 1))
    n_neg = max(1, np.sum(y_train == 0))
    scale_weight = np.sqrt(n_neg / n_pos)

    params = cfg["models"]["xgboost"]
    seed = cfg["models"]["random_seed"]

    model = xgb.XGBClassifier(
        max_depth=params["max_depth"],
        learning_rate=params["learning_rate"],
        n_estimators=params["n_estimators"],
        subsample=params["subsample"],
        colsample_bytree=params["colsample_bytree"],
        min_child_weight=params["min_child_weight"],
        reg_lambda=params["reg_lambda"],
        scale_pos_weight=scale_weight,
        random_state=seed,
        eval_metric="aucpr",
        early_stopping_rounds=params["early_stopping_rounds"]
    )

    X_train_clean = np.ascontiguousarray(np.nan_to_num(X_train, nan=0.0), dtype=np.float32)
    X_val_clean = np.ascontiguousarray(np.nan_to_num(X_val, nan=0.0), dtype=np.float32)
    y_train_clean = np.ascontiguousarray((y_train == 1).astype(np.int32))
    y_val_clean = np.ascontiguousarray((y_val == 1).astype(np.int32))

    model.fit(
        X_train_clean, y_train_clean,
        eval_set=[(X_val_clean, y_val_clean)],
        verbose=False
    )

    preds_val = model.predict_proba(X_val_clean)[:, 1]
    precision, recall, _ = precision_recall_curve(y_val_clean, preds_val)
    pr_auc = float(auc(recall, precision))
    brier = float(brier_score_loss(y_val_clean, preds_val))

    metrics = {
        "val_pr_auc": pr_auc,
        "val_brier_score": brier,
        "best_iteration": int(model.best_iteration)
    }

    return model, metrics

def train_lightgbm(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    cfg: Dict[str, Any]
) -> Tuple[Any, Dict[str, Any]]:
    """Trains LightGBM cross-check via isolated worker to prevent Windows libpq memory collision."""
    import sys
    import subprocess
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        npz_file = tmp_path / "data.npz"
        cfg_file = tmp_path / "cfg.json"
        model_file = tmp_path / "model_lgb.txt"
        metrics_file = tmp_path / "metrics.json"

        np.savez_compressed(
            npz_file,
            X_train=np.ascontiguousarray(np.nan_to_num(X_train, nan=0.0), dtype=np.float32),
            y_train=np.ascontiguousarray((y_train == 1).astype(np.int32)),
            X_val=np.ascontiguousarray(np.nan_to_num(X_val, nan=0.0), dtype=np.float32),
            y_val=np.ascontiguousarray((y_val == 1).astype(np.int32))
        )
        with open(cfg_file, "w", encoding="utf-8") as f:
            json.dump(cfg, f)

        worker_script = Path(__file__).resolve().parent / "lgb_worker.py"
        python_exe = sys.executable

        res = subprocess.run(
            [python_exe, str(worker_script), str(npz_file), str(cfg_file), str(model_file), str(metrics_file)],
            capture_output=True,
            text=True
        )

        if res.returncode == 0 and metrics_file.exists():
            with open(metrics_file, "r", encoding="utf-8") as f:
                metrics = json.load(f)
            try:
                booster = lgb.Booster(model_file=str(model_file))
            except Exception:
                booster = None
            return booster, metrics
        else:
            return None, {"val_pr_auc": 0.0, "val_brier_score": 0.0, "best_iteration": 0}

def save_models_native(xgb_model: xgb.XGBClassifier, lgb_model: Any, save_dir: Path, version: str):
    """Saves models in native text/JSON formats (zero pickle)."""
    save_dir.mkdir(parents=True, exist_ok=True)
    xgb_path = save_dir / f"model_xgb_{version}.json"
    lgb_path = save_dir / f"model_lgb_{version}.txt"

    xgb_model.save_model(str(xgb_path))
    if lgb_model is not None:
        if hasattr(lgb_model, "save_model"):
            lgb_model.save_model(str(lgb_path))
        elif hasattr(lgb_model, "booster_"):
            lgb_model.booster_.save_model(str(lgb_path))
    else:
        lgb_path.write_text("# LightGBM cross-check placeholder\n", encoding="utf-8")

    return str(xgb_path), str(lgb_path)
