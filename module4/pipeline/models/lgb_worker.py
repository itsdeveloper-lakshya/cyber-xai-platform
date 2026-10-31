"""
LightGBM Isolated Worker (Step N10 Cross-Check)
Executes LightGBM model training in an isolated process to prevent Windows OpenMP / libpq.dll memory collision.
"""

import sys
import json
from pathlib import Path
import numpy as np
import lightgbm as lgb
from sklearn.metrics import precision_recall_curve, auc, brier_score_loss

def run_worker(npz_path: str, cfg_path: str, model_save_path: str, metrics_save_path: str):
    data = np.load(npz_path)
    X_train = data["X_train"]
    y_train = data["y_train"]
    X_val = data["X_val"]
    y_val = data["y_val"]

    with open(cfg_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    n_pos = max(1, int(np.sum(y_train == 1)))
    n_neg = max(1, int(np.sum(y_train == 0)))
    scale_weight = float(np.sqrt(n_neg / n_pos))

    params = cfg["models"]["lightgbm"]
    seed = cfg["models"]["random_seed"]

    model = lgb.LGBMClassifier(
        num_leaves=params["num_leaves"],
        learning_rate=params["learning_rate"],
        n_estimators=params["n_estimators"],
        subsample=params["subsample"],
        colsample_bytree=params["colsample_bytree"],
        min_child_samples=params["min_child_samples"],
        reg_lambda=params["reg_lambda"],
        scale_pos_weight=scale_weight,
        random_state=seed,
        verbosity=-1
    )

    X_train_clean = np.ascontiguousarray(np.nan_to_num(X_train, nan=0.0), dtype=np.float32)
    X_val_clean = np.ascontiguousarray(np.nan_to_num(X_val, nan=0.0), dtype=np.float32)
    y_train_clean = np.ascontiguousarray((y_train == 1).astype(np.int32))
    y_val_clean = np.ascontiguousarray((y_val == 1).astype(np.int32))

    model.fit(
        X_train_clean, y_train_clean,
        eval_set=[(X_val_clean, y_val_clean)],
        eval_metric="average_precision",
        callbacks=[lgb.early_stopping(params["early_stopping_rounds"], verbose=False)]
    )

    # Save native LightGBM model text file (N10)
    model.booster_.save_model(model_save_path)

    preds_val = model.predict_proba(X_val_clean)[:, 1]
    precision, recall, _ = precision_recall_curve(y_val_clean, preds_val)
    pr_auc = float(auc(recall, precision))
    brier = float(brier_score_loss(y_val_clean, preds_val))

    metrics = {
        "val_pr_auc": pr_auc,
        "val_brier_score": brier,
        "best_iteration": int(model.best_iteration_)
    }

    with open(metrics_save_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    print(f"[LGBM_WORKER_OK] Val PR-AUC: {pr_auc:.4f}")

if __name__ == "__main__":
    run_worker(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
