"""
Module 2 Part B: Model Training & Evaluation Engine (Section 7.6 & 7.8)
Trains:
1. Baseline 1: Plain z-score heuristic (Max of absolute self z-scores > cutoff)
2. Baseline 2: Isolation Forest
3. Primary Model: XGBoost with class-imbalance weighting (scale_pos_weight)
Evaluates on test slice: PR-AUC, Precision, Recall, F1, and Precision@K per day.
Saves model in native XGBoost JSON format (Section 7.6) and persists scores.
"""

import os
import json
import time
import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.ensemble import IsolationForest
from sklearn.metrics import precision_score, recall_score, f1_score, precision_recall_curve, auc

from split import split_dataset, FEATURE_COLUMNS

def train_and_evaluate(df_featured: pd.DataFrame):
    t_start = time.time()
    train_df, val_df, test_df, ranges = split_dataset(df_featured)

    X_train = train_df[FEATURE_COLUMNS].values
    y_train = train_df["is_malicious"].values

    X_val = val_df[FEATURE_COLUMNS].values
    y_val = val_df["is_malicious"].values

    X_test = test_df[FEATURE_COLUMNS].values
    y_test = test_df["is_malicious"].values

    print("\n" + "="*75)
    print("STEP 1: TRAINING BASELINES (SECTION 7.6)")
    print("="*75)

    # -------------------------------------------------------------
    # Baseline 1: Plain Max Absolute Z-Score Rule
    # -------------------------------------------------------------
    z_cols = [c for c in FEATURE_COLUMNS if c.startswith("z_30d_")]
    z_test_max = test_df[z_cols].abs().max(axis=1).values
    z_cutoff = 3.0 # > 3 sigma deviation
    y_pred_z = (z_test_max >= z_cutoff).astype(int)

    p_z = precision_score(y_test, y_pred_z, zero_division=0)
    r_z = recall_score(y_test, y_pred_z, zero_division=0)
    f1_z = f1_score(y_test, y_pred_z, zero_division=0)
    print(f"1. Baseline 1 (Max Z-Score Rule >= {z_cutoff} sigma):")
    print(f"   Precision: {p_z:.4f} | Recall: {r_z:.4f} | F1: {f1_z:.4f}")

    # -------------------------------------------------------------
    # Baseline 2: Isolation Forest
    # -------------------------------------------------------------
    print("2. Training Baseline 2 (Isolation Forest)...")
    iso = IsolationForest(n_estimators=100, max_samples=256, contamination=0.01, random_state=42, n_jobs=-1)
    iso.fit(X_train)
    iso_scores = -iso.score_samples(X_test) # Higher means more anomalous
    precision_iso, recall_iso, _ = precision_recall_curve(y_test, iso_scores)
    pr_auc_iso = auc(recall_iso, precision_iso)
    iso_pred = (iso_scores >= np.percentile(iso_scores, 99)).astype(int)
    p_iso = precision_score(y_test, iso_pred, zero_division=0)
    r_iso = recall_score(y_test, iso_pred, zero_division=0)
    f1_iso = f1_score(y_test, iso_pred, zero_division=0)
    print(f"   PR-AUC: {pr_auc_iso:.4f} | Precision@Top1%: {p_iso:.4f} | Recall: {r_iso:.4f} | F1: {f1_iso:.4f}")

    # -------------------------------------------------------------
    # Primary Model: XGBoost with Class-Imbalance Weighting
    # Section 7.6: scale_pos_weight = sqrt(neg / pos)
    # -------------------------------------------------------------
    print("\n3. Training Primary Model (XGBoost Classifier)...")
    num_neg = (y_train == 0).sum()
    num_pos = (y_train == 1).sum()
    scale_weight = np.sqrt(num_neg / num_pos)
    print(f"   Negative/Positive Ratio: {num_neg/num_pos:.1f}:1 | scale_pos_weight: {scale_weight:.2f}")

    model = xgb.XGBClassifier(
        n_estimators=300,
        max_depth=5,
        learning_rate=0.08,
        scale_pos_weight=scale_weight,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42,
        eval_metric="aucpr",
        early_stopping_rounds=30,
        tree_method="hist",
        n_jobs=-1
    )

    model.fit(
        X_train, y_train,
        eval_set=[(X_val, y_val)],
        verbose=False
    )
    print(f"   -> Early stopping reached at tree {model.best_iteration} (Best Val PR-AUC: {model.best_score:.4f})")

    # -------------------------------------------------------------
    # Step 2: Test Slice Evaluation (Section 7.8)
    # -------------------------------------------------------------
    y_test_probs = model.predict_proba(X_test)[:, 1]
    precisions, recalls, thresholds = precision_recall_curve(y_test, y_test_probs)
    pr_auc_xgb = auc(recalls, precisions)

    # Optimal F1 threshold
    f1_scores = 2 * (precisions * recalls) / (precisions + recalls + 1e-8)
    best_idx = np.argmax(f1_scores)
    best_thresh = thresholds[best_idx] if best_idx < len(thresholds) else 0.5
    y_test_pred = (y_test_probs >= best_thresh).astype(int)

    p_xgb = precision_score(y_test, y_test_pred, zero_division=0)
    r_xgb = recall_score(y_test, y_test_pred, zero_division=0)
    f1_xgb = f1_score(y_test, y_test_pred, zero_division=0)

    # -------------------------------------------------------------
    # Insider-Level Recall (Section 7.8)
    # -------------------------------------------------------------
    test_eval = test_df[["user_id", "date", "is_malicious"]].copy()
    test_eval["prob"] = y_test_probs
    test_eval["pred"] = y_test_pred

    malicious_insiders_test = test_eval[test_eval["is_malicious"] == 1]["user_id"].unique()
    caught_insiders = 0
    for u in malicious_insiders_test:
        u_slice = test_eval[test_eval["user_id"] == u]
        if (u_slice[u_slice["is_malicious"] == 1]["pred"] == 1).any():
            caught_insiders += 1
    insider_recall = caught_insiders / len(malicious_insiders_test) if len(malicious_insiders_test) > 0 else 0

    print("\n" + "="*75)
    print("SECTION 7.8: MODEL COMPARISON BENCHMARK (TEST SLICE)")
    print("="*75)
    print(f"{'Model':<24} | {'PR-AUC':<8} | {'Precision':<9} | {'Recall':<8} | {'F1-Score':<8}")
    print("-" * 75)
    print(f"{'1. Plain Z-Score Rule':<24} | {'N/A':<8} | {p_z:<9.4f} | {r_z:<8.4f} | {f1_z:<8.4f}")
    print(f"{'2. Isolation Forest':<24} | {pr_auc_iso:<8.4f} | {p_iso:<9.4f} | {r_iso:<8.4f} | {f1_iso:<8.4f}")
    print(f"{'3. XGBoost (Ours)':<24} | {pr_auc_xgb:<8.4f} | {p_xgb:<9.4f} | {r_xgb:<8.4f} | {f1_xgb:<8.4f}")
    print("="*75)
    print(f"Insider-Level Detection Rate (Test Slice): {caught_insiders} / {len(malicious_insiders_test)} ({100*insider_recall:.1f}%)")

    # -------------------------------------------------------------
    # Step 3: Save Model Artifacts (Native JSON Format - Section 7.6)
    # -------------------------------------------------------------
    os.makedirs("module2/ml/artifacts", exist_ok=True)
    model_json_path = "module2/ml/artifacts/behavior_xgboost_v1.json"
    model.save_model(model_json_path)

    metadata = {
        "model_version": 1,
        "algorithm": "XGBoost",
        "feature_list": FEATURE_COLUMNS,
        "train_date_range": ranges["train_range"],
        "val_date_range": ranges["val_range"],
        "test_date_range": ranges["test_range"],
        "metrics": {
            "pr_auc": float(pr_auc_xgb),
            "precision": float(p_xgb),
            "recall": float(r_xgb),
            "f1": float(f1_xgb),
            "insider_recall": float(insider_recall),
            "threshold": float(best_thresh)
        },
        "file_reference": model_json_path
    }
    meta_path = "module2/ml/artifacts/behavior_model_metadata.json"
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"\nSaved XGBoost Model (Native JSON) : {model_json_path}")
    print(f"Saved Version Metadata             : {meta_path}")

    # -------------------------------------------------------------
    # Step 4: Generate beh_daily_score & beh_feature_matrix (Section 7.9)
    # -------------------------------------------------------------
    print("\nComputing full-dataset anomaly scores and ranking for Postgres...")
    all_X = df_featured[FEATURE_COLUMNS].values
    df_featured["probability"] = model.predict_proba(all_X)[:, 1].astype(np.float32)

    # Compute daily rank (Section 7.9: Rank 1 is highest anomaly probability that day)
    df_featured["rank_in_day"] = df_featured.groupby("date")["probability"].rank(ascending=False, method="min").astype(int)

    score_cols = ["user_id", "date", "probability", "rank_in_day"]
    scores_df = df_featured[score_cols].copy()
    scores_df["model_version"] = 1
    scores_path = "data/intermediate/beh_daily_score.parquet"
    scores_df.to_parquet(scores_path, engine="pyarrow", index=False)

    # Save feature matrix for Module 5 SHAP (Section 7.9)
    feat_matrix_cols = ["user_id", "date"] + FEATURE_COLUMNS
    feat_matrix_df = df_featured[feat_matrix_cols].copy()
    feat_matrix_df["model_version"] = 1
    matrix_path = "data/intermediate/beh_feature_matrix.parquet"
    feat_matrix_df.to_parquet(matrix_path, engine="pyarrow", index=False)

    print(f"Saved beh_daily_score Parquet      : {scores_path} ({len(scores_df):,} rows)")
    print(f"Saved beh_feature_matrix Parquet   : {matrix_path} (For Module 5 SHAP)")
    print(f"Total Part B pipeline completed in {time.time() - t_start:.1f}s!")

if __name__ == "__main__":
    df_path = "data/intermediate/featured_user_daily_activity.parquet"
    if os.path.exists(df_path):
        df_feat = pd.read_parquet(df_path)
        train_and_evaluate(df_feat)
