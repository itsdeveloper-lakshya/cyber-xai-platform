"""
Module 4 Complete End-to-End Pipeline Runner
Executes Steps N1 through N18:
1. Windowing & Feature Engineering (populates net_window_base)
2. Time Dynamics & Correlation Pruning
3. Surge & Onset Labeling (populates net_surge_episode)
4. Chronological Splitting with Purging
5. XGBoost & LightGBM Training with Early Stopping
6. Platt Scaling Calibration
7. Model Artifact Storage & Registry Activation (net_model_registry, net_experiment_run)
8. Feature Matrix Storage for Module 5 SHAP (net_feature_matrix)
9. Replay Execution (net_forecast, net_alert_episode)
"""

import os
import sys
import json
import uuid
import yaml
from pathlib import Path
from datetime import datetime, timezone
import psycopg2
from psycopg2.extras import execute_values
import numpy as np
import pandas as pd
from sqlalchemy import create_engine
import xgboost as xgb
import lightgbm as lgb

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from module4.pipeline.windowing.window_builder import build_all_windows
from module4.pipeline.features.time_features import add_time_features_to_segment, prune_correlated_features
from module4.pipeline.labels.surge_labeler import compute_surge_labels
from module4.pipeline.splits.split_manager import split_chronological_day
from module4.pipeline.models.trainer import (
    train_xgboost,
    train_lightgbm,
    save_models_native,
    PlattCalibrator
)
from module4.pipeline.replay.replay_service import ReplayService

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CONFIG_PATH = REPO_ROOT / "module4" / "config.yaml"
ARTIFACTS_DIR = REPO_ROOT / "module4" / "artifacts"

def run_end_to_end_pipeline():
    print("=" * 70)
    print(" >>> STARTING MODULE 4 NETWORK ATTACK FORECASTING PIPELINE")
    print("=" * 70)

    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    db_url = cfg["database"]["connection_url"]
    window_size_sec = cfg["windows"]["default_size_sec"] # 300s
    horizon_k = cfg["horizons"]["default_k"] # 1
    engine = create_engine(db_url)

    # --------------------------------------------------------------------------
    # Step 1: Ensure net_window_base has windows computed
    # --------------------------------------------------------------------------
    print("\n[Step 1] Checking existing precomputed windows in net_window_base...")
    conn = psycopg2.connect(db_url)
    cur = conn.cursor()
    cur.execute(f"SELECT COUNT(*) FROM net_window_base WHERE window_size_sec = {window_size_sec};")
    count = cur.fetchone()[0]

    if count == 0:
        print(f"[-] No windows found for window_size = {window_size_sec}s. Generating from 2.8M flows...")
        build_all_windows(window_size_sec, db_url)
    else:
        print(f"[+] Found {count:,} existing windows in net_window_base.")

    # --------------------------------------------------------------------------
    # Step 2: Load Windows, Add Time Features & Surge Labels per Day Segment
    # --------------------------------------------------------------------------
    print("\n[Step 2] Engineering time features and surge labels per day segment...")
    df_windows = pd.read_sql(f"SELECT * FROM net_window_base WHERE window_size_sec = {window_size_sec} ORDER BY window_start ASC;", engine)
    
    processed_days = []
    surge_episodes_to_save = []

    for day_name, day_group in df_windows.groupby("source_day"):
        # 1. Time features strictly within segment (Step N4)
        df_time = add_time_features_to_segment(day_group, lag_steps=cfg["features"]["lag_steps"], rolling_l=cfg["features"]["rolling_window_l"])
        
        # 2. Surge labels and targets (Step N6 & N7)
        df_labeled = compute_surge_labels(
            df_time,
            share_threshold=cfg["labels"]["attack_share_threshold"],
            flow_floor=cfg["labels"]["flow_count_floor"],
            calm_history_h=cfg["labels"]["calm_history_windows"],
            horizons_k=cfg["horizons"]["candidate_k"]
        )

        # 3. Extract ground-truth surge episodes
        in_surge = False
        s_start = None
        s_end = None
        s_count = 0
        peak_share = 0.0
        cur_families = set()

        for _, r in df_labeled.iterrows():
            if r["is_surge"]:
                if not in_surge:
                    in_surge = True
                    s_start = r["window_start"]
                    s_end = r["window_end"]
                    s_count = 1
                    peak_share = float(r["attack_share"])
                    cur_families = set(r["family_counts"].keys()) if isinstance(r["family_counts"], dict) else set()
                else:
                    s_end = r["window_end"]
                    s_count += 1
                    peak_share = max(peak_share, float(r["attack_share"]))
                    if isinstance(r["family_counts"], dict):
                        cur_families.update(r["family_counts"].keys())
            else:
                if in_surge:
                    surge_episodes_to_save.append({
                        "episode_id": f"SURGE_{uuid.uuid4().hex[:12].upper()}",
                        "config_id": "cfg_default",
                        "window_size_sec": window_size_sec,
                        "start_window": s_start,
                        "end_window": s_end,
                        "n_windows": s_count,
                        "peak_attack_share": peak_share,
                        "families": json.dumps(list(cur_families))
                    })
                    in_surge = False

        if in_surge:
            surge_episodes_to_save.append({
                "episode_id": f"SURGE_{uuid.uuid4().hex[:12].upper()}",
                "config_id": "cfg_default",
                "window_size_sec": window_size_sec,
                "start_window": s_start,
                "end_window": s_end,
                "n_windows": s_count,
                "peak_attack_share": peak_share,
                "families": json.dumps(list(cur_families))
            })

        processed_days.append(df_labeled)

    df_full = pd.concat(processed_days, ignore_index=True)

    # Save surge episodes into net_surge_episode
    if surge_episodes_to_save:
        cur.execute("DELETE FROM net_surge_episode WHERE window_size_sec = %s;", (window_size_sec,))
        q_ep = """
        INSERT INTO net_surge_episode (
            episode_id, config_id, window_size_sec, start_window, end_window, n_windows, peak_attack_share, families
        ) VALUES %s;
        """
        ep_tuples = [(e["episode_id"], e["config_id"], e["window_size_sec"], e["start_window"], e["end_window"], e["n_windows"], e["peak_attack_share"], e["families"]) for e in surge_episodes_to_save]
        execute_values(cur, q_ep, ep_tuples)
        conn.commit()
        print(f"[+] Recorded {len(surge_episodes_to_save)} ground-truth surge episodes in net_surge_episode.")

    # --------------------------------------------------------------------------
    # Step 3: Splitting Scheme A (Chronological per day with k-window purging)
    # --------------------------------------------------------------------------
    print("\n[Step 3] Splitting dataset chronologically with k-window purging...")
    train_slices = []
    val_slices = []
    test_slices = []

    for _, day_df in df_full.groupby("source_day"):
        # Exclude warm-up windows
        valid_day = day_df[~day_df["is_warmup"]].copy()
        splits = split_chronological_day(
            valid_day,
            horizon_k=horizon_k,
            train_pct=cfg["splits"]["chronological"]["train_pct"],
            val_pct=cfg["splits"]["chronological"]["val_pct"]
        )
        train_slices.append(splits["train"])
        val_slices.append(splits["val"])
        test_slices.append(splits["test"])

    df_train = pd.concat(train_slices, ignore_index=True)
    df_val = pd.concat(val_slices, ignore_index=True)
    df_test = pd.concat(test_slices, ignore_index=True)

    print(f"[+] Dataset Split: Train = {len(df_train)} windows | Val = {len(df_val)} windows | Test = {len(df_test)} windows")

    # --------------------------------------------------------------------------
    # Step 4: Feature Selection & Correlation Pruning
    # --------------------------------------------------------------------------
    print("\n[Step 4] Feature pruning (correlation threshold = 0.95 on train)...")
    candidate_cols = [c for c in df_train.columns if c.startswith("f_")]
    retained_feats, dropped_feats = prune_correlated_features(df_train, candidate_cols, threshold=cfg["features"]["correlation_threshold"])
    print(f"[+] Retained {len(retained_feats)} non-collinear features (dropped {len(dropped_feats)} correlated features).")

    target_col = f"y_k{horizon_k}"
    X_train = df_train[retained_feats].values
    y_train = df_train[target_col].values
    X_val = df_val[retained_feats].values
    y_val = df_val[target_col].values
    X_test = df_test[retained_feats].values
    y_test = df_test[target_col].values

    # --------------------------------------------------------------------------
    # Step 5: Model Training (XGBoost Main & LightGBM Cross-Check)
    # --------------------------------------------------------------------------
    print("\n[Step 5] Training XGBoost and LightGBM models...")
    xgb_model, xgb_metrics = train_xgboost(X_train, y_train, X_val, y_val, cfg)
    print(f"  [XGBoost] Val PR-AUC = {xgb_metrics['val_pr_auc']:.4f} | Brier = {xgb_metrics['val_brier_score']:.4f}")

    lgb_model, lgb_metrics = train_lightgbm(X_train, y_train, X_val, y_val, cfg)
    print(f"  [LightGBM] Val PR-AUC = {lgb_metrics['val_pr_auc']:.4f} | Brier = {lgb_metrics['val_brier_score']:.4f}")

    # --------------------------------------------------------------------------
    # Step 6: Probability Calibration (Platt Scaling)
    # --------------------------------------------------------------------------
    print("\n[Step 6] Fitting Platt Scaling Calibrator on Validation Slice...")
    calibrator = PlattCalibrator()
    raw_val_scores = xgb_model.predict_proba(np.nan_to_num(X_val, nan=0.0))[:, 1]
    calibrator.fit(raw_val_scores, y_val)
    print(f"[+] Platt Calibrator fitted: Coef = {calibrator.to_dict()['coef']:.4f}, Intercept = {calibrator.to_dict()['intercept']:.4f}")

    # --------------------------------------------------------------------------
    # Step 7: Final Test Evaluation (Once!)
    # --------------------------------------------------------------------------
    print("\n[Step 7] Evaluating on Unseen Test Slice...")
    from sklearn.metrics import precision_recall_curve, auc, brier_score_loss, classification_report
    raw_test_scores = xgb_model.predict_proba(np.nan_to_num(X_test, nan=0.0))[:, 1]
    cal_test_probs = calibrator.predict_proba(raw_test_scores)

    valid_mask = (y_test >= 0)
    y_test_clean = (y_test[valid_mask] == 1).astype(int)
    cal_test_clean = cal_test_probs[valid_mask]

    p_curve, r_curve, _ = precision_recall_curve(y_test_clean, cal_test_clean)
    test_pr_auc = float(auc(r_curve, p_curve))
    test_brier = float(brier_score_loss(y_test_clean, cal_test_clean))
    test_metrics = {
        "test_pr_auc": test_pr_auc,
        "test_brier_score": test_brier,
        "test_samples": int(len(y_test_clean)),
        "test_positives": int(np.sum(y_test_clean == 1))
    }
    print(f"[PASS] Test PR-AUC = {test_pr_auc:.4f} | Test Brier Score = {test_brier:.4f}")

    # --------------------------------------------------------------------------
    # Step 8: Persist Artifacts and Register in Database
    # --------------------------------------------------------------------------
    print("\n[Step 8] Persisting Model Artifacts and Registering in PostgreSQL...")
    model_version = "v1"
    run_id = f"RUN_EXP_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    xgb_path, lgb_path = save_models_native(xgb_model, lgb_model, ARTIFACTS_DIR, model_version)
    calibrator_path = ARTIFACTS_DIR / f"calibrator_{model_version}.json"
    calibrator_path.write_text(json.dumps(calibrator.to_dict(), indent=2), encoding="utf-8")

    # 1. Log into net_experiment_run
    q_run = """
    INSERT INTO net_experiment_run (
        run_id, created_at, git_commit, seed, window_size_sec, horizon_k,
        share_threshold, flow_floor, split_scheme, training_regime, feature_set,
        model_type, params, library_versions, val_metrics, test_metrics, notes
    ) VALUES (%s, NOW(), %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
    """
    cur.execute(q_run, (
        run_id, "HEAD", cfg["models"]["random_seed"], window_size_sec, horizon_k,
        cfg["labels"]["attack_share_threshold"], cfg["labels"]["flow_count_floor"],
        "scheme_a", "all_windows", "retained_pruned_35", "xgboost",
        json.dumps(cfg["models"]["xgboost"]), json.dumps({"xgboost": xgb.__version__, "lightgbm": lgb.__version__}),
        json.dumps(xgb_metrics), json.dumps(test_metrics), "Initial baseline run for Module 4"
    ))

    # 2. Register into net_model_registry
    cur.execute("UPDATE net_model_registry SET is_active = FALSE WHERE window_size_sec = %s;", (window_size_sec,))
    q_reg = """
    INSERT INTO net_model_registry (
        model_version, run_id, model_type, file_ref, feature_list,
        window_size_sec, horizon_k, calibrator, thresholds, hysteresis, is_active
    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    ON CONFLICT (model_version) DO UPDATE SET
        run_id = EXCLUDED.run_id,
        file_ref = EXCLUDED.file_ref,
        feature_list = EXCLUDED.feature_list,
        calibrator = EXCLUDED.calibrator,
        thresholds = EXCLUDED.thresholds,
        hysteresis = EXCLUDED.hysteresis,
        is_active = EXCLUDED.is_active;
    """
    cur.execute(q_reg, (
        model_version, run_id, "xgboost", xgb_path, json.dumps(retained_feats),
        window_size_sec, horizon_k, json.dumps(calibrator.to_dict()),
        json.dumps(cfg["alerts"]["thresholds"]), json.dumps({"confirmations": cfg["alerts"]["hysteresis_confirmations"]}),
        True
    ))

    # 3. Store net_feature_matrix for Module 5 SHAP
    print("\n[Step 9] Storing Feature Matrix for Module 5 SHAP in net_feature_matrix...")
    cur.execute("DELETE FROM net_feature_matrix WHERE model_version = %s;", (model_version,))
    matrix_rows = []
    for _, r in df_full.iterrows():
        feat_dict = {col: float(r[col]) for col in retained_feats if col in r and pd.notna(r[col])}
        w_end = r["window_end"].to_pydatetime() if hasattr(r["window_end"], "to_pydatetime") else r["window_end"]
        matrix_rows.append((
            model_version, w_end, int(r.get(target_col, 0)), bool(r.get(f"is_onset_k{horizon_k}", False)), json.dumps(feat_dict)
        ))
    execute_values(cur, """
        INSERT INTO net_feature_matrix (model_version, window_end, y, onset_flag, features)
        VALUES %s;
    """, matrix_rows, page_size=1000)

    conn.commit()
    print(f"[PASS] Successfully stored {len(matrix_rows)} feature matrix rows for Module 5 SHAP.")

    # --------------------------------------------------------------------------
    # Step 10: Run Initial Replay Service on Test Set
    # --------------------------------------------------------------------------
    print("\n[Step 10] Running Simulated Live Replay Stream on Test Set...")
    replay_svc = ReplayService(
        db_url=db_url,
        model=xgb_model,
        calibrator=calibrator,
        feature_cols=retained_feats,
        model_version=model_version,
        horizon_k=horizon_k,
        watch_thresh=cfg["alerts"]["thresholds"]["watch"],
        warn_thresh=cfg["alerts"]["thresholds"]["warning"],
        crit_thresh=cfg["alerts"]["thresholds"]["critical"],
        hysteresis_confirmations=cfg["alerts"]["hysteresis_confirmations"]
    )
    replay_result = replay_svc.run_replay(df_test, replay_run_id="REPLAY_BASELINE_TEST_V1", speed_multiplier=0.0)
    print(f"[PASS] Replay complete! Generated {replay_result['total_windows']} forecast ticks and {replay_result['alert_episodes_count']} alert episodes.")

    cur.close()
    conn.close()
    engine.dispose()
    print("\n" + "=" * 70)
    print(" >>> MODULE 4 PIPELINE EXECUTION SUCCESSFULLY COMPLETED!")
    print("=" * 70)

if __name__ == "__main__":
    run_end_to_end_pipeline()
