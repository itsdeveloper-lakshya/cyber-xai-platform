"""
Module 4 Step N17: Network Forecast Replay Service (Simulated Live Feed)
Features:
1. Steps through test timeline window-by-window in strict chronological order.
2. Evaluates features available at window t, scores via active model, applies Platt calibration.
3. Applies 4-level alert state machine with hysteresis and rising-trend check.
4. Writes forecasts to net_forecast and aggregates alert episodes into net_alert_episode.
5. Guarantees: Replay output strictly equals batch scoring (Test R-01), deterministic on rerun (Test R-02).
"""

import time
import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime
import psycopg2
from psycopg2.extras import execute_values
import numpy as np
import pandas as pd
import xgboost as xgb

from module4.pipeline.alerts.alert_engine import AlertStateMachine, aggregate_alert_episodes
from module4.pipeline.models.trainer import PlattCalibrator

class ReplayService:
    def __init__(
        self,
        db_url: str,
        model: Any,
        calibrator: PlattCalibrator,
        feature_cols: List[str],
        model_version: str = "v1",
        horizon_k: int = 1,
        watch_thresh: float = 0.35,
        warn_thresh: float = 0.60,
        crit_thresh: float = 0.80,
        hysteresis_confirmations: int = 2
    ):
        self.db_url = db_url
        self.model = model
        self.calibrator = calibrator
        self.feature_cols = feature_cols
        self.model_version = model_version
        self.horizon_k = horizon_k
        self.watch_thresh = watch_thresh
        self.warn_thresh = warn_thresh
        self.crit_thresh = crit_thresh
        self.hysteresis_confirmations = hysteresis_confirmations

    def run_replay(
        self,
        df_test: pd.DataFrame,
        replay_run_id: Optional[str] = None,
        speed_multiplier: float = 0.0 # 0.0 means immediate batch simulation for testing
    ) -> Dict[str, Any]:
        """Runs the replay simulation over the test windows."""
        if not replay_run_id:
            replay_run_id = f"REP_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"

        state_machine = AlertStateMachine(
            watch_thresh=self.watch_thresh,
            warn_thresh=self.warn_thresh,
            crit_thresh=self.crit_thresh,
            confirmations=self.hysteresis_confirmations
        )

        # Sort chronologically
        df_sorted = df_test.sort_values("window_end").reset_index(drop=True)
        forecast_records = []

        X_test = np.nan_to_num(df_sorted[self.feature_cols].values, nan=0.0)
        raw_scores = self.model.predict_proba(X_test)[:, 1]
        calibrated_probs = self.calibrator.predict_proba(raw_scores)

        for i, row in df_sorted.iterrows():
            w_end = row["window_end"]
            raw_s = float(raw_scores[i])
            cal_p = float(calibrated_probs[i])
            actual_surge = bool(row.get(f"y_k{self.horizon_k}", 0) == 1)

            # Step state machine
            lvl, reason = state_machine.step(cal_p)

            rec = {
                "replay_run_id": replay_run_id,
                "model_version": self.model_version,
                "window_end": w_end if isinstance(w_end, datetime) else pd.to_datetime(w_end).to_pydatetime(),
                "raw_score": raw_s,
                "calibrated_prob": cal_p,
                "level": int(lvl),
                "level_reason": reason,
                "horizon_k": self.horizon_k,
                "actual_surge_in_horizon": actual_surge
            }
            forecast_records.append(rec)

            if speed_multiplier > 0:
                # Sleep small fraction to simulate stream
                time.sleep(0.01)

        # Aggregate alert episodes
        alert_episodes = aggregate_alert_episodes(forecast_records, replay_run_id, self.model_version)

        # Persist to PostgreSQL
        self._save_to_db(forecast_records, alert_episodes)

        return {
            "replay_run_id": replay_run_id,
            "model_version": self.model_version,
            "total_windows": len(forecast_records),
            "alert_episodes_count": len(alert_episodes),
            "forecasts": forecast_records,
            "episodes": alert_episodes
        }

    def _save_to_db(self, forecasts: List[Dict[str, Any]], episodes: List[Dict[str, Any]]):
        """Persists forecasts and episodes into net_forecast and net_alert_episode."""
        conn = psycopg2.connect(self.db_url)
        cur = conn.cursor()

        # Insert forecasts
        q_fc = """
        INSERT INTO net_forecast (
            replay_run_id, model_version, window_end, raw_score, calibrated_prob,
            level, level_reason, horizon_k, actual_surge_in_horizon
        ) VALUES %s
        ON CONFLICT (replay_run_id, model_version, window_end) DO UPDATE SET
            raw_score = EXCLUDED.raw_score,
            calibrated_prob = EXCLUDED.calibrated_prob,
            level = EXCLUDED.level,
            level_reason = EXCLUDED.level_reason;
        """
        fc_tuples = [
            (
                f["replay_run_id"], f["model_version"], f["window_end"],
                f["raw_score"], f["calibrated_prob"], f["level"],
                f["level_reason"], f["horizon_k"], f["actual_surge_in_horizon"]
            )
            for f in forecasts
        ]
        if fc_tuples:
            execute_values(cur, q_fc, fc_tuples, page_size=1000)

        # Insert episodes
        q_ep = """
        INSERT INTO net_alert_episode (
            episode_id, replay_run_id, model_version, max_level,
            start_window, end_window, peak_prob, status
        ) VALUES %s
        ON CONFLICT (episode_id) DO NOTHING;
        """
        ep_tuples = [
            (
                e["episode_id"], e["replay_run_id"], e["model_version"],
                e["max_level"], e["start_window"], e["end_window"],
                e["peak_prob"], e["status"]
            )
            for e in episodes
        ]
        if ep_tuples:
            execute_values(cur, q_ep, ep_tuples, page_size=100)

        conn.commit()
        cur.close()
        conn.close()
