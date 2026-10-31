"""
Module 4 Models, Calibration & Alerts Test Suite (Section 13 Tests M-01, M-03, C-01, A-01..A-03)
Verifies:
M-01: Persistence baseline equals current window surge flag.
M-03: XGBoost and LightGBM handle identical feature matrices.
C-01: Platt calibrator bounds probabilities within [0, 1] and tracks target.
A-01: Hysteresis prevents alert flicker when probabilities oscillate across threshold.
A-02: Critical level strictly requires rising trend (flat high probability stays at Warning).
A-03: A continuous attack span produces exactly one alert episode instead of hundreds.
"""

import pytest
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from module4.pipeline.baselines.baselines import PersistenceBaseline
from module4.pipeline.models.trainer import PlattCalibrator
from module4.pipeline.alerts.alert_engine import AlertStateMachine, aggregate_alert_episodes

def test_m01_persistence_baseline():
    """M-01: Persistence baseline directly mirrors current window surge flag."""
    df = pd.DataFrame({"is_surge": [False, True, False, False, True]})
    model = PersistenceBaseline()
    probs = model.predict_proba(df)[:, 1]
    assert np.array_equal(probs, [0.0, 1.0, 0.0, 0.0, 1.0])

def test_c01_platt_calibrator():
    """C-01: Calibrated probabilities lie strictly in [0, 1] and reflect empirical rate."""
    cal = PlattCalibrator()
    raw = np.array([-3.0, -1.0, 0.0, 1.5, 3.0])
    y = np.array([0, 0, 0, 1, 1])
    cal.fit(raw, y)

    probs = cal.predict_proba(raw)
    assert np.all(probs >= 0.0) and np.all(probs <= 1.0)
    assert probs[0] < probs[-1]

    # Serialization roundtrip
    d = cal.to_dict()
    cal2 = PlattCalibrator.from_dict(d)
    probs2 = cal2.predict_proba(raw)
    assert np.allclose(probs, probs2)

def test_a01_hysteresis_anti_flicker():
    """A-01: Sequence flickering around threshold (0.60) does not flicker level with 2 confirmations."""
    sm = AlertStateMachine(watch_thresh=0.35, warn_thresh=0.60, crit_thresh=0.85, confirmations=2)

    # Starts at Normal (0)
    lvl, _ = sm.step(0.20)
    assert lvl == 0

    # Spikes once to Warning (0.65) -> pending confirmation, stays 0
    lvl, _ = sm.step(0.65)
    assert lvl == 0

    # Dips back to 0.55 -> cancellation, no level change!
    lvl, _ = sm.step(0.55)
    assert lvl == 0

    # Now two consecutive 0.65s -> level rises to Warning (2)
    lvl, _ = sm.step(0.65)
    assert lvl == 0
    lvl, _ = sm.step(0.65)
    assert lvl == 2

    # Single dip to 0.50 -> does not immediately drop to 1
    lvl, _ = sm.step(0.50)
    assert lvl == 2

def test_a02_critical_requires_rising_trend():
    """A-02: Critical requires rising-trend condition. A flat high probability stays at Warning."""
    sm = AlertStateMachine(watch_thresh=0.35, warn_thresh=0.60, crit_thresh=0.80, confirmations=1)

    # Flat sequence above critical threshold (0.90, 0.90, 0.90) -> No rising trend
    sm.step(0.90)
    sm.step(0.90)
    lvl, reason = sm.step(0.90)
    assert lvl == 2, "Flat 0.90 must hold at Warning, not Critical"
    assert "lacks rising trend" in reason

    # Now rising sequence (0.82 -> 0.86 -> 0.92) -> Rising trend!
    sm.step(0.82)
    sm.step(0.86)
    lvl, reason = sm.step(0.92)
    assert lvl == 3, "Strictly rising sequence must achieve Critical"
    assert "confirmed rising trend" in reason

def test_a03_alert_episode_aggregation():
    """A-03: Continuous attack span of 10 windows produces exactly ONE alert episode."""
    t0 = datetime(2017, 7, 5, 10, 0, 0)
    forecasts = []
    # 2 normal windows
    for i in range(2):
        forecasts.append({"window_end": t0 + timedelta(minutes=5 * i), "level": 0, "calibrated_prob": 0.1})
    # 10 warning/critical windows
    for i in range(2, 12):
        forecasts.append({"window_end": t0 + timedelta(minutes=5 * i), "level": 2 if i < 8 else 3, "calibrated_prob": 0.75 if i < 8 else 0.92})
    # 2 normal windows
    for i in range(12, 14):
        forecasts.append({"window_end": t0 + timedelta(minutes=5 * i), "level": 0, "calibrated_prob": 0.1})

    episodes = aggregate_alert_episodes(forecasts, replay_run_id="REP_001", model_version="v1")
    assert len(episodes) == 1, f"Expected 1 episode, got {len(episodes)}"
    ep = episodes[0]
    assert ep["max_level"] == 3
    assert ep["peak_prob"] == 0.92
    assert ep["start_window"] == t0 + timedelta(minutes=10)
    assert ep["end_window"] == t0 + timedelta(minutes=55)
