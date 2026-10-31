"""
Module 4 Step N14..N16: 4-Level Alert State Machine with Hysteresis & Cooldown
Implements:
1. Four alert levels:
   - 0: Normal (P < Watch)
   - 1: Watch (P >= Watch threshold)
   - 2: Warning (P >= Warning threshold)
   - 3: Critical (P >= Critical threshold AND rising trend over last 3 windows)
2. Hysteresis (anti-flicker state machine):
   - Level rises only after 2 consecutive confirmations at or above threshold.
   - Level drops only after 2 consecutive confirmations below threshold.
3. Alert Episode aggregation:
   - Continuous periods at Warning (2) or Critical (3) are aggregated into a single episode.
"""

import uuid
from typing import Dict, Any, List, Tuple
from datetime import datetime

class AlertStateMachine:
    def __init__(
        self,
        watch_thresh: float = 0.35,
        warn_thresh: float = 0.60,
        crit_thresh: float = 0.80,
        confirmations: int = 2
    ):
        self.watch_thresh = watch_thresh
        self.warn_thresh = warn_thresh
        self.crit_thresh = crit_thresh
        self.confirmations = confirmations

        self.current_level = 0
        self.prob_history: List[float] = []
        self.pending_level = 0
        self.pending_count = 0

    def _raw_target_level(self, prob: float) -> Tuple[int, str]:
        """Determines target level before hysteresis and trend conditions."""
        if prob < self.watch_thresh:
            return 0, "Normal probability"

        if prob < self.warn_thresh:
            return 1, f"Probability {prob:.3f} exceeds Watch threshold ({self.watch_thresh})"

        if prob < self.crit_thresh:
            return 2, f"Probability {prob:.3f} exceeds Warning threshold ({self.warn_thresh})"

        # Critical candidate: check rising-trend condition over last 3 windows (N14 & A-02)
        if len(self.prob_history) >= 2:
            p_prev1 = self.prob_history[-1]
            p_prev2 = self.prob_history[-2]
            # Must not have fallen AND must have positive increase (not flat)
            if (prob >= p_prev1 >= p_prev2) and (prob > p_prev2):
                return 3, f"Probability {prob:.3f} exceeds Critical ({self.crit_thresh}) with confirmed rising trend"

        # If flat or falling, hold at Warning
        return 2, f"Probability {prob:.3f} exceeds Critical ({self.crit_thresh}) but lacks rising trend, holding at Warning"

    def step(self, prob: float) -> Tuple[int, str]:
        """Steps the state machine with a new probability forecast."""
        target_lvl, raw_reason = self._raw_target_level(prob)

        if target_lvl == self.current_level:
            self.pending_level = self.current_level
            self.pending_count = 0
        elif target_lvl == self.pending_level:
            self.pending_count += 1
            if self.pending_count >= self.confirmations:
                self.current_level = target_lvl
                self.pending_count = 0
        else:
            self.pending_level = target_lvl
            self.pending_count = 1
            if self.pending_count >= self.confirmations:
                self.current_level = target_lvl
                self.pending_count = 0

        self.prob_history.append(prob)
        if len(self.prob_history) > 10:
            self.prob_history.pop(0)

        level_names = {0: "Normal", 1: "Watch", 2: "Warning", 3: "Critical"}
        reason = f"Level {level_names[self.current_level]} ({raw_reason})"
        return self.current_level, reason

def aggregate_alert_episodes(forecasts: List[Dict[str, Any]], replay_run_id: str, model_version: str) -> List[Dict[str, Any]]:
    """Aggregates continuous periods of Warning or Critical into single alert episodes."""
    episodes = []
    in_episode = False
    cur_ep: Dict[str, Any] = {}

    for f in forecasts:
        lvl = f["level"]
        prob = f["calibrated_prob"]
        w_end = f["window_end"]

        if lvl >= 2: # Warning or Critical
            if not in_episode:
                in_episode = True
                cur_ep = {
                    "episode_id": f"EP_NET_{uuid.uuid4().hex[:12].upper()}",
                    "replay_run_id": replay_run_id,
                    "model_version": model_version,
                    "max_level": lvl,
                    "start_window": w_end,
                    "end_window": w_end,
                    "peak_prob": prob,
                    "status": "closed"
                }
            else:
                cur_ep["max_level"] = max(cur_ep["max_level"], lvl)
                cur_ep["peak_prob"] = max(cur_ep["peak_prob"], prob)
                cur_ep["end_window"] = w_end
        else:
            if in_episode:
                episodes.append(cur_ep)
                in_episode = False
                cur_ep = {}

    if in_episode:
        episodes.append(cur_ep)

    return episodes
