"""
Client-Side Clipboard Scoring Engine (Section 9 C4 & Section 15 C-10)
Exact Python port of module2/extension/shared/scoring_engine.js.
Blends Regex Rule Score (60%) and Tiny Logistic Regression (40%).
Enforces Hard-Rule Floor >= 0.9.
Tier boundaries: 0.35 and 0.70.
"""

import json
import math
from pathlib import Path
from typing import Dict, Any, List, Optional
import regex

from .rules import REGEX_RULES, REGEX_TIMEOUT_SEC
from .feature_extractor import FeatureExtractor

DEFAULT_MODEL_PATH = Path(__file__).resolve().parent / "default_model.json"

class ScoringEngine:
    def __init__(self, model_config: Optional[Dict[str, Any]] = None):
        if model_config:
            self.model = model_config
        elif DEFAULT_MODEL_PATH.exists():
            with open(DEFAULT_MODEL_PATH, "r", encoding="utf-8") as f:
                self.model = json.load(f)
        else:
            self.model = {
                "weights": [0.35, 0.25, 0.85, 0.40, 0.65, -0.20, 0.75, 1.10, 0.15, 0.60, 0.50, 0.70, 0.80, 1.20, 1.40, 1.10, 0.90, 1.50],
                "means": [5.2, 1.8, 0.08, 0.06, 0.09, 0.16, 4.2, 1.2, 45.0, 0.02, 0.01, 0.1, 0.05, 0.2, 0.1, 0.2, 0.1, 0.05],
                "stds": [1.5, 1.2, 0.12, 0.08, 0.08, 0.07, 0.8, 1.5, 30.0, 0.04, 0.03, 0.3, 0.10, 0.6, 0.3, 0.5, 0.6, 0.22],
                "bias": -1.8,
                "suggested_thresholds": {"low": 0.35, "medium": 0.70}
            }

    def evaluate_rules(self, text: str) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        if not text or not isinstance(text, str):
            return hits

        for rule in REGEX_RULES:
            try:
                if rule.custom_check:
                    if rule.custom_check(text):
                        hits.append({
                            "id": rule.id,
                            "category": rule.category,
                            "weight": rule.weight,
                            "hard": rule.hard,
                            "match_count": 1
                        })
                elif rule.pattern:
                    matches = rule.pattern.findall(text, timeout=REGEX_TIMEOUT_SEC)
                    if matches:
                        valid_matches = matches
                        if rule.validator:
                            valid_matches = [m for m in matches if rule.validator(m)]

                        if valid_matches:
                            weight = rule.weight
                            if rule.count_scaled and len(valid_matches) >= 5:
                                weight = 0.5
                            hits.append({
                                "id": rule.id,
                                "category": rule.category,
                                "weight": weight,
                                "hard": rule.hard,
                                "match_count": len(valid_matches)
                            })
            except regex.error.TimeoutError:
                # Section 9 C4: Timeout counts as "unscored, treat as medium" and is logged without content
                hits.append({
                    "id": f"{rule.id}_TIMEOUT",
                    "category": "RegexTimeout",
                    "weight": 0.5,
                    "hard": False,
                    "match_count": 1
                })
        return hits

    @staticmethod
    def compute_regex_score(hits: List[Dict[str, Any]]) -> float:
        if not hits:
            return 0.0
        complement_product = 1.0
        for h in hits:
            complement_product *= (1.0 - h["weight"])
        score = 1.0 - complement_product
        return max(0.0, min(1.0, score))

    def compute_ml_score(self, features: List[float]) -> float:
        weights = self.model.get("weights", [])
        means = self.model.get("means", [])
        stds = self.model.get("stds", [])
        bias = self.model.get("bias", 0.0)

        if len(features) != len(weights):
            return 0.0

        z = bias
        for i in range(len(features)):
            m = means[i] if i < len(means) else 0.0
            s = stds[i] if i < len(stds) and stds[i] > 0 else 1.0
            std_feat = (features[i] - m) / s
            z += std_feat * weights[i]

        # Sigmoid
        try:
            return 1.0 / (1.0 + math.exp(-z))
        except OverflowError:
            return 1.0 if z > 0 else 0.0

    def score_text(self, text: str, max_bytes: int = 102400) -> Dict[str, Any]:
        """
        Main scoring function.
        Caps analyzed text at max_bytes (default 100 KB) and notes truncation.
        """
        is_truncated = False
        analyzed_text = text
        if text and len(text.encode("utf-8")) > max_bytes:
            # Safely slice text within max_bytes
            encoded = text.encode("utf-8")[:max_bytes]
            analyzed_text = encoded.decode("utf-8", errors="ignore")
            is_truncated = True

        hits = self.evaluate_rules(analyzed_text)
        has_hard_rule = any(h["hard"] for h in hits)
        regex_score = self.compute_regex_score(hits)

        features = FeatureExtractor.extract(analyzed_text, hits)
        ml_score = self.compute_ml_score(features)

        # Blend: final = 0.6 * regex_score + 0.4 * ml_score
        final_score = 0.6 * regex_score + 0.4 * ml_score

        # Hard rule floor: at least 0.9 if any hard rule fired
        if has_hard_rule and final_score < 0.9:
            final_score = 0.9

        # Determine risk tier
        if final_score >= 0.70:
            tier = "high"
        elif final_score >= 0.35:
            tier = "medium"
        else:
            tier = "low"

        categories = sorted(list({h["category"] for h in hits}))
        rule_ids = [h["id"] for h in hits]

        return {
            "regex_score": round(regex_score, 4),
            "ml_score": round(ml_score, 4),
            "final_score": round(final_score, 4),
            "risk_tier": tier,
            "matched_categories": categories,
            "matched_rule_ids": rule_ids,
            "has_hard_rule": has_hard_rule,
            "is_truncated": is_truncated
        }
