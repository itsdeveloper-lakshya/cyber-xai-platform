"""
Text Feature Extractor (Section 9 C4 - 18 Text Features)
Generates numerical feature vector for the client-side logistic regression model.
Ported from module2/extension/shared/feature_extractor.js to ensure scorer parity (Test C-10).
"""

import math
from typing import List, Dict, Any, Set
import regex

class FeatureExtractor:
    @staticmethod
    def shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        length = len(s)
        freq: Dict[str, int] = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        entropy = 0.0
        for c, count in freq.items():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    @classmethod
    def highest_token_entropy(cls, text: str) -> float:
        tokens = [t for t in regex.split(r"\s+", text) if len(t) >= 20]
        if not tokens:
            return 0.0
        max_ent = 0.0
        for t in tokens:
            ent = cls.shannon_entropy(t)
            if ent > max_ent:
                max_ent = ent
        return max_ent

    @classmethod
    def extract(cls, text: str, regex_hits: List[Dict[str, Any]]) -> List[float]:
        total_chars = max(len(text), 1)
        lines = text.split("\n")
        num_lines = max(len(lines), 1)
        tokens = [t for t in regex.split(r"\s+", text.strip()) if t]
        total_tokens = max(len(tokens), 1)

        # 1. Log of character length
        f1_log_char_len = math.log(total_chars + 1)

        # 2. Log of line count
        f2_log_line_cnt = math.log(num_lines + 1)

        # 3. Digit ratio
        digits = len(regex.findall(r"\d", text))
        f3_digit_ratio = digits / total_chars

        # 4. Uppercase ratio
        upper = len(regex.findall(r"[A-Z]", text))
        f4_upper_ratio = upper / total_chars

        # 5. Punctuation / special character ratio
        punct = len(regex.findall(r"[^a-zA-Z0-9\s]", text))
        f5_punct_ratio = punct / total_chars

        # 6. Whitespace ratio
        whitespace = len(regex.findall(r"\s", text))
        f6_ws_ratio = whitespace / total_chars

        # 7. Shannon entropy of characters
        f7_entropy = cls.shannon_entropy(text)

        # 8. Highest token entropy (tokens >= 20 chars)
        f8_token_entropy = cls.highest_token_entropy(text)

        # 9. Average line length
        f9_avg_line_len = total_chars / num_lines

        # 10. Code symbol density ({}, ;, [], <>, => per character)
        code_symbols = len(regex.findall(r"[{}\;<>[\]=>]", text))
        f10_code_sym_density = code_symbols / total_chars

        # 11. Code keyword density
        code_keywords = len(regex.findall(
            r"\b(function|return|import|export|const|let|var|def|class|if|else|for|while|try|catch|async|await)\b",
            text
        ))
        f11_code_kw_density = code_keywords / total_tokens

        # 12. Delimiter consistency (share of lines matching most common delimiter count)
        f12_delim_consistency = 0.0
        if len(lines) > 1:
            comma_counts = [l.count(",") for l in lines]
            pipe_counts = [l.count("|") for l in lines]

            def check_mode_consistency(counts: List[int]) -> float:
                freq_map: Dict[int, int] = {}
                max_count = 0
                mode = 0
                for c in counts:
                    freq_map[c] = freq_map.get(c, 0) + 1
                    if freq_map[c] > max_count:
                        max_count = freq_map[c]
                        mode = c
                return (max_count / len(counts)) if mode > 0 else 0.0

            f12_delim_consistency = max(check_mode_consistency(comma_counts), check_mode_consistency(pipe_counts))

        # 13. Share of tokens that are numeric
        numeric_tokens = sum(1 for t in tokens if regex.match(r"^\d+(?:\.\d+)?$", t))
        f13_numeric_token_share = numeric_tokens / total_tokens

        # 14. Log of total regex hits
        f14_log_regex_hits = math.log(len(regex_hits) + 1)

        # 15. Highest weight among fired rules
        max_weight = 0.0
        for r in regex_hits:
            w = r.get("weight", 0.0)
            if w > max_weight:
                max_weight = w
        f15_max_rule_weight = max_weight

        # 16. Number of distinct rule categories fired
        categories = {r["category"] for r in regex_hits}
        f16_distinct_categories = float(len(categories))

        # 17. Count of emails plus phone numbers
        email_hits = len(regex.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text))
        phone_hits = len(regex.findall(r"(?:\+91)?[6-9]\d{9}", text))
        f17_emails_phones_count = float(email_hits + phone_hits)

        # 18. Confidentiality marker present (0 or 1)
        has_conf = bool(regex.search(r"confidential|internal only|do not distribute|proprietary", text, regex.IGNORECASE))
        f18_has_confidential_marker = 1.0 if has_conf else 0.0

        return [
            f1_log_char_len,
            f2_log_line_cnt,
            f3_digit_ratio,
            f4_upper_ratio,
            f5_punct_ratio,
            f6_ws_ratio,
            f7_entropy,
            f8_token_entropy,
            f9_avg_line_len,
            f10_code_sym_density,
            f11_code_kw_density,
            f12_delim_consistency,
            f13_numeric_token_share,
            f14_log_regex_hits,
            f15_max_rule_weight,
            f16_distinct_categories,
            f17_emails_phones_count,
            f18_has_confidential_marker
        ]
