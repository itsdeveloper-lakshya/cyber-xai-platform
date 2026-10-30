/**
 * Text Feature Extractor (Section 6.3 - 18 Text Features)
 * Generates numerical feature vector for the client-side logistic regression model.
 */

const FeatureExtractor = {
  // Shannon entropy of character distribution
  shannonEntropy: function(str) {
    if (!str || str.length === 0) return 0;
    const len = str.length;
    const freq = {};
    for (let i = 0; i < len; i++) {
      const c = str[i];
      freq[c] = (freq[c] || 0) + 1;
    }
    let entropy = 0;
    for (const c in freq) {
      const p = freq[c] / len;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  },

  // Highest token entropy for tokens >= 20 characters (detects base64/hex keys)
  highestTokenEntropy: function(text) {
    const tokens = text.split(/\s+/).filter(t => t.length >= 20);
    if (tokens.length === 0) return 0;
    let maxEnt = 0;
    for (const t of tokens) {
      const ent = this.shannonEntropy(t);
      if (ent > maxEnt) maxEnt = ent;
    }
    return maxEnt;
  },

  // Extract all 18 features defined in Section 6.3
  extract: function(text, regexHits = []) {
    const totalChars = Math.max(text.length, 1);
    const lines = text.split("\n");
    const numLines = Math.max(lines.length, 1);
    const tokens = text.trim().split(/\s+/).filter(t => t.length > 0);
    const totalTokens = Math.max(tokens.length, 1);

    // 1. Log of character length
    const f1_log_char_len = Math.log(totalChars + 1);

    // 2. Log of line count
    const f2_log_line_cnt = Math.log(numLines + 1);

    // 3. Digit ratio
    const digits = (text.match(/\d/g) || []).length;
    const f3_digit_ratio = digits / totalChars;

    // 4. Uppercase ratio
    const upper = (text.match(/[A-Z]/g) || []).length;
    const f4_upper_ratio = upper / totalChars;

    // 5. Punctuation / special character ratio
    const punct = (text.match(/[^a-zA-Z0-9\s]/g) || []).length;
    const f5_punct_ratio = punct / totalChars;

    // 6. Whitespace ratio
    const whitespace = (text.match(/\s/g) || []).length;
    const f6_ws_ratio = whitespace / totalChars;

    // 7. Shannon entropy of characters
    const f7_entropy = this.shannonEntropy(text);

    // 8. Highest token entropy (tokens >= 20 chars)
    const f8_token_entropy = this.highestTokenEntropy(text);

    // 9. Average line length
    const f9_avg_line_len = totalChars / numLines;

    // 10. Code symbol density ({}, ;, [], <>, => per character)
    const codeSymbols = (text.match(/[{};<>[\]=>]/g) || []).length;
    const f10_code_sym_density = codeSymbols / totalChars;

    // 11. Code keyword density
    const codeKeywords = (text.match(/\b(function|return|import|export|const|let|var|def|class|if|else|for|while|try|catch|async|await)\b/g) || []).length;
    const f11_code_kw_density = codeKeywords / totalTokens;

    // 12. Delimiter consistency (share of lines matching most common delimiter count)
    let f12_delim_consistency = 0;
    if (lines.length > 1) {
      const commaCounts = lines.map(l => (l.match(/,/g) || []).length);
      const pipeCounts = lines.map(l => (l.match(/\|/g) || []).length);
      const checkModeConsistency = (counts) => {
        const freqMap = {};
        let maxCount = 0;
        let mode = 0;
        for (const c of counts) {
          freqMap[c] = (freqMap[c] || 0) + 1;
          if (freqMap[c] > maxCount) {
            maxCount = freqMap[c];
            mode = c;
          }
        }
        return mode > 0 ? (maxCount / counts.length) : 0;
      };
      f12_delim_consistency = Math.max(checkModeConsistency(commaCounts), checkModeConsistency(pipeCounts));
    }

    // 13. Share of tokens that are numeric
    const numericTokens = tokens.filter(t => /^\d+(?:\.\d+)?$/.test(t)).length;
    const f13_numeric_token_share = numericTokens / totalTokens;

    // 14. Log of total regex hits
    const f14_log_regex_hits = Math.log(regexHits.length + 1);

    // 15. Highest weight among fired rules
    let maxWeight = 0;
    for (const r of regexHits) {
      if (r.weight > maxWeight) maxWeight = r.weight;
    }
    const f15_max_rule_weight = maxWeight;

    // 16. Number of distinct rule categories fired
    const categories = new Set(regexHits.map(r => r.category));
    const f16_distinct_categories = categories.size;

    // 17. Count of emails plus phone numbers
    const emailHits = (text.match(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g) || []).length;
    const phoneHits = (text.match(/(?:\+91)?[6-9]\d{9}/g) || []).length;
    const f17_emails_phones_count = emailHits + phoneHits;

    // 18. Confidentiality marker present (0 or 1)
    const f18_has_confidential_marker = /confidential|internal only|do not distribute|proprietary/i.test(text) ? 1.0 : 0.0;

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
    ];
  }
};

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { FeatureExtractor };
}
