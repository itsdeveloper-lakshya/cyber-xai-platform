/**
 * Client-Side Scoring Engine (Section 6.2 & 6.3)
 * Blends Regex Rule Probability (60%) and Tiny Logistic Regression (40%).
 * Enforces Hard-Rule Floor >= 0.9.
 */

const ScoringEngine = {
  // Evaluates all catalog regex rules against the input text
  evaluateRules: function(text) {
    const hits = [];
    if (!text || typeof text !== 'string') return hits;

    for (const rule of REGEX_RULES) {
      if (rule.customCheck) {
        if (rule.customCheck(text)) {
          hits.push({
            id: rule.id,
            category: rule.category,
            weight: rule.weight,
            hard: !!rule.hard
          });
        }
      } else if (rule.pattern) {
        // Reset regex state
        rule.pattern.lastIndex = 0;
        const matches = text.match(rule.pattern);
        if (matches && matches.length > 0) {
          // If validator function exists, verify matches
          let validMatches = matches;
          if (rule.validator) {
            validMatches = matches.filter(m => rule.validator(m));
          }

          if (validMatches.length > 0) {
            let weight = rule.weight;
            if (rule.countScaled && validMatches.length >= 5) {
              weight = 0.5; // Scale up for 5+ hits
            }
            hits.push({
              id: rule.id,
              category: rule.category,
              weight: weight,
              hard: !!rule.hard,
              matchCount: validMatches.length
            });
          }
        }
      }
    }
    return hits;
  },

  // Combine rule weights: 1 - product(1 - weight)
  computeRegexScore: function(hits) {
    if (hits.length === 0) return 0;
    let complementProduct = 1.0;
    for (const hit of hits) {
      complementProduct *= (1.0 - hit.weight);
    }
    return Math.min(Math.max(1.0 - complementProduct, 0), 1.0);
  },

  // Evaluate logistic regression on standardized features
  computeMLScore: function(features, model) {
    if (!model || !model.weights || features.length !== model.weights.length) {
      return 0;
    }
    let z = model.bias || 0;
    for (let i = 0; i < features.length; i++) {
      const mean = model.means[i] || 0;
      const std = model.stds[i] || 1;
      const standardized = (features[i] - mean) / (std > 0 ? std : 1);
      z += standardized * model.weights[i];
    }
    // Sigmoid function
    return 1.0 / (1.0 + Math.exp(-z));
  },

  // Master scoring function
  scoreText: function(text, modelConfig) {
    const hits = this.evaluateRules(text);
    const hasHardRule = hits.some(h => h.hard);
    const regexScore = this.computeRegexScore(hits);

    let mlScore = 0;
    if (typeof FeatureExtractor !== 'undefined' && modelConfig) {
      const features = FeatureExtractor.extract(text, hits);
      mlScore = this.computeMLScore(features, modelConfig);
    }

    // Blend: final = 0.6 * regex_score + 0.4 * ml_score
    let finalScore = 0.6 * regexScore + 0.4 * mlScore;

    // Hard rule floor: at least 0.9 if any hard rule fired
    if (hasHardRule && finalScore < 0.9) {
      finalScore = 0.9;
    }

    // Determine risk tier
    let tier = "low";
    let action = "logged";
    if (finalScore >= 0.70) {
      tier = "high";
      action = "blocked";
    } else if (finalScore >= 0.35) {
      tier = "medium";
      action = "warned";
    }

    return {
      regexScore: parseFloat(regexScore.toFixed(4)),
      mlScore: parseFloat(mlScore.toFixed(4)),
      finalScore: parseFloat(finalScore.toFixed(4)),
      riskTier: tier,
      action: action,
      matchedCategories: [...new Set(hits.map(h => h.category))],
      matchedRuleIds: hits.map(h => h.id),
      hasHardRule: hasHardRule
    };
  }
};

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { ScoringEngine };
}
