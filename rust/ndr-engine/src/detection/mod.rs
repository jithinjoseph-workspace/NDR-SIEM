// NDR Engine — Detection Engine
// License: Apache-2.0

mod sigma;
pub use sigma::{SigmaRule, DetectionMatch, load_rules_from_dir, parse_rule_content};

use crate::normalizer::NormalizedEvent;
use sigma::Logic;

pub struct DetectionEngine {
    rules: Vec<SigmaRule>,
}

impl DetectionEngine {
    pub fn new(rules_dir: &str) -> Self {
        let rules = load_rules_from_dir(rules_dir);
        tracing::info!("Detection engine: {} SIGMA rules loaded", rules.len());
        Self { rules }
    }

    /// Check an event against all loaded rules. Returns all matches.
    pub fn check(&self, event: &NormalizedEvent) -> Vec<DetectionMatch> {
        self.rules.iter()
            .filter_map(|rule| self.eval(rule, event))
            .collect()
    }

    fn eval(&self, rule: &SigmaRule, event: &NormalizedEvent) -> Option<DetectionMatch> {
        let matched = match rule.logic {
            Logic::And => rule.conditions.iter().all(|c| c.matches(event)),
            Logic::Or  => rule.conditions.iter().any(|c| c.matches(event)),
        };
        matched.then(|| DetectionMatch {
            rule_id:  rule.id.clone(),
            title:    rule.title.clone(),
            severity: rule.severity.clone(),
            tags:     rule.tags.clone(),
        })
    }

    pub fn rule_count(&self) -> usize { self.rules.len() }
   pub fn get_rules(&self) -> Vec<serde_json::Value> {
    self.rules.iter().map(|r| serde_json::json!({
        "id":       r.id,
        "title":    r.title,
        "severity": r.severity,
        "tags":     r.tags,
        "logsource": {
            "product":  r.logsource.product,
            "category": r.logsource.category,
            "service":  r.logsource.service,
        },
        "conditions": r.conditions.len(),
    })).collect()
}

pub fn set_rules(&mut self, rules: Vec<SigmaRule>) {
    tracing::info!("Rules updated: {} loaded", rules.len());
    self.rules = rules;
}
}
