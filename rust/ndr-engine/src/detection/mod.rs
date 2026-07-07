// NDR Engine — Detection Engine
// License: Apache-2.0

mod sigma;
pub mod updater;
pub use sigma::{SigmaRule, DetectionMatch, load_rules_from_dir, parse_rule_content};
pub use updater::{spawn_sigma_updater, sync_now};

use crate::normalizer::NormalizedEvent;
use std::collections::{HashMap, HashSet};

pub struct DetectionEngine {
    rules: Vec<SigmaRule>,
    // Per-tenant disabled overrides for community rules.
    // Key = tenant_id, Value = set of rule IDs disabled by that tenant.
    // Empty set = no overrides (tenant sees all community rules).
    disabled_overrides: HashMap<String, HashSet<String>>,
}

impl DetectionEngine {
    pub fn new(_rules_dir: &str) -> Self {
        tracing::info!("Detection engine: starting empty, rules load from ClickHouse");
        Self { rules: Vec::new(), disabled_overrides: HashMap::new() }
    }

    /// Check an event against all loaded rules. Returns all matches.
    pub fn check(&self, event: &NormalizedEvent) -> Vec<DetectionMatch> {
        self.rules.iter()
            .filter_map(|rule| self.eval(rule, event))
            .collect()
    }

    /// Check rules for a specific tenant.
    /// Community rules (tenant_id="*") are included unless the tenant has
    /// overridden that rule to disabled in their rules_state.
    pub fn check_for_tenant(&self, event: &NormalizedEvent, tenant_id: &str) -> Vec<DetectionMatch> {
        let disabled = self.disabled_overrides.get(tenant_id);
        self.rules.iter()
            .filter(|rule| rule.tenant_id == "*" || rule.tenant_id == tenant_id)
            .filter(|rule| disabled.map_or(true, |d| !d.contains(&rule.id)))
            .filter_map(|rule| self.eval(rule, event))
            .collect()
    }

    fn eval(&self, rule: &SigmaRule, event: &NormalizedEvent) -> Option<DetectionMatch> {
        let matched = rule.condition_expr.eval(&rule.selections, event);
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
            "id":        r.id,
            "title":     r.title,
            "severity":  r.severity,
            "tags":      r.tags,
            "tenant_id": r.tenant_id,
            "logsource": {
                "product":  r.logsource.product,
                "category": r.logsource.category,
                "service":  r.logsource.service,
            },
            "conditions": r.conditions.len(),
        })).collect()
    }

pub fn set_rules(&mut self, rules: Vec<SigmaRule>, disabled: HashMap<String, HashSet<String>>) {
    tracing::info!("Rules updated: {} loaded, {} tenants with overrides", rules.len(), disabled.len());
    self.rules = rules;
    self.disabled_overrides = disabled;
}
}
