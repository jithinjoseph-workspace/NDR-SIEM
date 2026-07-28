// NDR Engine — Detection Engine
// License: Apache-2.0

mod sigma;
pub mod updater;
pub mod multiflow;
pub use sigma::{SigmaRule, DetectionMatch, parse_rule_content};
pub use updater::{spawn_sigma_updater, sync_now};

use crate::normalizer::{NormalizedEvent, EventSource};
use crate::detection::sigma::LogSource;
use std::collections::{HashMap, HashSet};

/// Returns true if a Sigma rule's logsource is compatible with the event.
/// Rules with no logsource constraints always match.
/// Windows / sysmon rules are skipped for Zeek/Suricata events (and vice-versa).
fn logsource_matches(ls: &LogSource, event: &NormalizedEvent) -> bool {
    // If no constraints, rule is universal
    let has_constraint = ls.product.is_some() || ls.category.is_some() || ls.service.is_some();
    if !has_constraint { return true; }

    let product  = ls.product.as_deref().unwrap_or("").to_lowercase();
    let category = ls.category.as_deref().unwrap_or("").to_lowercase();
    let service  = ls.service.as_deref().unwrap_or("").to_lowercase();

    match &event.event_source {
        EventSource::Zeek => {
            // Windows / endpoint-only rules don't apply to Zeek network events
            if matches!(product.as_str(), "windows" | "macos" | "linux" | "azure" | "okta" | "aws") {
                return false;
            }
            // Service field narrows to a specific Zeek log type (rdp, ssl, dns, http, …).
            // Must be checked BEFORE the category early-return so rules with
            // `service: rdp` don't accidentally fire on every Zeek event.
            if !service.is_empty() {
                let log_src = event.log_source.as_deref().unwrap_or("");
                return service == log_src || service == "zeek";
            }
            // Network-specific categories always apply to Zeek (only when no service filter)
            if matches!(category.as_str(), "network_connection" | "dns" | "proxy" | "firewall" | "webserver") {
                return true;
            }
            // No category and no service → generic Zeek network rule, matches all Zeek events
            if category.is_empty() {
                return true;
            }
            false
        }
        EventSource::Suricata => {
            // Issue 3 fix: linux endpoint rules use auditd/sysmon fields that
            // don't exist on Suricata network events — block them to skip wasted eval.
            if matches!(product.as_str(), "windows" | "macos" | "linux" | "azure" | "okta" | "aws") {
                return false;
            }
            true
        }
        EventSource::Linux => {
            // Linux auditd rules must specify linux or be universal
            if product == "windows" || product == "macos" { return false; }
            if product == "linux" || product.is_empty() { return true; }
            // Sysmon-for-linux category rules
            if category == "process_creation" || category == "network_connection" { return true; }
            false
        }
        EventSource::Unknown => true,
    }
}

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
            .filter(|rule| logsource_matches(&rule.logsource, event))
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
