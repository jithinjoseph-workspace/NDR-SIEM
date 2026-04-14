// NDR Engine — SIGMA-compatible Detection Rule Engine
// Lightweight fresh implementation — NOT based on any existing SIGMA codebase.
// Supports: equals, contains, startswith, endswith, re, AND/OR logic.
// License: Apache-2.0

use crate::normalizer::NormalizedEvent;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tracing::{info, warn};

// ── Rule types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSource {
    pub product:  Option<String>,
    pub category: Option<String>,
    pub service:  Option<String>,
}

#[derive(Debug, Clone)]
pub enum Matcher { Equals, Contains, StartsWith, EndsWith, Regex }

#[derive(Debug, Clone)]
pub struct FieldCondition {
    pub field:   String,
    pub matcher: Matcher,
    pub values:  Vec<String>, // OR within same field
    pub negated: bool,
}

impl FieldCondition {
    pub fn matches(&self, event: &NormalizedEvent) -> bool {
        let field_val = match event.get_field(&self.field) {
            Some(v) => v.to_lowercase(),
            None    => return self.negated,
        };
        let hit = self.values.iter().any(|val| {
            let v = val.to_lowercase();
            match &self.matcher {
                Matcher::Equals     => field_val == v,
                Matcher::Contains   => field_val.contains(&v),
                Matcher::StartsWith => field_val.starts_with(&v),
                Matcher::EndsWith   => field_val.ends_with(&v),
                Matcher::Regex      => Regex::new(val).map(|r| r.is_match(&field_val)).unwrap_or(false),
            }
        });
        if self.negated { !hit } else { hit }
    }
}

#[derive(Debug, Clone)]
pub enum Logic { And, Or }

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SigmaRule {
    pub id:          String,
    pub title:       String,
    pub severity:    String,
    pub tags:        Vec<String>,
    pub logsource:   LogSource,
    pub conditions:  Vec<FieldCondition>,
    pub logic:       Logic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionMatch {
    pub rule_id:  String,
    pub title:    String,
    pub severity: String,
    pub tags:     Vec<String>,
}

// ── Loader ────────────────────────────────────────────────────────────────

pub fn load_rules_from_dir(dir: impl AsRef<Path>) -> Vec<SigmaRule> {
    let mut rules = Vec::new();
    let dir = dir.as_ref();
    if !dir.exists() { return rules; }

    let Ok(entries) = std::fs::read_dir(dir) else { return rules; };

    for entry in entries.flatten() {
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext != "yml" && ext != "yaml" { continue; }

        match parse_rule_file(&path) {
            Ok(rule) => { info!("SIGMA rule loaded: {} [{}]", rule.title, rule.id); rules.push(rule); }
            Err(e)   => warn!("Failed to parse {:?}: {}", path, e),
        }
    }
    rules
}

fn parse_rule_file(path: &Path) -> anyhow::Result<SigmaRule> {
    let content = std::fs::read_to_string(path)?;
    let doc: HashMap<String, serde_yaml::Value> = serde_yaml::from_str(&content)?;

    let get_str = |k: &str| -> String {
        doc.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string()
    };

    let tags = doc.get("tags")
        .and_then(|v| v.as_sequence())
        .map(|s| s.iter().filter_map(|v| v.as_str()).map(String::from).collect())
        .unwrap_or_default();

    let logsource = doc.get("logsource")
        .and_then(|v| v.as_mapping())
        .map(|m| LogSource {
            product:  m.get("product").and_then(|v| v.as_str()).map(String::from),
            category: m.get("category").and_then(|v| v.as_str()).map(String::from),
            service:  m.get("service").and_then(|v| v.as_str()).map(String::from),
        })
        .unwrap_or(LogSource { product: None, category: None, service: None });

    let detection_val = doc.get("detection")
        .ok_or_else(|| anyhow::anyhow!("Missing 'detection' block"))?;

    let logic = detection_val.as_mapping()
        .and_then(|m| m.get("condition"))
        .and_then(|v| v.as_str())
        .map(|s| if s.contains("all") { Logic::And } else { Logic::Or })
        .unwrap_or(Logic::And);

    let mut conditions = Vec::new();
    if let Some(mapping) = detection_val.as_mapping() {
        for (key, val) in mapping {
            let key_str = key.as_str().unwrap_or("");
            if key_str == "condition" { continue; }
            if let Some(field_map) = val.as_mapping() {
                for (field_key, field_val) in field_map {
                    if let Some(fk) = field_key.as_str() {
                        parse_condition(fk, field_val, &mut conditions);
                    }
                }
            }
        }
    }

    Ok(SigmaRule {
        id: get_str("id"), title: get_str("title"),
        severity: get_str("level"), tags, logsource, conditions, logic,
    })
}

fn parse_condition(field_modifier: &str, value: &serde_yaml::Value, out: &mut Vec<FieldCondition>) {
    let parts: Vec<&str> = field_modifier.splitn(2, '|').collect();
    let field = parts[0].to_string();
    let modifier = parts.get(1).copied().unwrap_or("equals");
    let negated = modifier.ends_with("not");

    let matcher = match modifier.trim_end_matches("|not") {
        "contains"   => Matcher::Contains,
        "startswith" => Matcher::StartsWith,
        "endswith"   => Matcher::EndsWith,
        "re"         => Matcher::Regex,
        _            => Matcher::Equals,
    };

    let values: Vec<String> = match value {
        serde_yaml::Value::String(s)   => vec![s.clone()],
        serde_yaml::Value::Number(n)   => vec![n.to_string()],
        serde_yaml::Value::Sequence(s) =>
            s.iter().filter_map(|v| v.as_str()).map(String::from).collect(),
        _ => return,
    };

    if !values.is_empty() {
        out.push(FieldCondition { field, matcher, values, negated });
    }
}
