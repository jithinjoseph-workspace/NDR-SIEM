// NDR Engine — API Routes and Handlers
// License: Apache-2.0

pub mod websocket;

use crate::correlator::{CorrelationEngine, CorrelationHit};
use crate::detection::DetectionEngine;
use crate::enrichment::EnrichmentPipeline;
use crate::normalizer::NormalizedEvent;
use crate::scoring::{conn_state_description, RiskScorer};
use crate::storage::SqliteStorage;
use crate::storage::ClickhouseStorage;
use axum::{extract::State, Json, http::StatusCode};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{info, warn};
use std::env;

fn agent_url() -> String {
    env::var("NDR_AGENT_URL")
        .unwrap_or_else(|_| "http://172.25.86.150:3001".to_string())
}

#[derive(serde::Deserialize)]
pub struct TogglePayload {
    pub enabled: bool,
}


// ── Shared application state ──────────────────────────────────────────────




#[derive(Clone)]
pub struct AppState {
    pub correlator: Arc<CorrelationEngine>,
    pub enrichment: Arc<EnrichmentPipeline>,
    pub scorer:     Arc<RiskScorer>,
    pub detection:  Arc<tokio::sync::RwLock<DetectionEngine>>,
    pub storage:    Arc<SqliteStorage>,
    pub ch_storage:  Arc<ClickhouseStorage>,
    pub tx:         broadcast::Sender<String>, // broadcasts to all WS clients
}


pub fn broadcast_raw_event(state: &AppState, event: &NormalizedEvent) {
    let src = event.source_ip.as_deref().unwrap_or("-");
    let dst = event.dest_ip.as_deref().unwrap_or("-");

    let msg = match event.event_source {
        crate::normalizer::EventSource::Zeek => {
            let cs       = event.conn_state.as_deref().unwrap_or("-");
            let cs_desc  = conn_state_description(cs);
            let svc      = event.network_protocol.as_deref().unwrap_or("-");
            let proto    = event.proto.as_deref().unwrap_or("-");
            info!("🟢 Zeek {} | {}→{} [{}] {} | CID: {}",
                svc, src, dst, proto, cs,
                event.community_id.as_deref().unwrap_or("?"));
            json!({
                "type": "zeek",
                "cid":  event.community_id,
                "src":  src, "dst": dst,
                "proto": event.proto,
                "service": event.network_protocol,
                "conn_state": event.conn_state,
                "conn_state_desc": cs_desc,
                "raw": event.raw,
            })
        }
        crate::normalizer::EventSource::Suricata => {
            let et = event.event_type.as_deref().unwrap_or("-");
            info!("🔵 Suricata {} | {}→{} | CID: {}",
                et, src, dst, event.community_id.as_deref().unwrap_or("?"));
            json!({
                "type": "suricata",
                "event_type": et,
                "cid":  event.community_id,
                "src":  src, "dst": dst,
                "raw": event.raw,
            })
        }
        _ => return,
    };

    let _ = state.tx.send(msg.to_string());
}


//network map
pub async fn get_network_map(State(state): State<AppState>) -> Json<Value> {
    match state.ch_storage.get_network_map().await {
        Ok(data) => Json(data),
        Err(_) => Json(json!({"nodes": [], "edges": []}))
    }
}

pub async fn process_correlation_hit(state: &AppState, hit: CorrelationHit) {
    let src = hit.suricata.source_ip.as_deref()
        .or(hit.zeek.source_ip.as_deref()).unwrap_or("-");
    let dst = hit.suricata.dest_ip.as_deref()
        .or(hit.zeek.dest_ip.as_deref()).unwrap_or("-");

    // Enrich
    let enrichment = state.enrichment.enrich(src, dst);

    // Score
    let risk = state.scorer.score(&hit, enrichment.is_malicious, enrichment.sensitive_country);

    // SIGMA detection on both sides
let mut detections = state.detection.read().await.check(&hit.zeek);
detections.extend(state.detection.read().await.check(&hit.suricata));

    let cs      = hit.zeek.conn_state.as_deref().unwrap_or("-");
    let cs_desc = conn_state_description(cs);

    // Console output
    println!("\n╔════════════════════════════════════════════════════════════╗");
    println!("║                     🔥 CORRELATION HIT                     ║");
    println!("╠════════════════════════════════════════════════════════════╣");
    println!("║ {} [score={:.0}/100]", risk.severity.as_str(), risk.score);
    println!("║ CID      : {}", hit.community_id);
    println!("║ Flow     : {} → {}", src, dst);
    println!("║ State    : {} ({})", cs, cs_desc);
    println!("║ Tags     : {}", risk.tags.join(", "));
    if !risk.reasons.is_empty() {
        println!("║ Reasons  : {}", risk.reasons.join(" | "));
    }
    if !detections.is_empty() {
        println!("║ SIGMA    : {}", detections.iter().map(|d| d.title.as_str()).collect::<Vec<_>>().join(", "));
    }
    println!("╚════════════════════════════════════════════════════════════╝\n");

    // Persist to SQLite
    if let Err(e) = state.storage.store_hit(&hit, &risk, &detections, &enrichment) {
        warn!("Storage error: {}", e);
    }

    // Persist to ClickHouse
    let ch = state.ch_storage.clone();
    let ch_hit = crate::storage::clickhouse::NdrHit {
    timestamp:    chrono::Utc::now().timestamp() as u32,
    community_id: hit.community_id.clone(),
    src_ip:       src.to_string(),
    dst_ip:       dst.to_string(),
    score:        risk.score as f32,
    severity:     risk.severity.as_str().to_string(),
    tags:         risk.tags.clone(),
    sigma_hits: {let mut seen = std::collections::HashSet::new();detections.iter().map(|d| d.title.clone()).filter(|t| seen.insert(t.clone())).collect()},  
    threat_intel: enrichment.is_malicious as u8,
    src_country:  enrichment.src_geo.as_ref()
                    .map(|g| g.country_code.clone())
                    .unwrap_or_default(),
    dst_country:  enrichment.dst_geo.as_ref()
                    .map(|g| g.country_code.clone())
                    .unwrap_or_default(),
    };
    tokio::spawn(async move {
        if let Err(e) = ch.insert_hit(ch_hit).await {
            tracing::warn!("ClickHouse hit insert error: {}", e);
        }
    });
    // Build WebSocket hit message
    let sigma_hits: Vec<String> = {
        let mut seen = std::collections::HashSet::new();
        detections.iter()
            .map(|d| d.title.clone())
            .filter(|t| seen.insert(t.clone()))
            .collect()
    };
    let hit_msg = json!({
        "type":            "hit",
        "cid":             hit.community_id,
        "event_type":      hit.suricata.event_type,
        "score":           risk.score,
        "severity":        risk.severity.as_str(),
        "severity_colour": risk.severity.colour(),
        "tags":            risk.tags,
        "reasons":         risk.reasons,
        "threat_intel":    enrichment.is_malicious,
        "direction":       enrichment.direction,
        "src_country":     enrichment.src_geo.as_ref().map(|g| &g.country_code),
        "dst_country":     enrichment.dst_geo.as_ref().map(|g| &g.country_code),
        "src_asn":         enrichment.src_asn.as_ref().map(|a| &a.full),
        "dst_asn":         enrichment.dst_asn.as_ref().map(|a| &a.full),
        "sigma_hits":      sigma_hits,
        "suricata": {
            "src": hit.suricata.source_ip, "src_port": hit.suricata.source_port,
            "dst": hit.suricata.dest_ip,   "dst_port": hit.suricata.dest_port,
        },
        "zeek": {
            "src": hit.zeek.source_ip, "dst": hit.zeek.dest_ip,
            "proto":            hit.zeek.proto,
            "service":          hit.zeek.network_protocol,
            "conn_state":       hit.zeek.conn_state,
            "conn_state_desc":  cs_desc,
        },
    });
    let _ = state.tx.send(hit_msg.to_string());
}

// ── GET /health ───────────────────────────────────────────────────────────

pub async fn health(State(state): State<AppState>) -> Json<Value> {
    let ch_stats = state.ch_storage.get_stats().await.unwrap_or(json!({}));

    // Get all service status from agent
    let agent_url = std::env::var("NDR_AGENT_URL")
        .unwrap_or_else(|_| "http://localhost:3001".to_string());
    
    let services = match reqwest::get(
        format!("{}/agent/status", agent_url)
    ).await {
        Ok(resp) => resp.json::<serde_json::Value>().await
            .unwrap_or(json!({})),
        Err(_) => json!({})
    };

    Json(json!({
        "status":          "ok",
        "sessions":        state.correlator.session_count(),
        "sigma_rules":     state.detection.read().await.rule_count(),
        "events_total":    ch_stats.get("events_total").and_then(|v| v.as_u64()).unwrap_or(0),
        "hits_total":      ch_stats.get("hits_total").and_then(|v| v.as_u64()).unwrap_or(0),
        "events_1h":       ch_stats.get("events_1h").and_then(|v| v.as_u64()).unwrap_or(0),
        "zeek_events":     ch_stats.get("zeek_events").and_then(|v| v.as_u64()).unwrap_or(0),
        "suricata_events": ch_stats.get("suricata_events").and_then(|v| v.as_u64()).unwrap_or(0),
        "services": {
            "zeek":       services.get("zeek").and_then(|v| v.as_str()).unwrap_or("unknown"),
            "suricata":   services.get("suricata").and_then(|v| v.as_str()).unwrap_or("unknown"),
            "vector":     services.get("vector").and_then(|v| v.as_str()).unwrap_or("unknown"),
            "kafka":      services.get("kafka").and_then(|v| v.as_str()).unwrap_or("unknown"),
            "clickhouse": services.get("clickhouse").and_then(|v| v.as_str()).unwrap_or("unknown"),
            "engine":     "running",
        }
    }))
}
// ── Interface Management ──────────────────────────────────────────────────

pub async fn get_interfaces() -> Json<Value> {
    let url = format!("{}/agent/interfaces", agent_url());
    match reqwest::get(&url).await {
        Ok(resp) => {
            let data: Value = resp.json().await.unwrap_or(json!([]));
            Json(data)
        }
        Err(_) => Json(json!([])),
    }
}
 



//get interface
pub async fn get_interface() -> Json<Value> {
    let url = format!("{}/agent/status", agent_url());
    match reqwest::get(&url).await {
        Ok(resp) => {
            let data: Value = resp.json().await.unwrap_or(json!({ "interface": "eth0" }));
            Json(json!({ "interface": data.get("interface").and_then(|v| v.as_str()).unwrap_or("eth0") }))
        }
        Err(_) => Json(json!({ "interface": "eth0" })),
    }
}

pub async fn set_interface(Json(payload): Json<Value>) -> StatusCode {
    let url = format!("{}/agent/interface", agent_url());
    match reqwest::Client::new().post(&url).json(&payload).send().await {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::BAD_GATEWAY,
    }
}

// ── Service Control ───────────────────────────────────────────────────────

pub async fn start_services() -> Json<Value> {
    let url = format!("{}/agent/start", agent_url());
    match reqwest::Client::new().post(&url).send().await {
        Ok(resp) => {
            let data: Value = resp.json().await
                .unwrap_or(json!({"status": "started"}));
            Json(data)
        }
        Err(e) => Json(json!({"status": "error", "message": e.to_string()})),
    }
}

pub async fn stop_services() -> Json<Value> {
    let url = format!("{}/agent/stop", agent_url());
    match reqwest::Client::new().post(&url).send().await {
        Ok(resp) => {
            let data: Value = resp.json().await
                .unwrap_or(json!({"status": "stopped"}));
            Json(data)
        }
        Err(e) => Json(json!({"status": "error", "message": e.to_string()})),
    }
}

//agent status 

pub async fn get_agent_status() -> Json<Value> {
    let url = format!("{}/agent/status", agent_url());
    match reqwest::get(&url).await {
        Ok(resp) => {
            let data: Value = resp.json().await.unwrap_or(json!({
                "zeek": "stopped",
                "suricata": "stopped",
                "vector": "stopped",
                "interface": "eth0"
            }));
            Json(data)
        }
        Err(_) => Json(json!({
            "zeek": "stopped",
            "suricata": "stopped",
            "vector": "stopped",
            "interface": "eth0"
        }))
    }
}

// ── ClickHouse API endpoints ──────────────────────────────────────────────

pub async fn get_stats(State(state): State<AppState>) -> Json<Value> {
    match state.ch_storage.get_stats().await {
        Ok(stats) => Json(stats),
        Err(e) => {
            tracing::warn!("Stats query error: {}", e);
            Json(json!({
                "events_total": 0,
                "hits_total": 0,
                "events_1h": 0,
                "hits_1h": 0,
                "zeek_events": 0,
                "suricata_events": 0,
            }))
        }
    }
}

pub async fn get_recent_events(State(state): State<AppState>) -> Json<Value> {
    match state.ch_storage.get_recent_events(50).await {
        Ok(events) => Json(json!(events)),
        Err(e) => {
            tracing::warn!("Recent events query error: {}", e);
            Json(json!([]))
        }
    }
}

pub async fn get_top_ips(State(state): State<AppState>) -> Json<Value> {
    let src = state.ch_storage.get_top_src_ips(10).await.unwrap_or_default();
    let dst = state.ch_storage.get_top_dst_ips(10).await.unwrap_or_default();
    Json(json!({
        "top_src_ips": src,
        "top_dst_ips": dst,
    }))
}


pub async fn get_hits(State(state): State<AppState>) -> Json<Value> {
    match state.ch_storage.get_recent_hits(50).await {
        Ok(hits) => Json(json!(hits)),
        Err(e) => {
            tracing::warn!("Hits query error: {}", e);
            Json(json!([]))
        }
    }
}

pub async fn get_rule_by_id(
    axum::extract::Path(rule_id): axum::extract::Path<String>,
) -> Json<Value> {
    let rules_dir = std::env::var("RULES_DIR")
        .unwrap_or_else(|_| "rules".to_string());
    let file_path = format!("{}/{}.yml", rules_dir, rule_id);

    match std::fs::read_to_string(&file_path) {
        Ok(content) => {
            // Parse YAML to extract fields
            let doc: std::collections::HashMap<String, serde_yaml::Value> =
                serde_yaml::from_str(&content).unwrap_or_default();

            let get_str = |k: &str| -> String {
                doc.get(k).and_then(|v| v.as_str())
                    .unwrap_or("").to_string()
            };

            // Extract detection field/matcher/value
            let mut field = String::new();
            let mut matcher = String::new();
            let mut value = String::new();

            if let Some(detection) = doc.get("detection")
                .and_then(|v| v.as_mapping()) {
                for (k, v) in detection {
                    let key = k.as_str().unwrap_or("");
                    if key == "condition" { continue; }
                    if let Some(field_map) = v.as_mapping() {
                        for (fk, fv) in field_map {
                            let fk_str = fk.as_str().unwrap_or("");
                            let parts: Vec<&str> = fk_str.splitn(2, '|').collect();
                            field   = parts[0].to_string();
                            matcher = parts.get(1).unwrap_or(&"equals").to_string();
                            value   = match fv {
                                serde_yaml::Value::String(s) => s.clone(),
                                serde_yaml::Value::Sequence(s) => s.first()
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("").to_string(),
                                _ => String::new(),
                            };
                        }
                    }
                }
            }

            Json(json!({
                "id":          get_str("id"),
                "title":       get_str("title"),
                "severity":    get_str("level"),
                "description": get_str("description"),
                "field":       field,
                "matcher":     matcher,
                "value":       value,
                "tags":        doc.get("tags")
                    .and_then(|v| v.as_sequence())
                    .map(|s| s.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>())
                    .unwrap_or_default(),
            }))
        }
        Err(_) => Json(json!({
            "error": "Rule not found"
        }))
    }
}

//rules endpoint
pub async fn get_rules(State(state): State<AppState>) -> Json<Value> {
    Json(json!(state.detection.read().await.get_rules()))
}

pub async fn get_threat_intel(State(state): State<AppState>) -> Json<Value> {
    // Get malicious IPs detected in our network from ClickHouse
    let detected = state.ch_storage.get_threat_intel_hits().await
        .unwrap_or_default();

    Json(json!({
        "total_malicious_ips": state.enrichment.threat_intel.count(),
        "source": "abuse.ch Feodo Tracker",
        "url": "https://feodotracker.abuse.ch",
        "detected_in_network": detected,
        "last_refresh": "Every 60 minutes",
    }))
}

pub async fn lookup_ioc(
    State(state): State<AppState>,
    axum::extract::Path(ip): axum::extract::Path<String>,
) -> Json<Value> {
    let is_malicious = state.enrichment.threat_intel.is_malicious(&ip);
    Json(json!({
        "ip":           ip,
        "is_malicious": is_malicious,
        "source":       "abuse.ch Feodo Tracker",
    }))
}



// auto reload rules 
pub async fn reload_rules_api(
    State(state): State<AppState>
) -> Json<Value> {
    let rules_dir = std::env::var("RULES_DIR")
        .unwrap_or_else(|_| "rules".to_string());

    // Get disabled rules from ClickHouse
    let disabled = state.ch_storage
        .get_disabled_rules().await
        .unwrap_or_default();

    let all_rules = crate::detection::load_rules_from_dir(&rules_dir);
    let total = all_rules.len();
    let active = all_rules.into_iter()
        .filter(|r| !disabled.contains(&r.id))
        .collect::<Vec<_>>();
    let count = active.len();

    state.detection.write().await.set_rules(active);
    tracing::info!("Hot-reloaded {} / {} SIGMA rules", count, total);

    Json(json!({
        "status":        "reloaded",
        "count":         count,
        "total":         total,
        "disabled":      disabled.len(),
        "message":       "Rules reloaded successfully"
    }))
}


// ── SIGMA Rules CRUD ──────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct NewRule {
    pub title:       String,
    pub severity:    String,
    pub description: Option<String>,
    pub tags:        Option<Vec<String>>,
    pub field:       String,
    pub value:       String,
    pub matcher:     Option<String>,
}

pub async fn create_rule(
    State(_state): State<AppState>,
    Json(payload): Json<NewRule>
) -> Json<Value> {
    let id = format!("ndr-{}", chrono::Utc::now().timestamp());
    let tags = payload.tags.unwrap_or_default();
    let matcher = payload.matcher.unwrap_or_else(|| "contains".to_string());
    let description = payload.description.unwrap_or_default();

    // Build SIGMA YAML
    let yaml = format!(
r#"id: {id}
title: {title}
description: {description}
level: {severity}
tags:{tags_str}
logsource:
  product: ndr
detection:
  keywords:
    {field}|{matcher}:
      - '{value}'
  condition: keywords
"#,
        id = id,
        title = payload.title,
        description = description,
        severity = payload.severity,
        tags_str = if tags.is_empty() {
            "\n  []".to_string()
        } else {
            tags.iter().map(|t| format!("\n  - {}", t)).collect::<String>()
        },
        field = payload.field,
        matcher = matcher,
        value = payload.value,
    );

    // Write to rules directory
    let rules_dir = std::env::var("RULES_DIR")
        .unwrap_or_else(|_| "rules".to_string());
    let file_path = format!("{}/{}.yml", rules_dir, id);

    match std::fs::write(&file_path, &yaml) {
        Ok(_) => {
            tracing::info!("New SIGMA rule created: {}", id);
            Json(json!({
                "status": "created",
                "id":     id,
                "file":   file_path,
                "rule":   yaml
            }))
        }
        Err(e) => {
            tracing::warn!("Failed to write rule: {}", e);
            Json(json!({
                "status": "error",
                "message": e.to_string()
            }))
        }
    }
}

pub async fn delete_rule(
    State(state): State<AppState>,
    axum::extract::Path(rule_id): axum::extract::Path<String>,
) -> Json<Value> {
    let rules_dir = std::env::var("RULES_DIR")
        .unwrap_or_else(|_| "rules".to_string());
    let file_path = format!("{}/{}.yml", rules_dir, rule_id);

    match std::fs::remove_file(&file_path) {
        Ok(_) => {
            // Also remove state from ClickHouse
            state.ch_storage
                .delete_rule_state(&rule_id).await.ok();

            // Reload rules
            let disabled = state.ch_storage
                .get_disabled_rules().await
                .unwrap_or_default();
            let all_rules = crate::detection::load_rules_from_dir(&rules_dir);
            let active = all_rules.into_iter()
                .filter(|r| !disabled.contains(&r.id))
                .collect::<Vec<_>>();
            let count = active.len();
            state.detection.write().await.set_rules(active);

            tracing::info!("Rule deleted: {}", rule_id);
            Json(json!({
                "status": "deleted",
                "id":     rule_id,
                "active_rules": count
            }))
        }
        Err(e) => Json(json!({
            "status":  "error",
            "message": e.to_string()
        }))
    }
}



//scale status
pub async fn get_scale_status(State(state): State<AppState>) -> Json<Value> {
    let stats = state.ch_storage.get_stats().await.unwrap_or(json!({}));
    let events_1h = stats.get("events_1h")
        .and_then(|v| v.as_u64()).unwrap_or(0);
    let events_per_sec = events_1h / 3600;

    Json(json!({
        "events_per_sec":   events_per_sec,
        "events_1h":        events_1h,
        "sessions":         state.correlator.session_count(),
        "scale_recommendation": if events_per_sec > 10000 {
            "scale_up"
        } else if events_per_sec < 1000 {
            "scale_down"
        } else {
            "optimal"
        },
        "current_engines": 1,
        "max_engines":     5,
    }))
}



//rules enable disable
pub async fn toggle_rule(
    State(state): State<AppState>,
    axum::extract::Path(rule_id): axum::extract::Path<String>,
    Json(payload): Json<TogglePayload>,
) -> Json<Value> {
    // Save state to ClickHouse
    if let Err(e) = state.ch_storage
        .set_rule_enabled(&rule_id, payload.enabled).await {
        return Json(json!({
            "status": "error",
            "message": e.to_string()
        }));
    }

    // Reload rules respecting disabled state
    let rules_dir = std::env::var("RULES_DIR")
        .unwrap_or_else(|_| "rules".to_string());
    let disabled = state.ch_storage
        .get_disabled_rules().await
        .unwrap_or_default();
    let all_rules = crate::detection::load_rules_from_dir(&rules_dir);
    let active = all_rules.into_iter()
        .filter(|r| !disabled.contains(&r.id))
        .collect::<Vec<_>>();
    let count = active.len();
    state.detection.write().await.set_rules(active);

    Json(json!({
        "status":       "ok",
        "id":           rule_id,
        "enabled":      payload.enabled,
        "active_rules": count
    }))
}

//severity
pub async fn get_severity(State(state): State<AppState>) -> Json<Value> {
    match state.ch_storage.get_severity_breakdown().await {
        Ok(data) => Json(data),
        Err(e) => {
            tracing::warn!("Severity query error: {}", e);
            Json(json!({
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            }))
        }
    }
}

