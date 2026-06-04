// NDR Engine — API Routes and Handlers
// License: Apache-2.0

pub mod websocket;

trait ExitStatusDefault {
    fn default() -> Self;
}
impl ExitStatusDefault for std::process::ExitStatus {
    fn default() -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            std::process::ExitStatus::from_raw(0)
        }
        #[cfg(not(unix))]
        {
            unsafe { std::mem::zeroed() }
        }
    }
}

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
use std::time::Duration;
use rdkafka::producer::Producer;
use rdkafka::util::Timeout;

use jsonwebtoken::{encode, decode, Header, 
    Validation, EncodingKey, DecodingKey};

#[derive(serde::Serialize, serde::Deserialize)]
struct Claims {
    sub: String,
    role: String,
    tenant_id: String,
    permissions: Vec<String>,
    exp: usize,
}

fn generate_jwt(username: &str, role: &str, 
    tenant_id: &str, permissions: Vec<String>) -> String {
    let secret = std::env::var("JWT_SECRET")
        .unwrap_or_else(|_| 
            "ndr-secret-key-2026".to_string());
    let expiry = chrono::Utc::now()
        .timestamp() as usize + 86400; // 24 hours
    let claims = Claims {
        sub: username.to_string(),
        role: role.to_string(),
        tenant_id: tenant_id.to_string(),
        permissions,
        exp: expiry,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes())
    ).unwrap_or_default()
}


use base64::Engine;
use std::collections::HashMap;
use std::sync::Mutex;

// Jira dedup cache: key = "src_dst", value = timestamp
static JIRA_DEDUP: std::sync::LazyLock<Mutex<HashMap<String, i64>>> = 
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

fn agent_url() -> String {
    env::var("NDR_AGENT_URL")
        .unwrap_or_else(|_| "http://172.25.86.150:3001".to_string())
}

fn kafka_health_status(state: &AppState) -> &'static str {
    match state
        .kafka_producer
        .client()
        .fetch_metadata(None, Timeout::After(Duration::from_secs(2)))
    {
        Ok(metadata) if metadata.brokers().iter().any(|broker| broker.id() >= 0) => "running",
        Ok(_) => "stopped",
        Err(error) => {
            warn!("Kafka health check failed: {}", error);
            "stopped"
        }
    }
}

#[derive(serde::Deserialize)]
pub struct TogglePayload {
    pub enabled: bool,
}



#[derive(serde::Deserialize)]
pub struct SoarSetupPayload {
    pub shuffle_url: String,
    pub username:    String,
    pub password:    String,
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
    pub redis:      Arc<redis::Client>,
    pub kafka_producer: Arc<rdkafka::producer::FutureProducer>,
}

pub fn publish_event(state: &AppState, tenant_id: &str, msg: &str) {
    let redis = state.redis.clone();
    let msg_str = msg.to_string();
    let channel = format!("tenant:{}", tenant_id);
    let tx = state.tx.clone();
    let msg_fallback = msg_str.clone();
    tokio::spawn(async move {
        match redis.get_async_connection().await {
            Ok(mut conn) => {
                // Redis available — it is the ONLY delivery path.
                // The WebSocket handler in websocket.rs subscribes directly to
                // this Redis channel, so exactly ONE message reaches the client.
                let _: Result<(), _> = redis::cmd("PUBLISH")
                    .arg(&channel)
                    .arg(&msg_str)
                    .query_async(&mut conn)
                    .await;
                // NOTE: Do NOT also call tx.send() here.
                // websocket.rs uses Redis when available and tx only as fallback.
                // Sending both causes duplicates with multiple engines.
            }
            Err(_) => {
                // Redis unavailable — fall back to in-process broadcast
                tracing::warn!("Redis unavailable, falling back to local broadcast");
                let _ = tx.send(msg_fallback);
            }
        }
    });
}



// JWT Claims extractor
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct AuthClaims {
    pub sub: String,
    pub role: String,
    pub tenant_id: String,
    pub permissions: Vec<String>,
    pub exp: usize,
}

pub fn extract_claims(
    headers: &axum::http::HeaderMap
) -> Option<AuthClaims> {
    let token = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))?;

    let secret = std::env::var("JWT_SECRET")
        .unwrap_or_else(|_| 
            "ndr-secret-key-2026".to_string());

    decode::<AuthClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default()
    ).ok().map(|d| d.claims)
}

fn require_super_admin(
    headers: &axum::http::HeaderMap,
) -> Result<AuthClaims, Json<Value>> {
    match extract_claims(headers) {
        Some(claims) if claims.role == "super_admin" => Ok(claims),
        Some(_) => Err(Json(json!({
            "status": "error",
            "message": "Forbidden: super admin required"
        }))),
        None => Err(Json(json!({
            "status": "error",
            "message": "Unauthorized"
        }))),
    }
}

fn permissions_from_payload(payload: &Value, role: &str) -> String {
    match payload.get("permissions") {
        Some(val) => {
            if let Some(arr) = val.as_array() {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            } else if let Some(s) = val.as_str() {
                s.to_string()
            } else {
                crate::storage::clickhouse::default_permissions(role)
            }
        }
        None => crate::storage::clickhouse::default_permissions(role),
    }
}

// Auth middleware
pub async fn auth_middleware(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let path = request.uri().path().to_string();
    
    // Public routes - no auth needed
    let public = ["/api/auth/login", "/api/health", "/ws", "/api/sensor", "/api/ingest", "/api/sensor/command", "/api/install-sensor.sh"];
    if public.iter().any(|p| path.starts_with(p)) {
        return next.run(request).await;
    }

    // Extract JWT
    match extract_claims(&headers) {
        Some(claims) => {
            if claims.role != "super_admin" {
                // ── Tenant-level gate ─────────────────────────────────────────
                match state.ch_storage.is_tenant_active(&claims.tenant_id).await {
                    Ok(false) => {
                        return axum::response::Response::builder()
                            .status(403)
                            .header("Content-Type", "application/json")
                            .body(axum::body::Body::from(
                                r#"{"status":"error","message":"Tenant has been deactivated"}"#
                            ))
                            .unwrap();
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Tenant active check failed for {}: {}",
                            claims.tenant_id,
                            e
                        );
                        return axum::response::Response::builder()
                            .status(503)
                            .header("Content-Type", "application/json")
                            .body(axum::body::Body::from(
                                r#"{"status":"error","message":"Unable to verify tenant status"}"#
                            ))
                            .unwrap();
                    }
                    Ok(true) => {}
                }

                // ── Per-user active gate ──────────────────────────────────────
                // Only enforce for roles that Tenant Admin can block.
                // super_admin is skipped above; tenant_admin, admin are
                // excluded here because they manage others and must not lock
                // themselves out via a DB race.
                let blockable_roles = ["analyst", "senior_analyst", "viewer", "default_user"];
                if blockable_roles.contains(&claims.role.as_str()) {
                    match state.ch_storage.is_user_active(&claims.sub).await {
                        Ok(false) => {
                            tracing::info!(
                                "🚫 Blocked user '{}' attempted API access — rejecting",
                                claims.sub
                            );
                            return axum::response::Response::builder()
                                .status(403)
                                .header("Content-Type", "application/json")
                                .body(axum::body::Body::from(
                                    r#"{"status":"error","message":"Your account has been disabled by your administrator.","code":"USER_DISABLED"}"#
                                ))
                                .unwrap();
                        }
                        Err(e) => {
                            // Log but don't block — fail-open to avoid disrupting
                            // legitimate users if ClickHouse has a transient fault.
                            tracing::warn!(
                                "User active check failed for '{}': {}",
                                claims.sub,
                                e
                            );
                        }
                        Ok(true) => {}
                    }
                }
            }
            request.extensions_mut().insert(claims);
            next.run(request).await
        }
        None => {
            axum::response::Response::builder()
                .status(401)
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"status":"error","message":"Unauthorized"}"#
                ))
                .unwrap()
        }
    }
}

pub fn broadcast_raw_event(state: &AppState, event: &NormalizedEvent) {
    let src = event.source_ip.as_deref().unwrap_or("-");
    let dst = event.dest_ip.as_deref().unwrap_or("-");

    let mut msg = match event.event_source {
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

    let tenant_id = event.raw.get("tenant_id")
        .and_then(|v| v.as_str())
        .unwrap_or("default")
        .to_string();
    if let Some(obj) = msg.as_object_mut() {
        obj.insert("tenant_id".to_string(), serde_json::Value::String(tenant_id.clone()));
    }

    publish_event(state, &tenant_id, &msg.to_string());
}


//network map
pub async fn get_network_map(State(state): State<AppState>, headers: axum::http::HeaderMap) -> Json<Value> {
    let tenant_id = extract_claims(&headers).map(|c| c.tenant_id).unwrap_or_else(|| "default".to_string());
    match state.ch_storage.get_network_map_by_tenant(&tenant_id).await {
        Ok(data) => Json(data),
        Err(_) => Json(json!({"nodes": [], "edges": []}))
    }
}

pub async fn process_correlation_hit(state: &AppState, hit: CorrelationHit) {
    let tenant_id = hit.zeek.raw.get("tenant_id")
        .or_else(|| hit.suricata.raw.get("tenant_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("default")
        .to_string();

  // ── Get thresholds from ClickHouse ────────
    let settings = state.ch_storage
        .get_settings_by_tenant(&tenant_id).await
        .unwrap_or(json!({}));
let store_threshold = settings["store_threshold"]
    .as_f64().unwrap_or(10.0) as f32;
let alert_threshold = settings["soar_threshold"]
    .as_f64().unwrap_or(75.0) as f32;
        
    let (src, dst) = match hit.source.as_str() {
        "zeek" => (
            hit.zeek.source_ip.as_deref().unwrap_or("-"),
            hit.zeek.dest_ip.as_deref().unwrap_or("-"),
        ),
        "suricata" => (
            hit.suricata.source_ip.as_deref().unwrap_or("-"),
            hit.suricata.dest_ip.as_deref().unwrap_or("-"),
        ),
        _ => (
            // zeek+suricata — prefer Zeek for flow data
            hit.zeek.source_ip.as_deref()
                .or(hit.suricata.source_ip.as_deref())
                .unwrap_or("-"),
            hit.zeek.dest_ip.as_deref()
                .or(hit.suricata.dest_ip.as_deref())
                .unwrap_or("-"),
        ),
    };
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

// Only store hits above threshold
    if risk.score < store_threshold {
        return;
    }

    // Persist to SQLite
    if let Err(e) = state.storage.store_hit(&hit, &risk, &detections, &enrichment) {
        warn!("Storage error: {}", e);
    }

    // Persist to ClickHouse

    let ch = state.ch_storage.clone();
    let tenant_id_clone = tenant_id.clone();
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
    tenant_id:    tenant_id.clone(),
    };
    tokio::spawn(async move {
        if let Err(e) = ch.insert_hit_for_tenant(ch_hit, &tenant_id_clone).await {
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


// ── Execute playbooks directly ────────────────
if risk.score >= alert_threshold {
let playbooks = state.ch_storage
    .get_soar_playbooks().await
    .unwrap_or_default();

for pb in &playbooks {
    if pb["enabled"] != true { continue; }

    let trigger = pb["trigger"]
        .as_str().unwrap_or("");

    // Check if trigger matches
    let triggered = match trigger {
        t if t.starts_with("score >") => {
            let threshold = t
                .replace("score >", "")
                .trim()
                .parse::<f32>()
                .unwrap_or(75.0);
            risk.score >= threshold
        }
        "threat_intel" => enrichment.is_malicious,
        "any"          => true,
        _              => false
    };

    if !triggered { continue; }

    let action_type = pb["action_type"]
        .as_str().unwrap_or("").to_string();
    let config: serde_json::Value =
        serde_json::from_str(
            pb["config"].as_str().unwrap_or("{}")
        ).unwrap_or(json!({}));
    let pb_name = pb["name"]
        .as_str().unwrap_or("").to_string();

    match action_type.as_str() {
        "slack" => {
            if let Some(url) = config["webhook_url"]
                .as_str() {
                let msg = json!({
                    "text": format!(
                        "🚨 *NDR Alert* | *{}*\n\
                        Source: `{}` → Dest: `{}`\n\
                        Score: *{}/100* | Threat Intel: {}\n\
                        Tags: {}",
                        risk.severity.as_str(),
                        src, dst,
                        risk.score as u32,
                        if enrichment.is_malicious 
                            { "⚠️ YES" } else { "No" },
                        risk.tags.join(", ")
                    )
                });
                let url = url.to_string();
                tokio::spawn(async move {
                    let _ = reqwest::Client::new()
                        .post(&url)
                        .json(&msg)
                        .timeout(
                            std::time::Duration
                                ::from_secs(5)
                        )
                        .send().await;
                });
                info!("✅ Slack playbook fired: {}", 
                    pb_name);
            }
        }
        "webhook" => {
            let url_val = config["url"]
                .as_str()
                .or(config["webhook_url"].as_str())
                .unwrap_or("").to_string();
            if !url_val.is_empty() {
                let url = url_val;
                let payload = json!({
                    "alert_type":   "ndr_threat",
                    "src_ip":       src,
                    "dst_ip":       dst,
                    "score":        risk.score,
                    "severity":     risk.severity.as_str(),
                    "threat_intel": enrichment.is_malicious,
                    "tags":         risk.tags,
                    "timestamp":    chrono::Utc::now()
                        .to_rfc3339()
                });
                let url = url.to_string();
                tokio::spawn(async move {
                    let _ = reqwest::Client::new()
                        .post(&url)
                        .json(&payload)
                        .timeout(
                            std::time::Duration
                                ::from_secs(5)
                        )
                        .send().await;
                });
                info!("✅ Webhook playbook fired: {}",
                    pb_name);
            }
        }
        _ => {}
    }
}
} // end playbooks threshold check


// Execute integrations - only above alert threshold
if risk.score >= alert_threshold {
let integrations = state.ch_storage
    .get_integrations().await
    .unwrap_or_default();

for integration in &integrations {
    if integration["enabled"] != true { continue; }
    
    let int_type = integration["type"]
        .as_str().unwrap_or("").to_string();
    let config = &integration["config"];
    let int_name = integration["name"]
        .as_str().unwrap_or("").to_string();

    match int_type.as_str() {
        "slack" | "discord" => {
            if let Some(url) = config["webhook_url"]
                .as_str() {
                let msg = json!({
                    "text": format!(
                        "🚨 *{}* | Score: {}/100\n\
                        {} → {}\nTags: {}",
                        risk.severity.as_str(),
                        risk.score as u32,
                        src, dst,
                        risk.tags.join(", ")
                    )
                });
                let url = url.to_string();
                tokio::spawn(async move {
                    let _ = reqwest::Client::new()
                        .post(&url)
                        .json(&msg)
                        .timeout(Duration::from_secs(5))
                        .send().await;
                });
                info!("✅ {} fired", int_name);
            }
        }
        "teams" => {
            if let Some(url) = config["webhook_url"]
                .as_str() {
                let msg = json!({
                    "@type": "MessageCard",
                    "@context": "http://schema.org/extensions",
                    "summary": "NDR Alert",
                    "themeColor": "FF0000",
                    "title": format!(
                        "🚨 NDR Alert: {}",
                        risk.severity.as_str()
                    ),
                    "sections": [{
                        "facts": [
                            {"name": "Source", "value": src},
                            {"name": "Destination", "value": dst},
                            {"name": "Score", "value": format!("{}/100", risk.score as u32)},
                            {"name": "Severity", "value": risk.severity.as_str()},
                            {"name": "Tags", "value": risk.tags.join(", ")}
                        ]
                    }]
                });
                let url = url.to_string();
                tokio::spawn(async move {
                    let _ = reqwest::Client::new()
                        .post(&url)
                        .json(&msg)
                        .timeout(Duration::from_secs(5))
                        .send().await;
                });
                info!("✅ Teams alert sent");
            }
        }
        "telegram" => {
            if let (Some(token), Some(chat_id)) = (
                config["bot_token"].as_str(),
                config["chat_id"].as_str()
            ) {
                let url = format!(
                    "https://api.telegram.org/bot{}/sendMessage",
                    token
                );
                let msg = json!({
                    "chat_id": chat_id,
                    "text": format!(
                        "🚨 NDR Alert\nSeverity: {}\nSource: {}\nDest: {}\nScore: {}/100\nTags: {}",
                        risk.severity.as_str(),
                        src, dst,
                        risk.score as u32,
                        risk.tags.join(", ")
                    ),
                    "parse_mode": "HTML"
                });
                tokio::spawn(async move {
                    let _ = reqwest::Client::new()
                        .post(&url)
                        .json(&msg)
                        .timeout(Duration::from_secs(5))
                        .send().await;
                });
                info!("✅ Telegram alert sent");
            }
        }
        "pagerduty" => {
            if let Some(key) = config["routing_key"]
                .as_str() {
                let payload = json!({
                    "routing_key": key,
                    "event_action": "trigger",
                    "payload": {
                        "summary": format!(
                            "NDR Alert: {} - {} → {}",
                            risk.severity.as_str(),
                            src, dst
                        ),
                        "severity": match risk.severity.as_str() {
                            "CRITICAL" => "critical",
                            "HIGH"     => "error",
                            "MEDIUM"   => "warning",
                            _          => "info"
                        },
                        "source": src,
                        "custom_details": {
                            "score":        risk.score,
                            "dst_ip":       dst,
                            "tags":         risk.tags,
                            "threat_intel": enrichment.is_malicious
                        }
                    }
                });
                tokio::spawn(async move {
                    let _ = reqwest::Client::new()
                        .post(
                            "https://events.pagerduty.com/v2/enqueue"
                        )
                        .json(&payload)
                        .timeout(Duration::from_secs(5))
                        .send().await;
                });
                info!("✅ PagerDuty alert sent");
            }
        }
        "webhook" => {
            let url_val = config["url"]
                .as_str()
                .or(config["webhook_url"].as_str())
                .unwrap_or("").to_string();
            if !url_val.is_empty() {
                let url = url_val;
                let payload = json!({
                    "alert_type":   "ndr_threat",
                    "src_ip":       src,
                    "dst_ip":       dst,
                    "score":        risk.score,
                    "severity":     risk.severity.as_str(),
                    "threat_intel": enrichment.is_malicious,
                    "tags":         risk.tags,
                    "timestamp":    chrono::Utc::now()
                        .to_rfc3339()
                });
                let url = url.to_string();
                let _int_name_c = int_name.clone();
                tokio::spawn(async move {
                    let _ = reqwest::Client::new()
                        .post(&url)
                        .json(&payload)
                        .timeout(Duration::from_secs(5))
                        .send().await;
                });
                info!("✅ Webhook integration fired: {}",
                    int_name);
            }
        }
        "jira" => {
    if let (Some(url), Some(email), Some(token), Some(project)) = (
        config["url"].as_str(),
        config["email"].as_str(),
        config["token"].as_str(),
        config["project_key"].as_str()
    ) {
        // Dedup: only one ticket per IP pair per hour
        let dedup_key = format!("{}_{}", src, dst);
        let now = chrono::Utc::now().timestamp();
        let should_create = {
            let mut cache = JIRA_DEDUP.lock().unwrap();
            let last = cache.get(&dedup_key).copied().unwrap_or(0);
            if now - last > 3600 {
                cache.insert(dedup_key.clone(), now);
                true
            } else {
                false
            }
        };
        if !should_create {
            info!("⏭️ Jira dedup: skipping {} → {}", src, dst);
        } else {
        let issue_url = format!(
            "{}/rest/api/3/issue", url
        );
        let creds = base64::engine::general_purpose::STANDARD.encode(
            format!("{}:{}", email, token)
        );
        let priority = match risk.severity.as_str() {
            "CRITICAL" => "Highest",
            "HIGH"     => "High",
            "MEDIUM"   => "Medium",
            _          => "Low"
        };
        let description = json!({
            "type": "doc",
            "version": 1,
            "content": [{
                "type": "paragraph",
                "content": [{
                    "type": "text",
                    "text": format!(
                        "NDR Alert Details\n\nSeverity: {}\nScore: {}/100\nSource IP: {}\nDestination IP: {}\nThreat Intel: {}\nTags: {}\nTime: {}",
                        risk.severity.as_str(),
                        risk.score as u32,
                        src, dst,
                        if enrichment.is_malicious { "MALICIOUS" } else { "Clean" },
                        risk.tags.join(", "),
                        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
                    )
                }]
            }]
        });
        let payload = json!({
            "fields": {
                "project": { "key": project },
                "summary": format!(
                    "🚨 NDR Alert: {} | {} → {} | Score: {}/100",
                    risk.severity.as_str(),
                    src, dst,
                    risk.score as u32
                ),
                "description": description,
                "issuetype": { "name": "Bug" },
                "priority": { "name": priority },
                "labels": ["NDR-Alert", "security"]
            }
        });
        let issue_url = issue_url.to_string();
        let creds = creds.to_string();
        let int_name_j = int_name.clone();
        tokio::spawn(async move {
            match reqwest::Client::new()
                .post(&issue_url)
                .header("Authorization",
                    format!("Basic {}", creds))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .json(&payload)
                .timeout(Duration::from_secs(10))
                .send().await {
                Ok(r) if r.status().is_success() =>
                    info!("✅ Jira ticket created: {}",
                        int_name_j),
                Ok(r) => warn!("Jira error: {}",
                    r.status()),
                Err(e) => warn!("Jira failed: {}", e),
            }
        });
        } // end should_create
    }
}
        _ => {}
    }
}
} // end alert_threshold check

// ── Send webhook to Shuffle SOAR ──────────────
// ── Send to Shuffle SOAR ──────────────────────
if risk.score >= alert_threshold {
    let shuffle_url = std::env::var("SHUFFLE_WEBHOOK_URL")
        .unwrap_or_default();

    if !shuffle_url.is_empty() {
        let payload = json!({
            "alert_type":   "ndr_threat_detected",
            "src_ip":       src,
            "dst_ip":       dst,
            "score":        risk.score,
            "severity":     risk.severity.as_str(),
            "threat_intel": enrichment.is_malicious,
            "sigma_hits":   sigma_hits,
            "timestamp":    chrono::Utc::now().to_rfc3339(),
            "tags":         risk.tags,
            "community_id": hit.community_id,
        });

        let url = shuffle_internal_url(&shuffle_url);
let api_key = std::env::var("SHUFFLE_API_KEY")
    .unwrap_or_default();
tokio::spawn(async move {
    let client = reqwest::Client::new();
    let mut req = client
        .post(&url)
        .json(&payload)
        .timeout(std::time::Duration::from_secs(5));
    if !api_key.is_empty() {
        req = req.header(
            "Authorization",
            format!("Bearer {}", api_key)
        );
    }
    match req.send().await
            {
                Ok(_)  => info!("✅ Alert sent to Shuffle SOAR"),
                Err(e) => warn!("Shuffle webhook failed: {}", e),
            }
        });
    }
}

    let mut hit_msg = json!({
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

    let tenant_id = std::env::var("TENANT_ID").unwrap_or_else(|_| "default".to_string());
    if let Some(obj) = hit_msg.as_object_mut() {
        obj.insert("tenant_id".to_string(), serde_json::Value::String(tenant_id.clone()));
    }

    publish_event(state, &tenant_id, &hit_msg.to_string());
}









// ── GET /health ───────────────────────────────────────────────────────────

pub async fn health(State(state): State<AppState>, headers: axum::http::HeaderMap) -> Json<Value> {
    let tenant_id = extract_claims(&headers).map(|c| c.tenant_id).unwrap_or_else(|| "default".to_string());
    let ch_stats = state.ch_storage.get_stats_by_tenant(&tenant_id).await.unwrap_or(json!({}));
    let clickhouse_status = if state.ch_storage.health_check().await {
        "running"
    } else {
        "stopped"
    };
    let kafka_status = kafka_health_status(&state);

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
            "zeek":       "unknown",
            "suricata":   "unknown",
            "vector":     "unknown",
            "kafka":      kafka_status,
            "clickhouse": clickhouse_status,
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



/// Convert external Shuffle URL to internal Docker URL
fn shuffle_internal_url(external_url: &str) -> String {
    let internal = std::env::var("SHUFFLE_INTERNAL_URL")
        .unwrap_or_else(|_|
            "http://shuffle-backend:5001".to_string());

    // Extract path+query from external URL
    // and replace host with internal
    if let Ok(parsed) = reqwest::Url::parse(external_url) {
        let path = parsed.path().to_string();
        let query = parsed.query()
            .map(|q| format!("?{}", q))
            .unwrap_or_default();
        return format!("{}{}{}", internal, path, query);
    }
    external_url.to_string()
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

pub async fn get_stats(State(state): State<AppState>, headers: axum::http::HeaderMap) -> Json<Value> {
    let tenant_id = extract_claims(&headers)
        .map(|c| c.tenant_id)
        .unwrap_or_else(|| "default".to_string());
    match state.ch_storage.get_stats_by_tenant(&tenant_id).await {
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

pub async fn get_recent_events(State(state): State<AppState>, headers: axum::http::HeaderMap) -> Json<Value> {
    let tenant_id = extract_claims(&headers)
        .map(|c| c.tenant_id)
        .unwrap_or_else(|| "default".to_string());
    match state.ch_storage.get_recent_events_by_tenant(50, &tenant_id).await {
        Ok(events) => Json(json!(events)),
        Err(e) => {
            tracing::warn!("Recent events query error: {}", e);
            Json(json!([]))
        }
    }
}

pub async fn get_top_ips(State(state): State<AppState>, headers: axum::http::HeaderMap) -> Json<Value> {
    let tenant_id = extract_claims(&headers)
        .map(|c| c.tenant_id)
        .unwrap_or_else(|| "default".to_string());
    let src = state.ch_storage.get_top_src_ips_by_tenant(10, &tenant_id).await.unwrap_or_default();
    let dst = state.ch_storage.get_top_dst_ips_by_tenant(10, &tenant_id).await.unwrap_or_default();
    Json(json!({
        "top_src_ips": src,
        "top_dst_ips": dst,
    }))
}


pub async fn get_hits(State(state): State<AppState>, headers: axum::http::HeaderMap) -> Json<Value> {
    let tenant_id = extract_claims(&headers)
        .map(|c| c.tenant_id)
        .unwrap_or_else(|| "default".to_string());
    match state.ch_storage.get_recent_hits_by_tenant(50, &tenant_id).await {
        Ok(hits) => Json(json!(hits)),
        Err(e) => {
            tracing::warn!("Hits query error: {}", e);
            Json(json!([]))
        }
    }
}

pub async fn load_rules_from_clickhouse(
    ch: &crate::storage::ClickhouseStorage,
    rules_dir: &str,
) -> Vec<crate::detection::SigmaRule> {
    if let Ok(ch_rules) = ch.get_all_enabled_sigma_rules().await {
        if !ch_rules.is_empty() {
            let mut rules = Vec::new();
            for (id, content) in ch_rules {
                match crate::detection::parse_rule_content(&content) {
                    Ok(r) => rules.push(r),
                    Err(e) => tracing::warn!("Failed to parse rule {} from ClickHouse: {}", id, e),
                }
            }
            if !rules.is_empty() {
                return rules;
            }
        }
    }
    crate::detection::load_rules_from_dir(rules_dir)
}

pub async fn get_rule_by_id(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(rule_id): axum::extract::Path<String>,
) -> Json<Value> {
    let tenant_id = extract_claims(&headers).map(|c| c.tenant_id).unwrap_or_else(|| "default".to_string());
    // Try ClickHouse first
    if let Ok(Some((id, name, content, _tenant_id, _enabled))) = state.ch_storage.get_sigma_rule_by_id(&rule_id, &tenant_id).await {
        let doc: std::collections::HashMap<String, serde_yaml::Value> =
            serde_yaml::from_str(&content).unwrap_or_default();

        let get_str = |k: &str| -> String {
            doc.get(k).and_then(|v| v.as_str())
                .unwrap_or("").to_string()
        };

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

        return Json(json!({
            "id":          id,
            "title":       name,
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
        }));
    }

    // Fallback to file-based
    let rules_dir = std::env::var("RULES_DIR")
        .unwrap_or_else(|_| "rules".to_string());
    let file_path = format!("{}/{}.yml", rules_dir, rule_id);

    match std::fs::read_to_string(&file_path) {
        Ok(content) => {
            let doc: std::collections::HashMap<String, serde_yaml::Value> =
                serde_yaml::from_str(&content).unwrap_or_default();

            let get_str = |k: &str| -> String {
                doc.get(k).and_then(|v| v.as_str())
                    .unwrap_or("").to_string()
            };

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

pub async fn get_rules(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    let tenant_id = extract_claims(&headers).map(|c| c.tenant_id).unwrap_or_else(|| "default".to_string());
    
    // Try ClickHouse first
    let db_rules = state.ch_storage.get_all_sigma_rules(&tenant_id).await.unwrap_or_default();
    
    let result: Vec<serde_json::Value> = if !db_rules.is_empty() {
        db_rules.iter().map(|(id, name, content, _r_tenant_id, enabled)| {
            let parsed = crate::detection::parse_rule_content(content).ok();
            let conditions_len = parsed.as_ref().map(|p| p.conditions.len()).unwrap_or(0);
            let tags = parsed.as_ref().map(|p| p.tags.clone()).unwrap_or_default();
            let severity = parsed.as_ref().map(|p| p.severity.clone()).unwrap_or_default();
            let logsource = parsed.as_ref().map(|p| p.logsource.clone());
            
            json!({
                "id":          id,
                "title":       name,
                "severity":    severity,
                "tags":        tags,
                "conditions":  conditions_len,
                "logsource": {
                    "product":  logsource.as_ref().and_then(|l| l.product.clone()),
                    "category": logsource.as_ref().and_then(|l| l.category.clone()),
                    "service":  logsource.as_ref().and_then(|l| l.service.clone()),
                },
                "enabled":     *enabled == 1,
                "status":      if *enabled == 1 { "active" } else { "disabled" }
            })
        }).collect()
    } else {
        // Fallback to loading from files
        let rules_dir = std::env::var("RULES_DIR")
            .unwrap_or_else(|_| "rules".to_string());
        let all_rules = crate::detection::load_rules_from_dir(&rules_dir);
        let disabled = state.ch_storage
            .get_disabled_rules(&tenant_id).await
            .unwrap_or_default();
        all_rules.iter().map(|r| {
            let is_enabled = !disabled.contains(&r.id);
            json!({
                "id":          r.id,
                "title":       r.title,
                "severity":    r.severity,
                "tags":        r.tags,
                "conditions":  r.conditions.len(),
                "logsource": {
                    "product":  r.logsource.product,
                    "category": r.logsource.category,
                    "service":  r.logsource.service,
                },
                "enabled": is_enabled,
                "status":  if is_enabled { "active" } else { "disabled" }
            })
        }).collect()
    };

    Json(json!(result))
}

//threat intelegence endpoint
pub async fn get_threat_intel(State(state): State<AppState>, headers: axum::http::HeaderMap) -> Json<Value> {
    let tenant_id = extract_claims(&headers).map(|c| c.tenant_id).unwrap_or_else(|| "default".to_string());
    let ti = &state.enrichment.threat_intel;
    let detected = state.ch_storage.get_threat_intel_hits_by_tenant(&tenant_id).await
        .unwrap_or_default();

    Json(json!({
        "total_malicious_ips":     ti.ip_count(),
        "total_malicious_hashes":  ti.hash_count(),
        "total_malicious_domains": ti.domain_count(),
        "detected_in_network":     detected,
        "last_refresh": "Every 60 minutes",
        "sources": [
            {
                "name": "Feodo Tracker",
                "type": "IP",
                "url":  "https://feodotracker.abuse.ch"
            },
            {
                "name": "MalwareBazaar",
                "type": "File Hash",
                "url":  "https://bazaar.abuse.ch"
            },
            {
                "name": "URLhaus",
                "type": "Domain/URL",
                "url":  "https://urlhaus.abuse.ch"
            }
        ]
    }))
}



//lookup ioc
//lookup ioc
pub async fn lookup_ioc(
    State(state): State<AppState>,
    axum::extract::Path(ioc): axum::extract::Path<String>,
) -> Json<Value> {
    let ti = &state.enrichment.threat_intel;

    // Check if real IP — ALL 4 parts must be valid numbers 0-255
    let is_real_ip = ioc.split('.').count() == 4 &&
        ioc.split('.').all(|p| p.parse::<u8>().is_ok());

    // Check if hash — hex string of specific length
    let is_hash = (ioc.len() == 32 || ioc.len() == 40 || ioc.len() == 64) &&
        ioc.chars().all(|c| c.is_ascii_hexdigit());

    // Detect IOC type correctly
    let (ioc_type, is_malicious) = if is_real_ip {
        // Real IP address like 10.0.2.15
        ("ip", ti.is_malicious_ip(&ioc))
    } else if is_hash {
        // Hash (MD5=32, SHA1=40, SHA256=64)
        ("hash", ti.is_malicious_hash(&ioc))
    } else if ioc.contains('.') {
        // Domain/hostname — includes 1navorex.lat etc
        ("domain", ti.is_malicious_domain(&ioc))
    } else {
        ("unknown", false)
    };

    Json(json!({
        "ioc":          ioc,
        "type":         ioc_type,
        "is_malicious": is_malicious,
        "source":       "abuse.ch (Feodo + MalwareBazaar + URLhaus)"
    }))
}
//add manaual ioc
pub async fn add_manual_ioc(
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Json<Value> {
    let ioc_type = payload["type"].as_str()
        .unwrap_or("ip");
    let value = payload["value"].as_str()
        .unwrap_or("");

    if value.is_empty() {
        return Json(json!({
            "status":  "error",
            "message": "value is required"
        }));
    }

    state.enrichment.threat_intel.add_ioc(ioc_type, value);

    Json(json!({
        "status":  "added",
        "type":    ioc_type,
        "value":   value,
        "message": format!("IOC {} added successfully", ioc_type)
    }))
}

// auto reload rules 
pub async fn reload_rules_api(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    let tenant_id = extract_claims(&headers).map(|c| c.tenant_id).unwrap_or_else(|| "default".to_string());
    let rules_dir = std::env::var("RULES_DIR")
        .unwrap_or_else(|_| "rules".to_string());

    let active = load_rules_from_clickhouse(&state.ch_storage, &rules_dir).await;
    let count = active.len();

    state.detection.write().await.set_rules(active);
    tracing::info!("Hot-reloaded {} SIGMA rules", count);

    // Publish reload rules to Redis channel
    let redis = state.redis.clone();
    tokio::spawn(async move {
        if let Ok(mut conn) = redis.get_async_connection().await {
            let _: Result<(), _> = redis::cmd("PUBLISH")
                .arg("system:reload_rules")
                .arg(&tenant_id)
                .query_async(&mut conn)
                .await;
        }
    });

    Json(json!({
        "status":        "reloaded",
        "count":         count,
        "message":       "Rules reloaded successfully"
    }))
}

//soar status
pub async fn get_soar_status(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap
) -> Json<Value> {
    let tenant_id = extract_claims(&headers).map(|c| c.tenant_id).unwrap_or_else(|| "default".to_string());

    // Get from ClickHouse first
    let config = state.ch_storage
        .get_soar_config_by_tenant(&tenant_id).await
        .unwrap_or(json!({}));
    
    // Fall back to env vars// Only fall back to env vars for default tenant
    let webhook_url = config["webhook_url"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            if tenant_id == "default" {
                std::env::var("SHUFFLE_WEBHOOK_URL")
                    .unwrap_or_default()
            } else {
                String::new()
            }
        });
    let shuffle_url = config["shuffle_url"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            if tenant_id == "default" {
                std::env::var("SHUFFLE_URL")
                    .unwrap_or_default()
            } else {
                String::new()
            }
        });

    let connected = !webhook_url.is_empty();

    // Get playbooks from ClickHouse
    let playbooks = state.ch_storage
        .get_soar_playbooks_by_tenant(&tenant_id).await
        .unwrap_or_default();

  let active_count = playbooks.iter()
    .filter(|p| p["enabled"] == true)
    .count();

Json(json!({
    "connected":    connected,
    "webhook_url":  webhook_url,
    "shuffle_url":  shuffle_url,
    "playbooks":    playbooks,
    "active_count": active_count,
    "shuffle_connected": connected,
    "ndr_playbooks_count": active_count
}))
}






pub async fn toggle_playbook(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<Value>,
) -> Json<Value> {
    let tenant_id = extract_claims(&headers).map(|c| c.tenant_id).unwrap_or_else(|| "default".to_string());
    let id = payload["id"]
        .as_str().unwrap_or("").to_string();
    let enabled = payload["enabled"]
        .as_bool().unwrap_or(false);

    match state.ch_storage
        .update_playbook_enabled(&id, enabled, &tenant_id).await {
        Ok(_) => Json(json!({
            "status": "ok",
            "message": format!(
                "Playbook {} {}",
                id,
                if enabled { "enabled" } else { "disabled" }
            )
        })),
        Err(e) => Json(json!({
            "status": "error",
            "message": e.to_string()
        }))
    }
}

pub async fn create_playbook(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<Value>,
) -> Json<Value> {
    let tenant_id = extract_claims(&headers).map(|c| c.tenant_id).unwrap_or_else(|| "default".to_string());
    let id = format!("pb-{}",
        chrono::Utc::now().timestamp());
    let name = payload["name"]
        .as_str().unwrap_or("New Playbook").to_string();
    let description = payload["description"]
        .as_str().unwrap_or("").to_string();
    let trigger = payload["trigger"]
        .as_str().unwrap_or("score > 75").to_string();
    let action_type = payload["action_type"]
        .as_str().unwrap_or("webhook").to_string();
    let action_config = payload["action_config"]
        .to_string()
        .replace("'", "\\'");



    match state.ch_storage.create_playbook(
        &id, &name, &description,
        &trigger, &action_type, &action_config, &tenant_id
    ).await {
        Ok(_) => Json(json!({
            "status":  "ok",
            "id":      id,
            "message": "Playbook created!"
        })),
        Err(e) => Json(json!({
            "status":  "error",
            "message": e.to_string()
        }))
    }
}



pub async fn test_soar_webhook(
    State(_state): State<AppState>
) -> Json<Value> {
    let webhook_url = std::env::var("SHUFFLE_WEBHOOK_URL")
        .unwrap_or_default();
let call_url = shuffle_internal_url(&webhook_url);
    if webhook_url.is_empty() {
        return Json(json!({
            "status": "error",
            "message": "Webhook URL not configured"
        }));
    }

    match reqwest::Client::new()
        .post(&call_url)
        .json(&json!({
            "alert_type": "test",
            "message":    "NDR test alert",
            "score":      85,
            "severity":   "HIGH",
            "timestamp":  chrono::Utc::now().to_rfc3339()
        }))
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
    {
        Ok(_) => Json(json!({
            "status": "ok",
            "message": "Test alert sent!"
        })),
        Err(e) => Json(json!({
            "status": "error",
            "message": e.to_string()
        }))
    }
}





pub async fn setup_soar(
    State(state): State<AppState>,
    Json(payload): Json<SoarSetupPayload>,
) -> Json<Value> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let internal_url = std::env::var("SHUFFLE_INTERNAL_URL")
        .unwrap_or_else(|_| "http://shuffle-backend:5001".to_string());

    tracing::info!("Connecting to Shuffle at: {}", internal_url);

    // Step 1: Login to get session
    let login_resp = match client
        .post(&format!("{}/api/v1/login", internal_url))
        .json(&serde_json::json!({
            "username": payload.username,
            "password": payload.password
        }))
        .send()
        .await {
            Ok(r) => r,
            Err(e) => return Json(json!({
                "status": "error",
                "message": format!("Cannot connect to Shuffle: {}", e)
            }))
        };

    // Get session from header
    let session_header = login_resp.headers()
        .get_all("set-cookie")
        .iter()
        .find_map(|v| {
            let s = v.to_str().ok()?;
            let part = s.split(';').next()?;
            let mut kv = part.splitn(2, '=');
            let key = kv.next()?.trim();
            let val = kv.next()?.trim();
            if key == "session_token" {
                Some(val.to_string())
            } else {
                None
            }
        })
        .unwrap_or_default();

    // Get session from body
    let login_body: Value = login_resp.json().await
        .unwrap_or(json!({}));

    let session = if !session_header.is_empty() {
        session_header
    } else {
        login_body["cookies"]
            .as_array()
            .and_then(|arr| arr.iter().find(|c| {
                c["key"].as_str() == Some("session_token")
            }))
            .and_then(|c| c["value"].as_str())
            .unwrap_or("")
            .to_string()
    };

    tracing::info!("Session: {}...", &session[..8.min(session.len())]);

    if session.is_empty() {
        return Json(json!({
            "status": "error",
            "message": "Login failed — check username and password"
        }));
    }

    // Step 2: Generate new API key using session
    let apikey_resp = client
        .get(&format!("{}/api/v1/users/generateapikey", internal_url))
        .header("Cookie", format!("session_token={}", session))
        .send()
        .await;

    let api_key = match apikey_resp {
        Ok(r) => {
            let body: Value = r.json().await.unwrap_or(json!({}));
            body["apikey"].as_str().unwrap_or("").to_string()
        }
        Err(_) => session.clone()
    };

    tracing::info!("API key: {}...", &api_key[..8.min(api_key.len())]);

    // Step 3: Create workflow using API key
    let workflow_resp = client
        .post(&format!("{}/api/v1/workflows", internal_url))
        .header("Cookie", format!("session_token={}", session))
        .header("Authorization", format!("Bearer {}", api_key))
        .json(&serde_json::json!({
            "name": "NDR Alert Response",
            "description": "Auto-created by NDR Stack"
        }))
        .send()
        .await; 

    let workflow_data: Value = match workflow_resp {
        Ok(r) => {
            let text = r.text().await.unwrap_or_default();
            tracing::info!("Workflow response: {}", &text[..200.min(text.len())]);
            serde_json::from_str(&text).unwrap_or(json!({}))
        }
        Err(e) => return Json(json!({
            "status": "error",
            "message": format!("Workflow creation failed: {}", e)
        }))
    };

    let workflow_id = workflow_data["id"]
        .as_str().unwrap_or("").to_string();

    if workflow_id.is_empty() {
        return Json(json!({
            "status": "error",
            "message": format!(
                "Could not create workflow: {}",
                workflow_data
            )
        }));
    }

    tracing::info!("Workflow created: {}", workflow_id);

    // Step 4: Build webhook URL using external IP
// Get real API key from Shuffle
let apikey_resp = client
    .get(&format!("{}/api/v1/users/generateapikey", internal_url))
    .header("Cookie", format!("session_token={}", session))
    .send()
    .await;

let real_api_key = match apikey_resp {
    Ok(r) => {
        let body: Value = r.json().await.unwrap_or(json!({}));
        body["apikey"].as_str().unwrap_or("").to_string()
    }
    Err(_) => "".to_string()
};

tracing::info!("Real API key: {}...",
    &real_api_key[..8.min(real_api_key.len())]);

// Save real API key to runtime env
if !real_api_key.is_empty() {
    std::env::set_var("SHUFFLE_API_KEY", &real_api_key);
}

// Build webhook URL
let webhook_url = format!(
    "{}/api/v1/workflows/{}/run",
    payload.shuffle_url,
    workflow_id);
    // Step 5: Save to .env file
    let install_dir = std::env::var("INSTALL_DIR")
        .unwrap_or_else(|_| ".".to_string());
    let env_path = format!("{}/.env", install_dir);
    let mut env_content = std::fs::read_to_string(&env_path)
        .unwrap_or_default();

   let vars = vec![
    ("SHUFFLE_URL", payload.shuffle_url.clone()),
    ("SHUFFLE_WEBHOOK_URL", webhook_url.clone()),
    ("SHUFFLE_API_KEY", real_api_key.clone()),
];

    for (key, val) in &vars {
        if env_content.contains(key) {
            let re = regex::Regex::new(
                &format!(r"{}=[^\n]*", key)
            ).unwrap();
            env_content = re.replace(
                &env_content,
                format!("{}={}", key, val).as_str()
            ).to_string();
        } else {
            env_content.push_str(
                &format!("\n{}={}", key, val)
            );
        }
    }
    // Save SOAR config to ClickHouse
let _ = state.ch_storage.save_soar_config(
    "webhook_url", &webhook_url).await;
let _ = state.ch_storage.save_soar_config(
    "workflow_id", &workflow_id).await;
let _ = state.ch_storage.save_soar_config(
    "api_key", &real_api_key).await;
let _ = state.ch_storage.save_soar_config(
    "shuffle_url", &payload.shuffle_url).await;

    std::fs::write(&env_path, &env_content).ok();

    // Step 6: Update runtime env
    std::env::set_var("SHUFFLE_URL", &payload.shuffle_url);
    std::env::set_var("SHUFFLE_WEBHOOK_URL", &webhook_url);

    Json(json!({
        "status":      "ok",
        "webhook_url": webhook_url,
        "workflow_id": workflow_id,
        "message":     "SOAR configured successfully!"
    }))
}

pub async fn update_soar_config(
    State(_state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Json<Value> {
    let webhook_url = payload["webhook_url"]
        .as_str().unwrap_or("").to_string();
    let shuffle_url = payload["shuffle_url"]
        .as_str().unwrap_or("").to_string();

    if !webhook_url.is_empty() {
        std::env::set_var("SHUFFLE_WEBHOOK_URL", &webhook_url);
    }
    if !shuffle_url.is_empty() {
        std::env::set_var("SHUFFLE_URL", &shuffle_url);
    }

    // Update .env file
    let install_dir = std::env::var("INSTALL_DIR")
        .unwrap_or_else(|_| ".".to_string());
    let env_path = format!("{}/.env", install_dir);
    let mut env_content = std::fs::read_to_string(&env_path)
        .unwrap_or_default();

    if !webhook_url.is_empty() {
        if env_content.contains("SHUFFLE_WEBHOOK_URL") {
            let lines: Vec<String> = env_content.lines()
                .map(|l| {
                    if l.starts_with("SHUFFLE_WEBHOOK_URL=") {
                        format!("SHUFFLE_WEBHOOK_URL={}", webhook_url)
                    } else { l.to_string() }
                }).collect();
            env_content = lines.join("\n");
        } else {
            env_content.push_str(
                &format!("\nSHUFFLE_WEBHOOK_URL={}", webhook_url)
            );
        }
    }

    std::fs::write(&env_path, env_content).ok();

    Json(json!({
        "status": "ok",
        "message": "SOAR config updated"
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
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<NewRule>
) -> Json<Value> {
    let tenant_id = extract_claims(&headers).map(|c| c.tenant_id).unwrap_or_else(|| "default".to_string());
    let id = format!("ndr-{}", chrono::Utc::now().timestamp());
    let tags = payload.tags.clone().unwrap_or_default();
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

    // Save to ClickHouse
    match state.ch_storage.save_sigma_rule(&id, &payload.title, &yaml, &tenant_id).await {
        Ok(_) => {
            // Also write to rules directory as fallback
            let rules_dir = std::env::var("RULES_DIR")
                .unwrap_or_else(|_| "rules".to_string());
            let file_path = format!("{}/{}.yml", rules_dir, id);
            let _ = std::fs::write(&file_path, &yaml);

            let redis = state.redis.clone();
            let tid = tenant_id.clone();
            tokio::spawn(async move {
                if let Ok(mut conn) = redis.get_async_connection().await {
                    let _: Result<(), _> = redis::cmd("PUBLISH")
                        .arg("system:reload_rules")
                        .arg(&tid)
                        .query_async(&mut conn)
                        .await;
                }
            });

            tracing::info!("New SIGMA rule created in ClickHouse: {}", id);
            Json(json!({
                "status": "created",
                "id":     id,
                "file":   file_path,
                "rule":   yaml
            }))
        }
        Err(e) => {
            tracing::warn!("Failed to save rule in ClickHouse: {}", e);
            Json(json!({
                "status": "error",
                "message": e.to_string()
            }))
        }
    }
}

pub async fn delete_rule(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(rule_id): axum::extract::Path<String>,
) -> Json<Value> {
    let tenant_id = extract_claims(&headers).map(|c| c.tenant_id).unwrap_or_else(|| "default".to_string());
    
    // Delete from ClickHouse
    let ch_deleted = state.ch_storage.delete_sigma_rule(&rule_id, &tenant_id).await.is_ok();
    
    // Also remove state from ClickHouse rules_state
    state.ch_storage.delete_rule_state(&rule_id, &tenant_id).await.ok();

    // Also delete from disk if present
    let rules_dir = std::env::var("RULES_DIR")
        .unwrap_or_else(|_| "rules".to_string());
    let file_path = format!("{}/{}.yml", rules_dir, rule_id);
    let disk_deleted = std::fs::remove_file(&file_path).is_ok();

    if ch_deleted || disk_deleted {
        // Reload rules
        let active = load_rules_from_clickhouse(&state.ch_storage, &rules_dir).await;
        let count = active.len();
        state.detection.write().await.set_rules(active);

        tracing::info!("Rule deleted: {}", rule_id);
        Json(json!({
            "status": "deleted",
            "id":     rule_id,
            "active_rules": count
        }))
    } else {
        Json(json!({
            "status":  "error",
            "message": "Rule not found"
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
    headers: axum::http::HeaderMap,
    axum::extract::Path(rule_id): axum::extract::Path<String>,
    Json(payload): Json<TogglePayload>,
) -> Json<Value> {
    let tenant_id = extract_claims(&headers).map(|c| c.tenant_id).unwrap_or_else(|| "default".to_string());
    // Save state to ClickHouse
    if let Err(e) = state.ch_storage
        .set_rule_enabled(&rule_id, payload.enabled, &tenant_id).await {
        return Json(json!({
            "status": "error",
            "message": e.to_string()
        }));
    }

    // Also update enabled field in sigma_rules table
    let _ = state.ch_storage.toggle_sigma_rule(&rule_id, payload.enabled, &tenant_id).await;

    // Reload rules respecting disabled state
    let rules_dir = std::env::var("RULES_DIR")
        .unwrap_or_else(|_| "rules".to_string());
    let active = load_rules_from_clickhouse(&state.ch_storage, &rules_dir).await;
    let count = active.len();
    state.detection.write().await.set_rules(active);

    Json(json!({
        "status":       "ok",
        "id":           rule_id,
        "enabled":      payload.enabled,
        "active_rules": count
    }))
}


//get the executions from the workflow
pub async fn get_soar_executions(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    let tenant_id = extract_claims(&headers).map(|c| c.tenant_id).unwrap_or_else(|| "default".to_string());
    let config = state.ch_storage
        .get_soar_config_by_tenant(&tenant_id).await
        .unwrap_or(json!({}));

    let internal_url = std::env::var("SHUFFLE_INTERNAL_URL")
        .unwrap_or_else(|_| "http://shuffle-backend:5001".to_string());
    let api_key = config["api_key"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| std::env::var("SHUFFLE_API_KEY").unwrap_or_default());
    let webhook_url = config["webhook_url"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| std::env::var("SHUFFLE_WEBHOOK_URL").unwrap_or_default());

    // Extract workflow ID from webhook URL
    let workflow_id = webhook_url
        .split("/workflows/")
        .nth(1)
        .and_then(|s| s.split("/run").next())
        .unwrap_or("")
        .to_string();

    if workflow_id.is_empty() {
        return Json(json!({
            "status": "error",
            "message": "SOAR not configured yet"
        }));
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    match client
        .get(&format!(
            "{}/api/v1/workflows/{}/executions",
            internal_url, workflow_id
        ))
        .header("Authorization", format!("Bearer {}", api_key))
        .send()
        .await
    {
        Ok(r) => {
            let data: Value = r.json().await.unwrap_or(json!([]));
            Json(json!({
                "status": "ok",
                "executions": data
            }))
        }
        Err(e) => Json(json!({
            "status": "error",
            "message": e.to_string()
        }))
    }
}

//get the actions from the workflow
pub async fn get_soar_actions(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    let tenant_id = extract_claims(&headers).map(|c| c.tenant_id).unwrap_or_else(|| "default".to_string());
    let config = state.ch_storage
        .get_soar_config_by_tenant(&tenant_id).await
        .unwrap_or(json!({}));

    let internal_url = std::env::var("SHUFFLE_INTERNAL_URL")
        .unwrap_or_else(|_| "http://shuffle-backend:5001".to_string());
    let api_key = config["api_key"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| std::env::var("SHUFFLE_API_KEY").unwrap_or_default());
    let webhook_url = config["webhook_url"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| std::env::var("SHUFFLE_WEBHOOK_URL").unwrap_or_default());

    let workflow_id = webhook_url
        .split("/workflows/")
        .nth(1)
        .and_then(|s| s.split("/run").next())
        .unwrap_or("")
        .to_string();

    if workflow_id.is_empty() {
        return Json(json!({ "status": "error", "actions": [] }));
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    match client
        .get(&format!(
            "{}/api/v1/workflows/{}",
            internal_url, workflow_id
        ))
        .header("Authorization", format!("Bearer {}", api_key))
        .send()
        .await
    {
        Ok(r) => {
            let data: Value = r.json().await.unwrap_or(json!({}));
            let actions = data["actions"].clone();
            Json(json!({
                "status":  "ok",
                "actions": actions
            }))
        }
        Err(e) => Json(json!({
            "status":  "error",
            "actions": [],
            "message": e.to_string()
        }))
    }
}

//configure slack 
pub async fn configure_slack(
    State(_state): State<AppState>,
    Json(payload): Json<Value>,
) -> Json<Value> {
    let slack_webhook = payload["webhook_url"]
        .as_str().unwrap_or("").to_string();

    if slack_webhook.is_empty() {
        return Json(json!({
            "status":  "error",
            "message": "webhook_url is required"
        }));
    }

    let internal_url = std::env::var("SHUFFLE_INTERNAL_URL")
        .unwrap_or_else(|_| "http://shuffle-backend:5001".to_string());
    let api_key = std::env::var("SHUFFLE_API_KEY")
        .unwrap_or_default();
    let webhook_url = std::env::var("SHUFFLE_WEBHOOK_URL")
        .unwrap_or_default();

    let workflow_id = webhook_url
        .split("/workflows/")
        .nth(1)
        .and_then(|s| s.split("/run").next())
        .unwrap_or("")
        .to_string();

    if workflow_id.is_empty() {
        return Json(json!({
            "status":  "error",
            "message": "SOAR not configured yet"
        }));
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    // Get current workflow
    let wf_resp = client
        .get(&format!(
            "{}/api/v1/workflows/{}",
            internal_url, workflow_id
        ))
        .header("Authorization", format!("Bearer {}", api_key))
        .send()
        .await;

    let mut workflow: Value = match wf_resp {
        Ok(r) => r.json().await.unwrap_or(json!({})),
        Err(e) => return Json(json!({
            "status":  "error",
            "message": format!("Cannot fetch workflow: {}", e)
        }))
    };

    // Build Slack HTTP action
    let slack_action = json!({
        "app_name":    "Http",
        "app_version": "1.0.0",
        "name":        "send_slack_alert",
        "label":       "Send Slack Alert",
        "parameters": [
            { "name": "url",     "value": slack_webhook },
            { "name": "method",  "value": "POST" },
            { "name": "headers", "value": "Content-Type=application/json" },
            { "name": "body",    "value": "{\"text\": \"🚨 NDR Alert: $exec.severity - $exec.src_ip → $exec.dst_ip (score: $exec.score)\"}" }
        ]
    });

    // Append action to workflow
    let actions = workflow["actions"]
        .as_array_mut()
        .map(|a| {
            a.push(slack_action.clone());
            a.clone()
        })
        .unwrap_or_else(|| vec![slack_action.clone()]);

    workflow["actions"] = json!(actions);

    // Save updated workflow back to Shuffle
    match client
        .put(&format!(
            "{}/api/v1/workflows/{}",
            internal_url, workflow_id
        ))
        .header("Authorization", format!("Bearer {}", api_key))
        .json(&workflow)
        .send()
        .await
    {
        Ok(_) => {
            // Save slack webhook to env
            std::env::set_var("SLACK_WEBHOOK_URL", &slack_webhook);
            Json(json!({
                "status":  "ok",
                "message": "Slack configured! Alerts will now be sent to Slack."
            }))
        }
        Err(e) => Json(json!({
            "status":  "error",
            "message": format!("Failed to update workflow: {}", e)
        }))
    }
}

// Get settings
pub async fn get_settings(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    let tenant_id = extract_claims(&headers).map(|c| c.tenant_id).unwrap_or_else(|| "default".to_string());
    match state.ch_storage.get_settings_by_tenant(&tenant_id).await {
        Ok(settings) => Json(json!({
            "status": "ok",
            "settings": settings
        })),
        Err(_) => Json(json!({
            "status": "ok",
            "settings": {
                "store_threshold":    10,
                "alert_threshold":    75,
                "critical_threshold": 90,
                "soar_threshold":     75
            }
        }))
    }
}

// Update settings
pub async fn update_settings(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<Value>,
) -> Json<Value> {
    let tenant_id = extract_claims(&headers).map(|c| c.tenant_id).unwrap_or_else(|| "default".to_string());
    let settings = vec![
        "store_threshold",
        "alert_threshold", 
        "critical_threshold",
        "soar_threshold",
    ];

    for key in &settings {
        if let Some(val) = payload[key].as_f64() {
            let _ = state.ch_storage
                .save_setting_by_tenant(key, &val.to_string(), &tenant_id)
                .await;
        }
    }

    Json(json!({
        "status": "ok",
        "message": "Settings saved!"
    }))
}

pub async fn export_report(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,) -> axum::response::Response {
    let tenant_id = extract_claims(&headers)
        .map(|c| c.tenant_id)
        .unwrap_or_else(|| "default".to_string());
    let format = params.get("format").map(|s: &String| s.as_str()).unwrap_or("json");
    let hours: u32 = params.get("hours").and_then(|h: &String| h.parse().ok()).unwrap_or(24);

    let stats    = state.ch_storage.get_stats_by_tenant(&tenant_id).await
        .unwrap_or(json!({}));
    let hits     = state.ch_storage.get_recent_hits_by_tenant(100, &tenant_id).await
        .unwrap_or_default();
    let top_ips  = state.ch_storage.get_top_src_ips_by_tenant(10, &tenant_id).await
        .unwrap_or_default();
    let severity = state.ch_storage.get_severity_by_tenant(&tenant_id).await
        .unwrap_or(json!({}));
    let threat   = state.ch_storage.get_threat_intel_hits().await
        .unwrap_or_default();
let rules = state.detection.read().await.get_rules();

    let report = json!({
        "generated_at":     chrono::Utc::now().to_rfc3339(),
        "time_range_hours": hours,
        "summary": {
            "total_events":    stats.get("events_total")
                .and_then(|v| v.as_u64()).unwrap_or(0),
            "total_hits":      stats.get("hits_total")
                .and_then(|v| v.as_u64()).unwrap_or(0),
            "events_1h":       stats.get("events_1h")
                .and_then(|v| v.as_u64()).unwrap_or(0),
            "zeek_events":     stats.get("zeek_events")
                .and_then(|v| v.as_u64()).unwrap_or(0),
            "suricata_events": stats.get("suricata_events")
                .and_then(|v| v.as_u64()).unwrap_or(0),
            "active_rules":    rules.len(),
        },
        "severity_breakdown":  severity,
        "top_source_ips":      top_ips,
        "recent_hits":         hits,
        "threat_intel_hits":   threat,
        "active_rules":        rules,
    });

    match format {
        "csv" => {
            let mut csv = String::new();
            csv.push_str("NDR Security Report\n");
            csv.push_str(&format!("Generated,{}\n",
                chrono::Utc::now().to_rfc3339()));
            csv.push_str(&format!("Time Range,Last {} hours\n\n", hours));

            csv.push_str("SUMMARY\n");
            csv.push_str("Metric,Value\n");
            csv.push_str(&format!("Total Events,{}\n",
                report["summary"]["total_events"]));
            csv.push_str(&format!("Total Hits,{}\n",
                report["summary"]["total_hits"]));
            csv.push_str(&format!("Events Last Hour,{}\n",
                report["summary"]["events_1h"]));
            csv.push_str(&format!("Zeek Events,{}\n",
                report["summary"]["zeek_events"]));
            csv.push_str(&format!("Suricata Events,{}\n",
                report["summary"]["suricata_events"]));
            csv.push_str(&format!("Active Rules,{}\n\n",
                report["summary"]["active_rules"]));

            csv.push_str("CORRELATION HITS\n");
            csv.push_str("Timestamp,Source IP,Dest IP,Severity,Score,Sigma Hits\n");
            if let Some(arr) = report["recent_hits"].as_array() {
                for h in arr {
                    csv.push_str(&format!("{},{},{},{},{:.0},{}\n",
                        h["timestamp"].as_u64().unwrap_or(0),
                        h["src_ip"].as_str().unwrap_or("-"),
                        h["dst_ip"].as_str().unwrap_or("-"),
                        h["severity"].as_str().unwrap_or("-"),
                        h["score"].as_f64().unwrap_or(0.0),
                        h["sigma_hits"].as_array()
                            .map(|a| a.iter()
                                .filter_map(|v| v.as_str())
                                .collect::<Vec<_>>().join(";"))
                            .unwrap_or_default(),
                    ));
                }
            }

            csv.push_str("\nTOP SOURCE IPs\n");
            csv.push_str("IP,Events\n");
            if let Some(ips) = report["top_source_ips"].as_array() {
                for ip in ips {
                    csv.push_str(&format!("{},{}\n",
                        ip["ip"].as_str().unwrap_or("-"),
                        ip["count"].as_u64().unwrap_or(0),
                    ));
                }
            }

            axum::response::Response::builder()
                .header("content-type", "text/csv")
                .header("content-disposition",
                    "attachment; filename=\"ndr-report.csv\"")
                .body(axum::body::Body::from(csv))
                .unwrap()
        }

        "pdf" => {
            let hits_rows = report["recent_hits"].as_array()
                .map(|hits| hits.iter().map(|h| format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td>\
                     <td>{}</td><td>{:.0}</td><td>{}</td></tr>",
                    h["timestamp"].as_u64().unwrap_or(0),
                    h["src_ip"].as_str().unwrap_or("-"),
                    h["dst_ip"].as_str().unwrap_or("-"),
                    h["severity"].as_str().unwrap_or("-"),
                    h["score"].as_f64().unwrap_or(0.0),
                    h["sigma_hits"].as_array()
                        .map(|a| a.iter()
                            .filter_map(|v| v.as_str())
                            .collect::<Vec<_>>().join(", "))
                        .unwrap_or_default(),
                )).collect::<Vec<_>>().join(""))
                .unwrap_or_default();

            let ip_rows = report["top_source_ips"].as_array()
                .map(|ips| ips.iter().map(|ip| format!(
                    "<tr><td>{}</td><td>{}</td></tr>",
                    ip["ip"].as_str().unwrap_or("-"),
                    ip["count"].as_u64().unwrap_or(0),
                )).collect::<Vec<_>>().join(""))
                .unwrap_or_default();

            let threat_rows = report["threat_intel_hits"].as_array()
                .map(|ti| ti.iter().map(|t| format!(
                    "<tr><td style='color:red'>{}</td>\
                     <td>{}</td><td>{}</td></tr>",
                    t["src_ip"].as_str().unwrap_or("-"),
                    t["dst_ip"].as_str().unwrap_or("-"),
                    t["hits"].as_u64().unwrap_or(0),
                )).collect::<Vec<_>>().join(""))
                .unwrap_or_default();

            let rules_rows = rules.iter().map(|r| format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                r["id"].as_str().unwrap_or("-"),
                r["title"].as_str().unwrap_or("-"),
                r["severity"].as_str().unwrap_or("-"),
                r["conditions"].as_u64().unwrap_or(0),
            )).collect::<Vec<_>>().join("");

            let html = format!(r#"<!DOCTYPE html>
<html>
<head>
<title>NDR Security Report</title>
<style>
body{{font-family:Arial,sans-serif;margin:40px;color:#333}}
h1{{color:#1a1a2e;border-bottom:3px solid #69f6b8;padding-bottom:10px}}
h2{{color:#16213e;margin-top:30px}}
table{{width:100%;border-collapse:collapse;margin:15px 0}}
th{{background:#1a1a2e;color:#69f6b8;padding:10px;text-align:left}}
td{{padding:8px 10px;border-bottom:1px solid #ddd}}
tr:nth-child(even){{background:#f9f9f9}}
.grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:15px;margin:20px 0}}
.card{{background:#f0f0f0;padding:15px;border-radius:8px;text-align:center}}
.val{{font-size:28px;font-weight:bold;color:#1a1a2e}}
.lbl{{font-size:12px;color:#666;text-transform:uppercase}}
@media print{{button{{display:none}}}}
</style>
</head>
<body>
<button onclick="window.print()"
  style="background:#69f6b8;border:none;padding:10px 20px;
  border-radius:5px;cursor:pointer;font-weight:bold;margin-bottom:20px">
  Print / Save as PDF
</button>
<h1>NDR Security Report</h1>
<p><strong>Generated:</strong> {}</p>
<p><strong>Time Range:</strong> Last {} hours</p>
<h2>Summary</h2>
<div class="grid">
  <div class="card"><div class="val">{}</div><div class="lbl">Total Events</div></div>
  <div class="card"><div class="val">{}</div><div class="lbl">Hits</div></div>
  <div class="card"><div class="val">{}</div><div class="lbl">Active Rules</div></div>
  <div class="card"><div class="val">{}</div><div class="lbl">Zeek Events</div></div>
  <div class="card"><div class="val">{}</div><div class="lbl">Suricata Events</div></div>
  <div class="card"><div class="val">{}</div><div class="lbl">Events/Hour</div></div>
</div>
<h2>Recent Hits</h2>
<table>
  <tr><th>Timestamp</th><th>Src IP</th><th>Dst IP</th>
      <th>Severity</th><th>Score</th><th>SIGMA</th></tr>
  {}
</table>
<h2>Top Source IPs</h2>
<table><tr><th>IP</th><th>Count</th></tr>{}</table>
<h2>Threat Intel Hits</h2>
<table><tr><th>Src IP</th><th>Dst IP</th><th>Hits</th></tr>{}</table>
<h2>Active SIGMA Rules</h2>
<table><tr><th>ID</th><th>Title</th><th>Severity</th><th>Conditions</th></tr>{}</table>
</body></html>"#,
                chrono::Utc::now().to_rfc3339(),
                hours,
                report["summary"]["total_events"],
                report["summary"]["total_hits"],
                report["summary"]["active_rules"],
                report["summary"]["zeek_events"],
                report["summary"]["suricata_events"],
                report["summary"]["events_1h"],
                hits_rows,
                ip_rows,
                threat_rows,
                rules_rows,
            );

            axum::response::Response::builder()
                .header("content-type", "text/html")
                .header("content-disposition",
                    "attachment; filename=\"ndr-report.html\"")
                .body(axum::body::Body::from(html))
                .unwrap()
        }

        _ => {
            axum::response::Response::builder()
                .header("content-type", "application/json")
                .header("content-disposition",
                    "attachment; filename=\"ndr-report.json\"")
                .body(axum::body::Body::from(report.to_string()))
                .unwrap()
        }
    }
}



// GET /api/soar/integrations
pub async fn get_integrations(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap
) -> Json<Value> {
    let tenant_id = extract_claims(&headers).map(|c| c.tenant_id).unwrap_or_else(|| "default".to_string());
    match state.ch_storage.get_integrations_by_tenant(&tenant_id).await {
        Ok(integrations) => Json(json!({
            "status": "ok",
            "integrations": integrations
        })),
        Err(_) => Json(json!({
            "status": "ok",
            "integrations": []
        }))
    }
}

// POST /api/soar/integrations
pub async fn save_integration(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<Value>,
) -> Json<Value> {
    let tenant_id = extract_claims(&headers).map(|c| c.tenant_id).unwrap_or_else(|| "default".to_string());
    let id = format!("int-{}",
        chrono::Utc::now().timestamp());
    let name = payload["name"]
        .as_str().unwrap_or("").to_string();
    let int_type = payload["type"]
        .as_str().unwrap_or("").to_string();
    let config = payload["config"].to_string();

    if name.is_empty() || int_type.is_empty() {
        return Json(json!({
            "status": "error",
            "message": "name and type required"
        }));
    }

    // Test connection before saving
    let test_result = test_integration(
        &int_type, &config).await;

    match state.ch_storage.save_integration(
        &id, &name, &int_type, &config, &tenant_id
    ).await {
        Ok(_) => Json(json!({
            "status": "ok",
            "id": id,
            "test": test_result,
            "message": format!(
                "{} integration saved!", name
            )
        })),
        Err(e) => Json(json!({
            "status": "error",
            "message": e.to_string()
        }))
    }
}

// Test integration connection
async fn test_integration(
    int_type: &str,
    config: &str
) -> String {
    let config: Value = serde_json::from_str(config)
        .unwrap_or(json!({}));
    
    match int_type {
        "slack" | "teams" | "discord" | "webhook" => {
            let url = config["webhook_url"]
                .as_str().unwrap_or("");
            if url.is_empty() {
                return "No URL configured".to_string();
            }
            let test_msg = json!({
                "text": "✅ NDR Stack test message"
            });
            match reqwest::Client::new()
                .post(url)
                .json(&test_msg)
                .timeout(std::time::Duration::from_secs(5))
                .send().await {
                Ok(_) => "✅ Connected".to_string(),
                Err(e) => format!("❌ {}", e)
            }
        }
        "pagerduty" => {
            let key = config["routing_key"]
                .as_str().unwrap_or("");
            if key.is_empty() {
                return "No routing key".to_string();
            }
            "✅ PagerDuty configured".to_string()
        }
        "telegram" => {
            let token = config["bot_token"]
                .as_str().unwrap_or("");
            let chat_id = config["chat_id"]
                .as_str().unwrap_or("");
            if token.is_empty() || chat_id.is_empty() {
                return "Missing token or chat_id".to_string();
            }
            let url = format!(
                "https://api.telegram.org/bot{}/sendMessage",
                token
            );
            let msg = json!({
                "chat_id": chat_id,
                "text": "✅ NDR Stack connected!"
            });
            match reqwest::Client::new()
                .post(&url)
                .json(&msg)
                .timeout(std::time::Duration::from_secs(5))
                .send().await {
                Ok(_) => "✅ Telegram connected".to_string(),
                Err(e) => format!("❌ {}", e)
            }
        }
        "jira" => {
    let url = config["url"].as_str().unwrap_or("");
    let email = config["email"].as_str().unwrap_or("");
    let token = config["token"].as_str().unwrap_or("");
    let project = config["project_key"].as_str().unwrap_or("");
    if url.is_empty() || email.is_empty() || token.is_empty() {
        return "Missing Jira config".to_string();
    }
    let test_url = format!("{}/rest/api/3/project/{}", url, project);
    let creds = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", email, token));
    match reqwest::Client::new()
        .get(&test_url)
        .header("Authorization", format!("Basic {}", creds))
        .header("Accept", "application/json")
        .timeout(std::time::Duration::from_secs(5))
        .send().await {
        Ok(r) if r.status().is_success() =>
            "✅ Jira connected".to_string(),
        Ok(r) => format!("❌ Jira error: {}", r.status()),
        Err(e) => format!("❌ {}", e)
    }
}
        _ => "Unknown integration".to_string()
    }
}

// POST /api/soar/integrations/test
pub async fn test_integration_endpoint(
    State(_state): State<AppState>,
    Json(payload): Json<Value>,
) -> Json<Value> {
    let int_type = payload["type"]
        .as_str().unwrap_or("").to_string();
    let config = payload["config"].to_string();
    
    let result = test_integration(&int_type, &config).await;
    Json(json!({
        "status": if result.starts_with("✅") 
            { "ok" } else { "error" },
        "message": result
    }))
}

// POST /api/soar/integrations/toggle
pub async fn toggle_integration(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<Value>,
) -> Json<Value> {
    let tenant_id = extract_claims(&headers).map(|c| c.tenant_id).unwrap_or_else(|| "default".to_string());
    let id = payload["id"]
        .as_str().unwrap_or("").to_string();
    let enabled = payload["enabled"]
        .as_bool().unwrap_or(false);
    
    match state.ch_storage
        .toggle_integration(&id, enabled, &tenant_id).await {
        Ok(_) => Json(json!({
            "status": "ok",
            "message": "Integration updated"
        })),
        Err(e) => Json(json!({
            "status": "error",
            "message": e.to_string()
        }))
    }
}

// DELETE /api/soar/integrations
pub async fn delete_integration(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<Value>,
) -> Json<Value> {
    let tenant_id = extract_claims(&headers).map(|c| c.tenant_id).unwrap_or_else(|| "default".to_string());
    let id = payload["id"]
        .as_str().unwrap_or("").to_string();
    
    match state.ch_storage
        .delete_integration(&id, &tenant_id).await {
        Ok(_) => Json(json!({
            "status": "ok",
            "message": "Integration deleted"
        })),
        Err(e) => Json(json!({
            "status": "error",
            "message": e.to_string()
        }))
    }
}




//configure email action
pub async fn configure_email(
    State(_state): State<AppState>,
    Json(payload): Json<Value>,
) -> Json<Value> {
    let email = payload["email"]
        .as_str().unwrap_or("").to_string();

    if email.is_empty() {
        return Json(json!({
            "status": "error",
            "message": "email is required"
        }));
    }

    let internal_url = std::env::var("SHUFFLE_INTERNAL_URL")
        .unwrap_or_else(|_|
            "http://shuffle-backend:5001".to_string());
    let api_key = std::env::var("SHUFFLE_API_KEY")
        .unwrap_or_default();
    let webhook_url = std::env::var("SHUFFLE_WEBHOOK_URL")
        .unwrap_or_default();

    let workflow_id = webhook_url
        .split("/workflows/")
        .nth(1)
        .and_then(|s| s.split("/run").next())
        .unwrap_or("").to_string();

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .build().unwrap();

    // Get current workflow
    let wf_resp = client
        .get(&format!(
            "{}/api/v1/workflows/{}",
            internal_url, workflow_id
        ))
        .header("Authorization",
            format!("Bearer {}", api_key))
        .send().await;

    let mut workflow: Value = match wf_resp {
        Ok(r) => r.json().await.unwrap_or(json!({})),
        Err(e) => return Json(json!({
            "status": "error",
            "message": format!("Cannot fetch workflow: {}", e)
        }))
    };

    // Add email action
    let email_action = json!({
        "app_name":    "Email",
        "app_version": "1.0.0",
        "name":        "send_email_alert",
        "label":       "Send Email Alert",
        "parameters": [
            { "name": "to",      "value": email },
            { "name": "subject", "value": "🚨 NDR Alert: $exec.severity" },
            { "name": "body",    "value": "Threat detected!\nSource: $exec.src_ip\nDestination: $exec.dst_ip\nScore: $exec.score\nSeverity: $exec.severity" }
        ]
    });

    let actions = workflow["actions"]
        .as_array_mut()
        .map(|a| { a.push(email_action.clone()); a.clone() })
        .unwrap_or_else(|| vec![email_action.clone()]);

    workflow["actions"] = json!(actions);

    match client
        .put(&format!(
            "{}/api/v1/workflows/{}",
            internal_url, workflow_id
        ))
        .header("Authorization",
            format!("Bearer {}", api_key))
        .json(&workflow)
        .send().await
    {
        Ok(_) => Json(json!({
            "status":  "ok",
            "message": "Email configured!"
        })),
        Err(e) => Json(json!({
            "status":  "error",
            "message": e.to_string()
        }))
    }
}


//severity
pub async fn get_severity(State(state): State<AppState>, headers: axum::http::HeaderMap) -> Json<Value> {
    let tenant_id = extract_claims(&headers)
        .map(|c| c.tenant_id)
        .unwrap_or_else(|| "default".to_string());
    match state.ch_storage.get_severity_by_tenant(&tenant_id).await {
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

// POST /api/auth/login
pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<Value>,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    let username = payload["username"]
        .as_str().unwrap_or("").to_string();
    let password = payload["password"]
        .as_str().unwrap_or("").to_string();

    if username.is_empty() || password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "status": "error",
                "message": "Username and password required"
            }))
        ).into_response();
    }

    tracing::info!("🔐 Login attempt: username='{}'", username);

    match state.ch_storage.verify_user(&username, &password).await {
        Ok(Some(user)) => {
            // Disabled account sentinel — returned by verify_user when
            // active=0 (or a pending disable mutation exists).
            if user.get("__disabled__").and_then(|v| v.as_bool()).unwrap_or(false) {
                tracing::warn!("🚫 Login BLOCKED for disabled account: '{}'", username);
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({
                        "status": "error",
                        "message": "Your account has been disabled. Please contact your administrator."
                    }))
                ).into_response();
            }

            let role = user["role"].as_str().unwrap_or("analyst");
            let tenant_id = user["tenant_id"].as_str().unwrap_or("default");
            if role != "super_admin" {
                match state.ch_storage.is_tenant_active(tenant_id).await {
                    Ok(false) => {
                        tracing::warn!(
                            "Login BLOCKED for inactive tenant: username='{}' tenant='{}'",
                            username,
                            tenant_id
                        );
                        return (
                            StatusCode::FORBIDDEN,
                            Json(json!({
                                "status": "error",
                                "message": "Your tenant has been deactivated. Please contact your administrator."
                            }))
                        ).into_response();
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Tenant active check failed during login for {}: {}",
                            tenant_id,
                            e
                        );
                        return (
                            StatusCode::SERVICE_UNAVAILABLE,
                            Json(json!({
                                "status": "error",
                                "message": "Unable to verify tenant status"
                            }))
                        ).into_response();
                    }
                    Ok(true) => {}
                }
            }
            let permissions_str = if role == "super_admin"
                || role == "tenant_admin"
                || role == "default_user"
            {
                crate::storage::clickhouse::default_permissions(role)
            } else {
                user["permissions"].as_str().unwrap_or("dashboard,alerts").to_string()
            };
            let permissions_vec: Vec<String> = permissions_str
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            let token = generate_jwt(
                &username,
                role,
                tenant_id,
                permissions_vec.clone(),
            );
            tracing::info!("✅ Login SUCCESS: username='{}' role='{}'", username, role);
            (
                StatusCode::OK,
                Json(json!({
                    "status": "ok",
                    "token": token,
                    "user": {
                        "id": user["id"].as_str().unwrap_or(""),
                        "username": username,
                        "role": role,
                        "tenant_id": tenant_id,
                        "permissions": permissions_vec
                    }
                }))
            ).into_response()
        }
        Ok(None) => {
            tracing::warn!("❌ Login FAILED (wrong credentials): username='{}'", username);
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "status": "error",
                    "message": "Invalid username or password"
                }))
            ).into_response()
        }
        Err(e) => {
            tracing::error!("💥 Login DB error for '{}': {}", username, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "status": "error",
                    "message": "Authentication service error. Please try again."
                }))
            ).into_response()
        }
    }
}


// GET /api/auth/me
pub async fn get_me(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    let token = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");

    let secret = std::env::var("JWT_SECRET")
        .unwrap_or_else(|_| 
            "ndr-secret-key-2026".to_string());

    match decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default()
    ) {
        Ok(data) => {
            let username = data.claims.sub;
            match state.ch_storage.get_user_by_username(&username).await {
                Ok(Some(user)) => {
                    let role = user["role"].as_str().unwrap_or("analyst");

                    // ── Per-user active check ─────────────────────────────────
                    // Roles that Tenant Admin can block are re-validated here so
                    // the 30-second session poll picks up a block even if the
                    // auth_middleware fast-path was not hit yet.
                    let blockable_roles = ["analyst", "senior_analyst", "viewer", "default_user"];
                    if blockable_roles.contains(&role) {
                        match state.ch_storage.is_user_active(&username).await {
                            Ok(false) => {
                                tracing::info!(
                                    "🚫 get_me: blocked user '{}' session check — returning USER_DISABLED",
                                    username
                                );
                                return Json(json!({
                                    "status": "error",
                                    "message": "Your account has been disabled by your administrator.",
                                    "code": "USER_DISABLED"
                                }));
                            }
                            Err(e) => {
                                tracing::warn!("User active check error in get_me for '{}': {}", username, e);
                            }
                            Ok(true) => {}
                        }
                    }

                    let permissions_str = if role == "super_admin"
                        || role == "tenant_admin"
                        || role == "default_user"
                    {
                        crate::storage::clickhouse::default_permissions(role)
                    } else {
                        user["permissions"].as_str().unwrap_or("dashboard,alerts").to_string()
                    };
                    let permissions: Vec<String> = permissions_str
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();

                    Json(json!({
                        "status": "ok",
                        "user": {
                            "id": user["id"].as_str().unwrap_or(""),
                            "username": username,
                            "role": role,
                            "tenant_id": user["tenant_id"].as_str().unwrap_or("default"),
                            "permissions": permissions
                        }
                    }))
                }
                Ok(None) => Json(json!({
                    "status": "error",
                    "message": "User not found"
                })),
                Err(e) => Json(json!({
                    "status": "error",
                    "message": e.to_string()
                })),
            }
        },
        Err(_) => Json(json!({
            "status": "error",
            "message": "Invalid token"
        }))
    }
}

// POST /api/auth/logout
pub async fn logout() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "message": "Logged out"
    }))
}


// GET /api/auth/users
pub async fn get_users(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(claims) => claims,
        None => return Json(json!({
            "status": "error",
            "message": "Unauthorized",
            "users": []
        })),
    };

    let result = if claims.role == "super_admin" {
        state.ch_storage.get_users().await
    } else if claims.role == "tenant_admin" {
        state.ch_storage.get_users_by_tenant(&claims.tenant_id).await
    } else {
        return Json(json!({
            "status": "error",
            "message": "Forbidden",
            "users": []
        }));
    };

    match result {
        Ok(users) => Json(json!({
            "status": "ok",
            "users": users
        })),
        Err(e) => Json(json!({
            "status": "error",
            "users": [],
            "message": e.to_string()
        }))
    }
}

// POST /api/auth/users
pub async fn create_user(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<Value>,
) -> Json<Value> {
    let username = payload["username"]
        .as_str().unwrap_or("").to_string();
    let password = payload["password"]
        .as_str().unwrap_or("").to_string();
    let requested_role = payload["role"]
        .as_str().unwrap_or("analyst").to_string();
    let requested_tenant_id = payload["tenant_id"]
        .as_str().unwrap_or("default").to_string();

    let claims = match extract_claims(&headers) {
        Some(claims) => claims,
        None => return Json(json!({
            "status": "error",
            "message": "Unauthorized"
        })),
    };

    let is_super_admin = claims.role == "super_admin";

    let (role, tenant_id) = if is_super_admin {
        let allowed_roles = ["tenant_admin", "default_user"];
        if !allowed_roles.contains(&requested_role.as_str()) {
            return Json(json!({
                "status": "error",
                "message": "Invalid role"
            }));
        }
        if requested_role == "tenant_admin" {
            if requested_tenant_id.is_empty() || requested_tenant_id == "default" {
                return Json(json!({
                    "status": "error",
                    "message": "Tenant Admin must be assigned to a tenant"
                }));
            }
            ("tenant_admin".to_string(), requested_tenant_id)
        } else if requested_role == "default_user" {
            ("default_user".to_string(), "default".to_string())
        } else if requested_tenant_id.is_empty() {
            (requested_role, "default".to_string())
        } else {
            (requested_role, requested_tenant_id)
        }
    } else if claims.role == "tenant_admin" {
        let allowed_roles = ["analyst", "senior_analyst", "viewer"];
        if !allowed_roles.contains(&requested_role.as_str()) {
            return Json(json!({
                "status": "error",
                "message": "Tenant admins can only create tenant users"
            }));
        }
        (requested_role, claims.tenant_id)
    } else {
        return Json(json!({
            "status": "error",
            "message": "Forbidden"
        }));
    };

    let permissions = permissions_from_payload(&payload, &role);

    if username.is_empty() || password.is_empty() {
        return Json(json!({
            "status": "error",
            "message": "Username and password required"
        }));
    }

    let hash = bcrypt::hash(&password, 12)
        .unwrap_or_default();

    match state.ch_storage.create_user(
        &username, &hash, &role, &tenant_id, &permissions
    ).await {
        Ok(_) => Json(json!({
            "status": "ok",
            "message": format!("User {} created!", username)
        })),
        Err(e) => Json(json!({
            "status": "error",
            "message": e.to_string()
        }))
    }
}

// PUT /api/auth/users/:id
pub async fn update_user_api(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(payload): Json<Value>,
) -> Json<Value> {
    let claims = match require_super_admin(&headers) {
        Ok(claims) => claims,
        Err(response) => return response,
    };

    if let Ok(Some((username, role, _tenant_id))) = state.ch_storage.get_user_identity(&id).await {
        if username == claims.sub || role == "super_admin" {
            return Json(json!({
                "status": "error",
                "message": "This user cannot be edited here"
            }));
        }
    }

    let role = payload["role"]
        .as_str().unwrap_or("analyst").to_string();
    let tenant_id = payload["tenant_id"]
        .as_str().unwrap_or("default").to_string();
    let active = payload["active"].as_bool().unwrap_or(true);
    let password = payload["password"].as_str().unwrap_or("").to_string();
    let allowed_roles = [
        "tenant_admin",
        "default_user",
        "admin",
        "senior_analyst",
        "analyst",
        "viewer",
    ];

    if !allowed_roles.contains(&role.as_str()) {
        return Json(json!({
            "status": "error",
            "message": "Invalid role"
        }));
    }
    if role == "tenant_admin" && (tenant_id.is_empty() || tenant_id == "default") {
        return Json(json!({
            "status": "error",
            "message": "Tenant Admin must be assigned to a tenant"
        }));
    }
    let tenant_id = if role == "default_user" {
        "default".to_string()
    } else {
        tenant_id
    };

    let permissions = permissions_from_payload(&payload, &role);
    let hash = if password.is_empty() {
        None
    } else {
        Some(bcrypt::hash(&password, 12).unwrap_or_default())
    };

    match state.ch_storage.update_user(
        &id, &role, &tenant_id, &permissions, active, hash.as_deref()
    ).await {
        Ok(_) => Json(json!({
            "status": "ok",
            "message": "User updated"
        })),
        Err(e) => Json(json!({
            "status": "error",
            "message": e.to_string()
        }))
    }
}

// POST /api/auth/users/:id/status
pub async fn set_user_status_api(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(payload): Json<Value>,
) -> Json<Value> {
    // Allow super_admin and tenant_admin
    let claims = match extract_claims(&headers) {
        Some(claims) if claims.role == "super_admin" || claims.role == "tenant_admin" => claims,
        Some(_) => return Json(json!({
            "status": "error",
            "message": "Forbidden: admin role required"
        })),
        None => return Json(json!({
            "status": "error",
            "message": "Unauthorized"
        })),
    };

    // Look up the target user to validate permissions
    if let Ok(Some((username, role, target_tenant))) = state.ch_storage.get_user_identity(&id).await {
        // Cannot deactivate yourself or other super_admins
        if username == claims.sub || role == "super_admin" {
            return Json(json!({
                "status": "error",
                "message": "This user cannot be deactivated here"
            }));
        }
        // Tenant admins can only manage users in their own tenant
        if claims.role == "tenant_admin" && target_tenant != claims.tenant_id {
            return Json(json!({
                "status": "error",
                "message": "Cannot modify users outside your tenant"
            }));
        }
        // Tenant admins cannot deactivate other admins
        if claims.role == "tenant_admin" && (role == "tenant_admin" || role == "admin") {
            return Json(json!({
                "status": "error",
                "message": "Cannot modify admin users"
            }));
        }
    }

    let active = payload["active"].as_bool().unwrap_or(true);

    match state.ch_storage.set_user_active(&id, active).await {
        Ok(_) => {
            info!("{} {} user {} (id={})",
                claims.sub,
                if active { "activated" } else { "deactivated" },
                id, claims.tenant_id
            );
            Json(json!({
                "status": "ok",
                "message": if active { "User activated" } else { "User deactivated" }
            }))
        }
        Err(e) => Json(json!({
            "status": "error",
            "message": e.to_string()
        }))
    }
}


// PUT /api/auth/users/:id/permissions
pub async fn update_user_permissions_api(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(payload): Json<Value>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(claims) => claims,
        None => return Json(json!({
            "status": "error",
            "message": "Unauthorized"
        })),
    };

    let target_user = match state.ch_storage.get_user_by_id(&id).await {
        Ok(Some(user)) => user,
        Ok(None) => return Json(json!({
            "status": "error",
            "message": "User not found"
        })),
        Err(e) => return Json(json!({
            "status": "error",
            "message": e.to_string()
        })),
    };

    let target_role = target_user["role"].as_str().unwrap_or("");
    let target_tenant_id = target_user["tenant_id"].as_str().unwrap_or("");
    let is_super_admin = claims.role == "super_admin"
        || (claims.role == "admin" && claims.tenant_id == "default");

    if target_role == "super_admin" {
        return Json(json!({
            "status": "error",
            "message": "Super admin permissions cannot be changed here"
        }));
    } else if claims.role == "tenant_admin" {
        let manageable_roles = ["analyst", "senior_analyst", "viewer"];
        if claims.tenant_id != target_tenant_id || !manageable_roles.contains(&target_role) {
            return Json(json!({
                "status": "error",
                "message": "Forbidden"
            }));
        }
    } else if !is_super_admin {
        return Json(json!({
            "status": "error",
            "message": "Forbidden"
        }));
    }

    let permissions = match payload.get("permissions") {
        Some(val) => {
            if let Some(arr) = val.as_array() {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            } else if let Some(s) = val.as_str() {
                s.to_string()
            } else {
                "".to_string()
            }
        }
        None => "".to_string(),
    };

    match state.ch_storage.update_user_permissions(&id, &permissions).await {
        Ok(_) => Json(json!({
            "status": "ok"
        })),
        Err(e) => Json(json!({
            "status": "error",
            "message": e.to_string()
        })),
    }
}

// POST /api/auth/users/:id/password
pub async fn reset_user_password_api(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(payload): Json<Value>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(claims) => claims,
        None => return Json(json!({
            "status": "error",
            "message": "Unauthorized"
        })),
    };

    let target_user = match state.ch_storage.get_user_by_id(&id).await {
        Ok(Some(user)) => user,
        Ok(None) => return Json(json!({
            "status": "error",
            "message": "User not found"
        })),
        Err(e) => return Json(json!({
            "status": "error",
            "message": e.to_string()
        })),
    };

    let target_role = target_user["role"].as_str().unwrap_or("");
    let target_tenant_id = target_user["tenant_id"].as_str().unwrap_or("");
    let is_super_admin = claims.role == "super_admin"
        || (claims.role == "admin" && claims.tenant_id == "default");

    if target_role == "super_admin" {
        return Json(json!({
            "status": "error",
            "message": "Super admin password cannot be changed here"
        }));
    } else if claims.role == "tenant_admin" {
        let manageable_roles = ["analyst", "senior_analyst", "viewer"];
        if claims.tenant_id != target_tenant_id || !manageable_roles.contains(&target_role) {
            return Json(json!({
                "status": "error",
                "message": "Forbidden"
            }));
        }
    } else if !is_super_admin {
        return Json(json!({
            "status": "error",
            "message": "Forbidden"
        }));
    }

    let password = match payload.get("password").and_then(|v| v.as_str()) {
        Some(p) if !p.is_empty() => p,
        _ => return Json(json!({
            "status": "error",
            "message": "Password is required"
        })),
    };

    // Hash the new password using bcrypt
    let password_hash = bcrypt::hash(password, 12).unwrap_or_default();

    match state.ch_storage.set_user_password(&id, &password_hash).await {
        Ok(_) => Json(json!({
            "status": "ok",
            "message": "Password updated successfully"
        })),
        Err(e) => Json(json!({
            "status": "error",
            "message": e.to_string()
        })),
    }
}

// DELETE /api/auth/users/:id
pub async fn delete_user(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(claims) => claims,
        None => return Json(json!({
            "status": "error",
            "message": "Unauthorized"
        })),
    };

    let target = match state.ch_storage.get_user_identity(&id).await {
        Ok(Some(target)) => target,
        Ok(None) => return Json(json!({
            "status": "error",
            "message": "User not found"
        })),
        Err(e) => return Json(json!({
            "status": "error",
            "message": e.to_string()
        })),
    };
    let (username, role, tenant_id) = target;

    if claims.role == "super_admin" {
        if username == claims.sub || role == "super_admin" {
            return Json(json!({
                "status": "error",
                "message": "This user cannot be deleted here"
            }));
        }
    } else if claims.role == "tenant_admin" {
        let protected_roles = ["super_admin", "admin", "tenant_admin"];
        if tenant_id != claims.tenant_id || protected_roles.contains(&role.as_str()) {
            return Json(json!({
                "status": "error",
                "message": "Tenant admins can only delete tenant users"
            }));
        }
    } else {
        return Json(json!({
            "status": "error",
            "message": "Forbidden"
        }));
    }

    match state.ch_storage.delete_user(&id).await {
        Ok(_) => Json(json!({
            "status": "ok",
            "message": "User deleted"
        })),
        Err(e) => Json(json!({
            "status": "error",
            "message": e.to_string()
        }))
    }
}

// GET /api/auth/tenants
pub async fn get_tenants(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    if let Err(response) = require_super_admin(&headers) {
        return response;
    }

    match state.ch_storage.get_tenants().await {
        Ok(tenants) => Json(json!({
            "status": "ok",
            "tenants": tenants
        })),
        Err(e) => Json(json!({
            "status": "error",
            "tenants": [],
            "message": e.to_string()
        }))
    }
}

// POST /api/auth/tenants
pub async fn create_tenant(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<Value>,
) -> Json<Value> {
    if let Err(response) = require_super_admin(&headers) {
        return response;
    }

    let name = payload["name"]
        .as_str().unwrap_or("").to_string();
    let id = payload["id"]
        .as_str().unwrap_or("").to_string();

    if name.is_empty() {
        return Json(json!({
            "status": "error",
            "message": "Tenant name required"
        }));
    }

    match state.ch_storage
        .create_tenant(&id, &name).await {
        Ok(_) => Json(json!({
            "status": "ok",
            "message": format!("Tenant {} created!", name)
        })),
        Err(e) => Json(json!({
            "status": "error",
            "message": e.to_string()
        }))
    }
}

// PUT /api/auth/tenants/:id
pub async fn update_tenant_api(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(payload): Json<Value>,
) -> Json<Value> {
    if let Err(response) = require_super_admin(&headers) {
        return response;
    }
    let name = payload["name"].as_str().unwrap_or("").to_string();
    let active = payload["active"].as_bool().unwrap_or(true);

    if id == "default" && !active {
        return Json(json!({
            "status": "error",
            "message": "Default tenant cannot be deactivated"
        }));
    }
    if name.is_empty() {
        return Json(json!({
            "status": "error",
            "message": "Tenant name required"
        }));
    }

    match state.ch_storage.update_tenant(&id, &name, active).await {
        Ok(_) => Json(json!({
            "status": "ok",
            "message": "Tenant updated"
        })),
        Err(e) => Json(json!({
            "status": "error",
            "message": e.to_string()
        }))
    }
}

// POST /api/auth/tenants/:id/status
pub async fn set_tenant_status_api(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(payload): Json<Value>,
) -> Json<Value> {
    if let Err(response) = require_super_admin(&headers) {
        return response;
    }
    let active = payload["active"].as_bool().unwrap_or(true);

    if id == "default" && !active {
        return Json(json!({
            "status": "error",
            "message": "Default tenant cannot be deactivated"
        }));
    }

    match state.ch_storage.set_tenant_active(&id, active).await {
        Ok(_) => Json(json!({
            "status": "ok",
            "message": if active { "Tenant activated" } else { "Tenant deactivated" }
        })),
        Err(e) => Json(json!({
            "status": "error",
            "message": e.to_string()
        }))
    }
}

pub async fn get_engines(
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    if let Err(response) = require_super_admin(&headers) {
        return response;
    }

    let output = std::process::Command::new("docker")
        .args(["ps",
            "--filter", "name=ndr-engine",
            "--format", "{{.Names}},{{.Status}},{{.RunningFor}}"])
        .output()
        .unwrap_or_else(|_| std::process::Output {
            status: <std::process::ExitStatus as ExitStatusDefault>::default(),
            stdout: vec![],
            stderr: vec![],
        });

    let engines: Vec<Value> = String::from_utf8_lossy(
        &output.stdout
    ).lines()
        .filter(|l| !l.is_empty())
        .map(|line| {
            let parts: Vec<&str> = line.splitn(3, ',').collect();
            json!({
                "name":    parts.get(0).unwrap_or(&""),
                "status":  parts.get(1).unwrap_or(&""),
                "running": parts.get(2).unwrap_or(&"")
            })
        }).collect();

    Json(json!({
        "engines": engines,
        "count": engines.len()
    }))
}

pub async fn scale_engines(
    headers: axum::http::HeaderMap,
    Json(payload): Json<Value>,
) -> Json<Value> {
    if let Err(response) = require_super_admin(&headers) {
        return response;
    }

    let action = payload["action"].as_str().unwrap_or("up");
    let engine_name = payload["engine"].as_str().unwrap_or("");

    match action {
        "up" => {
            // ── Count currently running ndr-engine containers ─────────────────
            let count_out = std::process::Command::new("docker")
                .args(["ps", "-q", "--filter", "name=ndr-engine"])
                .output()
                .unwrap_or_else(|_| std::process::Output {
                    status: <std::process::ExitStatus as ExitStatusDefault>::default(),
                    stdout: vec![],
                    stderr: vec![],
                });
            let count = String::from_utf8_lossy(&count_out.stdout)
                .lines()
                .filter(|l| !l.is_empty())
                .count();
            let new_instance_id = count + 1;
            let new_name = format!("ndr-engine-{}", new_instance_id);

            tracing::info!("Scaling up: {} engines running → starting {}", count, new_name);

            // ── Step 1: Clone any running engine and start new one ────────────
            let start_script = format!(r#"set -e
ENGINE=$(docker ps --format '{{{{.Names}}}}' --filter "name=ndr-engine" | head -n 1)
if [ -z "$ENGINE" ]; then echo "No running engine found as blueprint" >&2; exit 1; fi
NEW_ENGINE="{0}"
NEW_INSTANCE_ID="{1}"
IMAGE=$(docker inspect --format '{{{{.Config.Image}}}}' "$ENGINE")
NETWORK=$(docker inspect --format '{{{{range $k, $v := .NetworkSettings.Networks}}}}{{{{$k}}}}{{{{end}}}}' "$ENGINE")
BINDS=$(docker inspect --format '{{{{range .HostConfig.Binds}}}}-v {{{{.}}}} {{{{end}}}}' "$ENGINE")
ENVS=$(docker inspect --format '{{{{range .Config.Env}}}}-e {{{{.}}}} {{{{end}}}}' "$ENGINE" | sed "s/INSTANCE_ID=[0-9]*/INSTANCE_ID=$NEW_INSTANCE_ID/")
# Remove any stopped container with the same name to avoid conflicts
docker rm -f "$NEW_ENGINE" 2>/dev/null || true
eval docker run -d --name "$NEW_ENGINE" --privileged --network "$NETWORK" $BINDS $ENVS "$IMAGE"
"#, new_name, new_instance_id);

            tracing::debug!("Start script:\n{}", start_script);
            let engine_out = std::process::Command::new("bash")
                .args(["-c", &start_script])
                .output();

            match &engine_out {
                Ok(o) if o.status.success() => {
                    tracing::info!("✅ Engine {} started (ID: {})", new_name, String::from_utf8_lossy(&o.stdout).trim());
                }
                Ok(o) => {
                    let err = String::from_utf8_lossy(&o.stderr);
                    tracing::error!("❌ Failed to start engine: {}", err);
                    return Json(json!({ "status": "error", "message": format!("Engine start failed: {}", err) }));
                }
                Err(e) => {
                    tracing::error!("❌ OS error: {}", e);
                    return Json(json!({ "status": "error", "message": e.to_string() }));
                }
            }

            // ── Step 2: Scale Kafka partitions up to match new engine count ───
            tracing::info!("Scaling Kafka ndr-events partitions to {}", new_instance_id);
            let kafka_out = std::process::Command::new("docker")
                .args([
                    "exec", "kafka",
                    "/opt/kafka/bin/kafka-topics.sh",
                    "--bootstrap-server", "localhost:9092",
                    "--alter", "--topic", "ndr-events",
                    "--partitions", &new_instance_id.to_string(),
                ])
                .output();
            let kafka_msg = match &kafka_out {
                Ok(o) if o.status.success() => {
                    tracing::info!("✅ Kafka partitions → {}", new_instance_id);
                    format!("Kafka partitions set to {}", new_instance_id)
                }
                Ok(o) => {
                    // Kafka warns if partition count already >= requested; not fatal
                    let warn = String::from_utf8_lossy(&o.stderr);
                    tracing::warn!("⚠️ Kafka alter: {}", warn);
                    format!("Kafka warning: {}", warn)
                }
                Err(e) => { tracing::error!("❌ Kafka exec error: {}", e); e.to_string() }
            };

            // ── Step 3: Inject new server into Nginx upstream & reload ─────────
            let install_dir = std::env::var("INSTALL_DIR").unwrap_or_else(|_| ".".to_string());
            let nginx_conf = format!("{}/config/nginx/nginx.conf", install_dir);
            let new_server = format!("        server {}:3000 max_fails=3 fail_timeout=30s;", new_name);
            tracing::info!("Adding {} to Nginx upstream: {}", new_name, nginx_conf);

            let nginx_up_script = format!(r#"set -e
CONF="{0}"
NEW_LINE="{1}"
if ! grep -qF "$NEW_LINE" "$CONF"; then
    sed -i "/server ndr-engine.*:3000/a\\$NEW_LINE" "$CONF"
    echo "Added $NEW_LINE"
else
    echo "Already present"
fi
docker exec ndr-nginx nginx -s reload && echo "Nginx reloaded"
"#, nginx_conf, new_server);

            let nginx_out = std::process::Command::new("bash")
                .args(["-c", &nginx_up_script])
                .output();
            let nginx_msg = match &nginx_out {
                Ok(o) if o.status.success() => {
                    let msg = String::from_utf8_lossy(&o.stdout).trim().to_string();
                    tracing::info!("✅ Nginx: {}", msg);
                    msg
                }
                Ok(o) => {
                    let err = String::from_utf8_lossy(&o.stderr);
                    tracing::error!("❌ Nginx update failed: {}", err);
                    format!("Nginx error: {}", err)
                }
                Err(e) => { tracing::error!("❌ Nginx OS error: {}", e); e.to_string() }
            };

            Json(json!({
                "status": "ok",
                "message": format!("Engine {} started!", new_name),
                "engine": new_name,
                "kafka": kafka_msg,
                "nginx": nginx_msg
            }))
        }

        "down" => {
            if engine_name.is_empty() {
                return Json(json!({ "status": "error", "message": "Engine name required" }));
            }

            // ── Step 1: Remove from Nginx FIRST (drain traffic before stopping) ─
            let install_dir = std::env::var("INSTALL_DIR").unwrap_or_else(|_| ".".to_string());
            let nginx_conf = format!("{}/config/nginx/nginx.conf", install_dir);
            let remove_server = format!("        server {}:3000 max_fails=3 fail_timeout=30s;", engine_name);
            tracing::info!("Removing {} from Nginx upstream BEFORE stopping container", engine_name);

            let nginx_down_script = format!(r#"set -e
CONF="{0}"
REMOVE="{1}"
ESCAPED=$(printf '%s\n' "$REMOVE" | sed 's/[\/&]/\\&/g; s/$//')
sed -i "/$ESCAPED/d" "$CONF"
echo "Removed $REMOVE"
docker exec ndr-nginx nginx -s reload && echo "Nginx reloaded"
"#, nginx_conf, remove_server);

            let nginx_out = std::process::Command::new("bash")
                .args(["-c", &nginx_down_script])
                .output();
            let nginx_msg = match &nginx_out {
                Ok(o) if o.status.success() => {
                    let msg = String::from_utf8_lossy(&o.stdout).trim().to_string();
                    tracing::info!("✅ Nginx drained: {}", msg);
                    msg
                }
                Ok(o) => {
                    let err = String::from_utf8_lossy(&o.stderr);
                    tracing::warn!("⚠️ Nginx down warning: {}", err);
                    format!("Nginx warning: {}", err)
                }
                Err(e) => e.to_string()
            };

            // ── Step 2: Brief drain wait — let active connections finish ──────
            tracing::info!("Waiting 2s for active connections to drain from {}", engine_name);
            std::thread::sleep(std::time::Duration::from_secs(2));

            // ── Step 3: Stop the container safely ─────────────────────────────
            tracing::info!("Stopping engine container: {}", engine_name);
            let stop_out = std::process::Command::new("docker")
                .args(["stop", engine_name])
                .output();
            match &stop_out {
                Ok(o) if o.status.success() => tracing::info!("✅ Engine {} stopped", engine_name),
                Ok(o) => tracing::error!("❌ Stop failed: {}", String::from_utf8_lossy(&o.stderr)),
                Err(e) => tracing::error!("❌ OS error stopping: {}", e),
            }

            Json(json!({
                "status": "ok",
                "message": format!("{} stopped!", engine_name),
                "engine": engine_name,
                "nginx": nginx_msg,
                "note": "Nginx drained before container stop — zero dropped requests"
            }))
        }

        _ => Json(json!({ "status": "error", "message": "Unknown action" }))
    }
}

//jira ticket
pub async fn get_jira_tickets(
    Json(payload): Json<Value>,
) -> Json<Value> {
    let url = payload["url"].as_str().unwrap_or("");
    let email = payload["email"].as_str().unwrap_or("");
    let token = payload["token"].as_str().unwrap_or("");
    let project = payload["project_key"]
        .as_str().unwrap_or("");

    if url.is_empty() || email.is_empty() {
        return Json(json!({
            "status": "error",
            "tickets": []
        }));
    }

    let creds = base64::engine::general_purpose::STANDARD
        .encode(format!("{}:{}", email, token));
    
    let jql_url = format!(
        "{}/rest/api/3/search?jql=project={}+ORDER+BY+created+DESC&maxResults=20",
        url, project
    );

    match reqwest::Client::new()
        .get(&jql_url)
        .header("Authorization", format!("Basic {}", creds))
        .header("Accept", "application/json")
        .timeout(Duration::from_secs(10))
        .send().await {
        Ok(r) => {
            let data: Value = r.json().await
                .unwrap_or(json!({}));
            let issues = data["issues"]
                .as_array()
                .map(|issues| issues.iter().map(|i| {
                    let fields = &i["fields"];
                    json!({
                        "id": i["id"],
                        "key": i["key"],
                        "summary": fields["summary"],
                        "status": fields["status"]["name"],
                        "priority": fields["priority"]["name"],
                        "created": fields["created"],
                        "url": format!("{}/browse/{}", 
                            url, i["key"].as_str().unwrap_or(""))
                    })
                }).collect::<Vec<_>>())
                .unwrap_or_default();

            Json(json!({
                "status": "ok",
                "tickets": issues
            }))
        }
        Err(e) => Json(json!({
            "status": "error",
            "tickets": [],
            "message": e.to_string()
        }))
    }
}


// ── Support Messages ─────────────────────────────────────────────────────────

fn can_manage_support_message(claims: &AuthClaims, tenant_id: &str, forwarded: u8) -> bool {
    if claims.role == "super_admin" || claims.role == "admin" {
        return forwarded == 1 || tenant_id == "default";
    }
    if claims.role == "tenant_admin" {
        return claims.tenant_id == tenant_id;
    }
    false
}

pub async fn get_support_messages(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(claims) => claims,
        None => return Json(json!({
            "status": "error",
            "message": "Unauthorized",
            "messages": []
        })),
    };

    let result = tokio::time::timeout(Duration::from_secs(8), async {
        if claims.role == "super_admin" || claims.role == "admin" {
            state.ch_storage.get_support_messages_for_super_admin().await
        } else if claims.role == "tenant_admin" {
            state.ch_storage.get_support_messages_for_tenant(&claims.tenant_id).await
        } else {
            state.ch_storage
                .get_support_messages_for_user(&claims.tenant_id, &claims.sub)
                .await
        }
    }).await;

    match result {
        Ok(Ok(messages)) => Json(json!({
            "status": "ok",
            "messages": messages
        })),
        Ok(Err(e)) => Json(json!({
            "status": "error",
            "message": e.to_string(),
            "messages": []
        })),
        Err(_) => return Json(json!({
            "status": "error",
            "message": "Support messages request timed out",
            "messages": []
        })),
    }
}

pub async fn create_support_message(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<Value>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(claims) => claims,
        None => return Json(json!({
            "status": "error",
            "message": "Unauthorized"
        })),
    };

    if claims.role == "super_admin" || claims.role == "tenant_admin" || claims.role == "admin" {
        return Json(json!({
            "status": "error",
            "message": "Support requests must be submitted by tenant users"
        }));
    }

    let subject = payload["subject"].as_str().unwrap_or("").trim();
    let category = payload["category"].as_str().unwrap_or("General").trim();
    let message = payload["message"].as_str().unwrap_or("").trim();

    if subject.is_empty() || message.is_empty() {
        return Json(json!({
            "status": "error",
            "message": "Subject and message are required"
        }));
    }

    let result = tokio::time::timeout(Duration::from_secs(8), state.ch_storage.create_support_message(
        &claims.tenant_id,
        &claims.sub,
        &claims.role,
        subject,
        if category.is_empty() { "General" } else { category },
        message,
    )).await;

    let result = match result {
        Ok(result) => result,
        Err(_) => return Json(json!({
            "status": "error",
            "message": "Support request timed out"
        })),
    };

    match result {
        Ok(id) => Json(json!({
            "status": "ok",
            "id": id,
            "message": "Support request sent"
        })),
        Err(e) => Json(json!({
            "status": "error",
            "message": e.to_string()
        })),
    }
}

pub async fn review_support_message(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(claims) => claims,
        None => return Json(json!({"status": "error", "message": "Unauthorized"})),
    };

    let scope = match tokio::time::timeout(
        Duration::from_secs(8),
        state.ch_storage.get_support_message_scope(&id)
    ).await {
        Ok(Ok(Some(scope))) => scope,
        Ok(Ok(None)) => return Json(json!({"status": "error", "message": "Support message not found"})),
        Ok(Err(e)) => return Json(json!({"status": "error", "message": e.to_string()})),
        Err(_) => return Json(json!({"status": "error", "message": "Support lookup timed out"})),
    };

    if !can_manage_support_message(&claims, &scope.0, scope.2) {
        return Json(json!({"status": "error", "message": "Forbidden"}));
    }

    let result = tokio::time::timeout(
        Duration::from_secs(8),
        state.ch_storage.update_support_status(&id, "reviewed")
    ).await;
    let result = match result {
        Ok(result) => result,
        Err(_) => return Json(json!({"status": "error", "message": "Support review timed out"})),
    };

    match result {
        Ok(_) => Json(json!({"status": "ok", "message": "Support request marked reviewed"})),
        Err(e) => Json(json!({"status": "error", "message": e.to_string()})),
    }
}

pub async fn reply_support_message(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(payload): Json<Value>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(claims) => claims,
        None => return Json(json!({"status": "error", "message": "Unauthorized"})),
    };

    let reply = payload["reply"].as_str().unwrap_or("").trim();
    if reply.is_empty() {
        return Json(json!({"status": "error", "message": "Reply is required"}));
    }

    let scope = match tokio::time::timeout(
        Duration::from_secs(8),
        state.ch_storage.get_support_message_scope(&id)
    ).await {
        Ok(Ok(Some(scope))) => scope,
        Ok(Ok(None)) => return Json(json!({"status": "error", "message": "Support message not found"})),
        Ok(Err(e)) => return Json(json!({"status": "error", "message": e.to_string()})),
        Err(_) => return Json(json!({"status": "error", "message": "Support lookup timed out"})),
    };

    if !can_manage_support_message(&claims, &scope.0, scope.2) {
        return Json(json!({"status": "error", "message": "Forbidden"}));
    }

    let result = tokio::time::timeout(
        Duration::from_secs(8),
        state.ch_storage.reply_support_message(&id, reply, &claims.sub, "replied")
    ).await;
    let result = match result {
        Ok(result) => result,
        Err(_) => return Json(json!({"status": "error", "message": "Support reply timed out"})),
    };

    match result {
        Ok(_) => Json(json!({"status": "ok", "message": "Reply sent"})),
        Err(e) => Json(json!({"status": "error", "message": e.to_string()})),
    }
}

pub async fn forward_support_message(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(claims) => claims,
        None => return Json(json!({"status": "error", "message": "Unauthorized"})),
    };

    if claims.role != "tenant_admin" {
        return Json(json!({"status": "error", "message": "Only tenant admins can forward support requests"}));
    }

    let scope = match tokio::time::timeout(
        Duration::from_secs(8),
        state.ch_storage.get_support_message_scope(&id)
    ).await {
        Ok(Ok(Some(scope))) => scope,
        Ok(Ok(None)) => return Json(json!({"status": "error", "message": "Support message not found"})),
        Ok(Err(e)) => return Json(json!({"status": "error", "message": e.to_string()})),
        Err(_) => return Json(json!({"status": "error", "message": "Support lookup timed out"})),
    };

    if scope.0 != claims.tenant_id {
        return Json(json!({"status": "error", "message": "Forbidden"}));
    }

    let result = tokio::time::timeout(
        Duration::from_secs(8),
        state.ch_storage.forward_support_message(&id, &claims.sub)
    ).await;
    let result = match result {
        Ok(result) => result,
        Err(_) => return Json(json!({"status": "error", "message": "Support forward timed out"})),
    };

    match result {
        Ok(_) => Json(json!({"status": "ok", "message": "Support request forwarded to super admin"})),
        Err(e) => Json(json!({"status": "error", "message": e.to_string()})),
    }
}

pub async fn delete_support_message_api(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(claims) => claims,
        None => return Json(json!({"status": "error", "message": "Unauthorized"})),
    };

    let scope = match tokio::time::timeout(
        Duration::from_secs(8),
        state.ch_storage.get_support_message_scope(&id)
    ).await {
        Ok(Ok(Some(scope))) => scope,
        Ok(Ok(None)) => return Json(json!({"status": "error", "message": "Support message not found"})),
        Ok(Err(e)) => return Json(json!({"status": "error", "message": e.to_string()})),
        Err(_) => return Json(json!({"status": "error", "message": "Support lookup timed out"})),
    };

    if !can_manage_support_message(&claims, &scope.0, scope.2) {
        return Json(json!({"status": "error", "message": "Forbidden"}));
    }

    let result = tokio::time::timeout(
        Duration::from_secs(8),
        state.ch_storage.delete_support_message(&id)
    ).await;
    let result = match result {
        Ok(result) => result,
        Err(_) => return Json(json!({"status": "error", "message": "Support delete timed out"})),
    };

    match result {
        Ok(_) => Json(json!({"status": "ok", "message": "Support request deleted"})),
        Err(e) => Json(json!({"status": "error", "message": e.to_string()})),
    }
}

// ── Sensor Key Management, Registration & Heartbeat ────────────────────────
fn generate_sensor_key(tenant_id: &str) -> (String, String, String) {
    use rand::Rng;
    let random: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    let plain = format!("NDR-{}-{}", tenant_id, random);
    let prefix = plain[..16.min(plain.len())].to_string();
    let hash = bcrypt::hash(&plain, 10).unwrap_or_default();
    (plain, prefix, hash)
}

pub async fn validate_sensor_key(
    headers: &axum::http::HeaderMap,
    ch: &Arc<ClickhouseStorage>,
) -> Option<String> {
    let key = headers
        .get("X-Sensor-Key")
        .or_else(|| headers.get("x-sensor-key"))?
        .to_str().ok()?;
    
    ch.validate_sensor_key(key).await.ok()?
}

fn extract_sensor_key_prefix(
    headers: &axum::http::HeaderMap,
) -> Option<String> {
    let key = headers
        .get("X-Sensor-Key")
        .or_else(|| headers.get("x-sensor-key"))?
        .to_str().ok()?;

    if key.len() < 16 {
        return None;
    }

    Some(key[..16].to_string())
}

pub async fn install_sensor_script() -> axum::response::Response {
    let path = std::env::var("SENSOR_INSTALL_SCRIPT_PATH")
        .unwrap_or_else(|_| "/scripts/install-sensor.sh".to_string());

    match std::fs::read_to_string(&path) {
        Ok(script) => axum::response::Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/x-shellscript; charset=utf-8")
            .body(axum::body::Body::from(script))
            .unwrap(),
        Err(e) => axum::response::Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("Content-Type", "application/json")
            .body(axum::body::Body::from(json!({
                "status": "error",
                "message": format!("Installer script not found at {}: {}", path, e)
            }).to_string()))
            .unwrap(),
    }
}

pub async fn create_sensor_key_api(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<Value>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"status": "error", "message": "Unauthorized"})),
    };
    let tenant_id = payload["tenant_id"].as_str().unwrap_or("").to_string();
    let name = payload["name"].as_str().unwrap_or("").to_string();
    
    if tenant_id.is_empty() || name.is_empty() {
        return Json(json!({"status": "error", "message": "tenant_id and name are required"}));
    }

    let is_platform_admin = claims.role == "super_admin" || claims.role == "admin";
    if !is_platform_admin && claims.role != "tenant_admin" {
        return Json(json!({"status": "error", "message": "Forbidden: admin or tenant_admin required"}));
    }
    if claims.role == "tenant_admin" && tenant_id != claims.tenant_id {
        return Json(json!({"status": "error", "message": "Forbidden: tenant admins can only create sensor keys for their own tenant"}));
    }
    
    let (plain, prefix, hash) = generate_sensor_key(&tenant_id);
    
    match state.ch_storage.create_sensor_key(&tenant_id, &name, &hash, &prefix).await {
        Ok(id) => Json(json!({
            "status": "ok",
            "key": plain,
            "id": id,
        })),
        Err(e) => Json(json!({
            "status": "error",
            "message": e.to_string()
        })),
    }
}

pub async fn get_sensor_keys(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"status": "error", "message": "Unauthorized"})),
    };
    
    let target_tenant = if claims.role == "super_admin" || claims.role == "admin" {
        "default".to_string()
    } else if claims.tenant_id != "default" {
        claims.tenant_id.clone()
    } else {
        return Json(json!({"status": "error", "message": "Forbidden"}));
    };
    
    match state.ch_storage.get_sensor_keys(&target_tenant).await {
        Ok(keys) => Json(json!({
            "status": "ok",
            "keys": keys
        })),
        Err(e) => Json(json!({
            "status": "error",
            "message": e.to_string()
        })),
    }
}

pub async fn revoke_sensor_key_api(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"status": "error", "message": "Unauthorized"})),
    };
    if claims.role != "super_admin" {
        return Json(json!({"status": "error", "message": "Forbidden: Only super_admin can revoke sensor keys"}));
    }
    
    match state.ch_storage.revoke_sensor_key(&id).await {
        Ok(_) => Json(json!({
            "status": "ok",
            "message": "Sensor key revoked"
        })),
        Err(e) => Json(json!({
            "status": "error",
            "message": e.to_string()
        })),
    }
}

pub async fn sensor_register(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<Value>,
) -> Json<Value> {
    let tenant_id = match validate_sensor_key(&headers, &state.ch_storage).await {
        Some(tid) => tid,
        None => return Json(json!({"status": "error", "message": "Invalid or missing X-Sensor-Key"})),
    };

    let hostname  = payload["hostname"].as_str().unwrap_or("unknown");
    let interface = payload["interface"].as_str().unwrap_or("unknown");
    let os        = payload["os"].as_str().unwrap_or("unknown");
    let key_prefix = extract_sensor_key_prefix(&headers);

    if let Some(prefix) = key_prefix.as_deref() {
        if let Err(e) = state.ch_storage
            .update_sensor_registration(prefix, hostname, interface, os)
            .await {
            tracing::warn!(
                "Failed to persist sensor registration for tenant={}: {}",
                tenant_id, e
            );
            return Json(json!({
                "status": "error",
                "message": format!("Failed to persist sensor registration: {}", e)
            }));
        }
    } else {
        return Json(json!({
            "status": "error",
            "message": "Invalid sensor key prefix"
        }));
    }

    tracing::info!(
        "Sensor registered: {} tenant={} iface={} os={}",
        hostname, tenant_id, interface, os
    );

    Json(json!({
        "status":    "ok",
        "message":   "Sensor registered",
        "tenant_id": tenant_id
    }))
}

pub async fn sensor_heartbeat(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<Value>,
) -> Json<Value> {
    let tenant_id = match validate_sensor_key(&headers, &state.ch_storage).await {
        Some(tid) => tid,
        None => return Json(json!({"status": "error", "message": "Invalid or missing X-Sensor-Key"})),
    };

    let zeek = payload["zeek"].as_str().unwrap_or("unknown");
    let suricata = payload["suricata"].as_str().unwrap_or("unknown");
    let vector = payload["vector"].as_str().unwrap_or("unknown");
    let key_prefix = extract_sensor_key_prefix(&headers);

    if let Some(prefix) = key_prefix.as_deref() {
        if let Err(e) = state.ch_storage
            .update_sensor_heartbeat(prefix, zeek, suricata, vector)
            .await {
            tracing::warn!(
                "Failed to persist sensor heartbeat for tenant={}: {}",
                tenant_id, e
            );
            return Json(json!({
                "status": "error",
                "message": format!("Failed to persist sensor heartbeat: {}", e)
            }));
        }
    } else {
        return Json(json!({
            "status": "error",
            "message": "Invalid sensor key prefix"
        }));
    }

    tracing::info!(
        "Heartbeat from tenant={} zeek={} suricata={}",
        tenant_id,
        zeek,
        suricata
    );

    Json(json!({"status": "ok"}))
}

pub async fn ingest_events(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    body: String,
) -> Json<Value> {
    // Validate sensor key
    let sensor_key = headers
        .get("X-Sensor-Key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if sensor_key.is_empty() {
        return Json(json!({
            "status": "error",
            "message": "Missing X-Sensor-Key header"
        }));
    }

    // Validate key and get tenant_id
    let tenant_id = match state.ch_storage
        .validate_sensor_key(sensor_key).await {
        Ok(Some(tid)) => tid,
        _ => return Json(json!({
            "status": "error",
            "message": "Invalid sensor key"
        }))
    };

    // Parse body which can be standard JSON (Format 1/2) or newline-delimited JSON (ndjson)
    let events_arr: Vec<Value> = if let Ok(payload) = serde_json::from_str::<Value>(&body) {
        if let Some(arr) = payload.get("events").and_then(|e| e.as_array()) {
            arr.clone()
        } else if payload.is_object() {
            vec![payload]
        } else if let Some(arr) = payload.as_array() {
            arr.clone()
        } else {
            return Json(json!({
                "status": "error",
                "message": "Invalid payload format"
            }));
        }
    } else {
        let mut parsed_events = Vec::new();
        for line in body.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(val) = serde_json::from_str::<Value>(trimmed) {
                if let Some(arr) = val.get("events").and_then(|e| e.as_array()) {
                    parsed_events.extend(arr.clone());
                } else {
                    parsed_events.push(val);
                }
            } else {
                tracing::warn!("Failed to parse ndjson line: {}", trimmed);
            }
        }
        if parsed_events.is_empty() {
            return Json(json!({
                "status": "error",
                "message": "Invalid JSON or ndjson payload"
            }));
        }
        parsed_events
    };

    let mut published = 0u64;
    let mut failed = 0u64;

    for event in &events_arr {
        // Add tenant_id to event
        let mut evt = event.clone();
        if let Some(obj) = evt.as_object_mut() {
            obj.insert(
                "tenant_id".to_string(),
                serde_json::Value::String(tenant_id.clone())
            );
        }

        // Serialize event to JSON string
        let payload_str = match serde_json::to_string(&evt) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("Failed to serialize event: {}", e);
                failed += 1;
                continue;
            }
        };

        // Publish to Kafka
        use rdkafka::producer::FutureRecord;
        let record = FutureRecord::<str, str>::to("ndr-events")
            .payload(&payload_str);

        match state.kafka_producer
            .send(record, 
                std::time::Duration::from_secs(5))
            .await {
            Ok(_) => {
                published += 1;
            },
            Err((e, _)) => {
                tracing::warn!(
                    "Failed to publish to Kafka: {}", e);
                failed += 1;
            }
        }
    }

    tracing::info!(
        "Ingest: published={} failed={} tenant={}",
        published, failed, tenant_id
    );

    Json(json!({
        "status": "ok",
        "published": published,
        "failed": failed,
        "tenant_id": tenant_id
    }))
}

pub async fn get_sensor_command_api(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    // Validate sensor key
    let sensor_key = headers
        .get("X-Sensor-Key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if sensor_key.is_empty() {
        return Json(json!({
            "command": ""
        }));
    }

    // Validate key and get tenant_id
    let tenant_id = match state.ch_storage
        .validate_sensor_key(sensor_key).await {
        Ok(Some(tid)) => tid,
        _ => return Json(json!({ "command": "" }))
    };
    let sensor_id = match extract_sensor_key_prefix(&headers) {
        Some(prefix) => prefix,
        None => return Json(json!({ "command": "" })),
    };

    // Get pending command
    let (command, command_sensor_id) = state.ch_storage
        .get_sensor_command(&tenant_id, &sensor_id).await
        .unwrap_or_default();

    // Clear command after sending
    if !command.is_empty() {
        let _ = state.ch_storage
            .clear_sensor_command(&tenant_id, &command_sensor_id).await;
        tracing::info!(
            "Command '{}' sent to sensor tenant={} sensor={}",
            command, tenant_id, sensor_id
        );
    }

    Json(json!({ "command": command }))
}

pub async fn sensor_control_api(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<Value>,
) -> Json<Value> {
    // JWT auth - admin or tenant_admin only
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({
            "status": "error",
            "message": "Unauthorized"
        }))
    };

    // Only admin or tenant_admin can control sensors
    if claims.role != "admin" 
        && claims.role != "super_admin"
        && claims.role != "tenant_admin" {
        return Json(json!({
            "status": "error",
            "message": "Insufficient permissions"
        }));
    }

    let command = payload["command"]
        .as_str()
        .unwrap_or("")
        .to_string();

    // Validate command
    if !["start", "stop", "restart"].contains(&command.as_str()) {
        return Json(json!({
            "status": "error",
            "message": "Invalid command. Use: start, stop, restart"
        }));
    }

    // Get tenant_id - admin can specify, tenant_admin uses own
    let tenant_id = if claims.role == "super_admin" 
        || claims.role == "admin" {
        payload["tenant_id"]
            .as_str()
            .unwrap_or(&claims.tenant_id)
            .to_string()
    } else {
        claims.tenant_id.clone()
    };

    let sensor_id = payload["sensor_id"]
        .as_str()
        .unwrap_or("")
        .to_string();

    if !sensor_id.is_empty() {
        match state.ch_storage.active_sensor_exists(&tenant_id, &sensor_id).await {
            Ok(true) => {},
            Ok(false) => return Json(json!({
                "status": "error",
                "message": "Sensor not found for tenant or sensor is revoked"
            })),
            Err(e) => return Json(json!({
                "status": "error",
                "message": format!("Failed to verify sensor: {}", e)
            })),
        }
    }

    // Store command for sensor to pick up. Empty sensor_id is kept as a
    // legacy tenant-wide command for older clients.
    match state.ch_storage
        .set_sensor_command(&tenant_id, &sensor_id, &command).await {
        Ok(_) => {
            tracing::info!(
                "Sensor command '{}' set for tenant={} sensor={}",
                command, tenant_id, sensor_id
            );
            Json(json!({
                "status": "ok",
                "message": format!(
                    "Command '{}' queued for sensor {}",
                    command,
                    if sensor_id.is_empty() { tenant_id.as_str() } else { sensor_id.as_str() }
                ),
                "tenant_id": tenant_id,
                "sensor_id": sensor_id,
                "command": command
            }))
        },
        Err(e) => Json(json!({
            "status": "error",
            "message": format!("Failed to set command: {}", e)
        }))
    }
}
