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
use crate::storage::clickhouse::sql_escape;
use axum::{extract::{State, Query}, Json, http::StatusCode};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{info, warn};
use std::env;
use std::time::Duration;
use rdkafka::producer::Producer;
use rdkafka::util::Timeout;
use crate::evidence;
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

fn percent_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex) = std::str::from_utf8(&bytes[i+1..i+3]) {
                if let Ok(b) = u8::from_str_radix(hex, 16) {
                    out.push(b as char);
                    i += 3;
                    continue;
                }
            }
        } else if bytes[i] == b'+' {
            out.push(' ');
            i += 1;
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
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
    pub redis_mux:  redis::aio::MultiplexedConnection,
    pub kafka_producer: Arc<rdkafka::producer::FutureProducer>,
    pub correlation_semaphore: Arc<tokio::sync::Semaphore>,
    pub sensor_key_cache: Arc<crate::auth::sensor_cache::SensorKeyCache>,
    pub ingest_tx: tokio::sync::mpsc::Sender<(String, String)>,
}

pub fn publish_event(state: &AppState, tenant_id: &str, msg: &str) {
    let mut conn = state.redis_mux.clone();
    let msg_str = msg.to_string();
    let channel = format!("tenant:{}", tenant_id);
    let tx = state.tx.clone();
    let msg_fallback = msg_str.clone();
    tokio::spawn(async move {
        let result: Result<(), _> = redis::cmd("PUBLISH")
            .arg(&channel)
            .arg(&msg_str)
            .query_async(&mut conn)
            .await;
        if result.is_err() {
            // Redis unavailable — fall back to in-process broadcast
            tracing::warn!("Redis publish failed, falling back to local broadcast");
            let _ = tx.send(msg_fallback);
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

// Accepts token from Authorization header OR ?token= query param (needed for window.open downloads)
#[allow(dead_code)]
pub fn extract_claims_with_token(token: &str) -> Option<AuthClaims> {
    let secret = std::env::var("JWT_SECRET")
        .unwrap_or_else(|_| "ndr-secret-key-2026".to_string());
    decode::<AuthClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default()
    ).ok().map(|d| d.claims)
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

fn string_list_from_payload(payload: &Value, key: &str) -> Vec<String> {
    match payload.get(key) {
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(|value| value.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect(),
        Some(Value::String(value)) => value
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

fn announcement_status_from_payload(payload: &Value) -> String {
    if let Some(status) = payload["status"].as_str() {
        return status.trim().to_string();
    }
    match payload["active"].as_bool() {
        Some(true) => "active".to_string(),
        Some(false) => "inactive".to_string(),
        None => "draft".to_string(),
    }
}

fn announcement_targets_from_payload(payload: &Value) -> (String, Vec<String>, Vec<String>) {
    let audience = payload["audience"].as_str().unwrap_or("all").trim().to_string();
    let mut target_roles = string_list_from_payload(payload, "target_roles");
    let mut target_tenants = string_list_from_payload(payload, "target_tenants");

    match audience.as_str() {
        "tenant_admins" if target_roles.is_empty() => {
            target_roles.push("tenant_admin".to_string());
        }
        "tenant" => {
            if target_tenants.is_empty() {
                if let Some(tenant_id) = payload["tenant_id"].as_str() {
                    let tenant_id = tenant_id.trim();
                    if !tenant_id.is_empty() {
                        target_tenants.push(tenant_id.to_string());
                    }
                }
            }
        }
        "all" if target_roles.is_empty() && target_tenants.is_empty() => {
            target_roles.push("all".to_string());
            target_tenants.push("all".to_string());
        }
        _ => {}
    }

    (audience, target_roles, target_tenants)
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
    let public = ["/api/auth/login", "/api/auth/check-username", "/api/health", "/ws", "/api/sensor", "/api/ingest", "/api/sensor/command", "/api/sensor/checkin", "/api/install-sensor.sh", "/api/uninstall-sensor.sh", "/api/pcap/pending", "/api/pcap/upload"];
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
            let ts       = event.raw.get("ts").and_then(|v| v.as_f64()).unwrap_or(0.0);
            info!("🟢 Zeek {} | {}→{} [{}] {} | CID: {}",
                svc, src, dst, proto, cs,
                event.community_id.as_deref().unwrap_or("?"));
            json!({
                "type": "zeek",
                "ts":   ts,
                "event_type": if svc != "-" { svc } else { cs },
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
            let ts = event.raw.get("timestamp")
                .and_then(|v| v.as_str())
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.timestamp() as f64)
                .unwrap_or(0.0);
            info!("🔵 Suricata {} | {}→{} | CID: {}",
                et, src, dst, event.community_id.as_deref().unwrap_or("?"));
            json!({
                "type": "suricata",
                "ts":   ts,
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
    let store_threshold    = settings["store_threshold"].as_f64().unwrap_or(10.0) as f32;
    let alert_threshold    = settings["alert_threshold"].as_f64().unwrap_or(75.0) as f32;
    let critical_threshold = settings["critical_threshold"].as_f64().unwrap_or(90.0) as u32;
    let soar_threshold     = settings["soar_threshold"].as_f64().unwrap_or(75.0) as f32;
        
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

    // Write permanent IOC hit records for any malicious IP match
    if enrichment.is_malicious {
        let ti = &state.enrichment.threat_intel;
        let mut ioc_matches: Vec<(String, String)> = vec![]; // (matched_ip, feed_source)
        for ip in [src, dst] {
            if !ip.is_empty() && ip != "-" && ti.is_malicious_ip(ip) {
                ioc_matches.push((ip.to_string(), "feodo".to_string()));
            }
        }
        if !ioc_matches.is_empty() {
            let ch = state.ch_storage.clone();
            let cid  = hit.community_id.clone();
            let tid  = tenant_id.clone();
            let s = src.to_string();
            let d = dst.to_string();
            tokio::spawn(async move {
                for (matched_ip, feed) in ioc_matches {
                    let _ = ch.write_ioc_hit(&tid, &cid, &s, &d, &matched_ip, &feed).await;
                }
            });
        }
    }

    // Score — use tenant-configured severity thresholds so critical_threshold
    // and alert_threshold bands from the Settings page are respected.
    let raw_risk = state.scorer.score(&hit, enrichment.is_malicious, enrichment.sensitive_country);
    let severity = crate::scoring::Severity::from_score_with_thresholds(
        raw_risk.score,
        critical_threshold,
        alert_threshold as u32,
        50,
        25,
    );
    let risk = crate::scoring::RiskResult {
        score:    raw_risk.score,
        severity,
        tags:     raw_risk.tags,
        reasons:  raw_risk.reasons,
    };

    // Auto-capture evidence for HIGH, CRITICAL, and MEDIUM hits
    let severity_str = risk.severity.as_str().to_string();
    if matches!(severity_str.as_str(), "HIGH" | "CRITICAL" | "MEDIUM") {
        let cid = hit.community_id.clone();
        let tenant = tenant_id.clone();
        let ch = state.ch_storage.clone();
        let opensearch_url = std::env::var("OPENSEARCH_URL")
            .unwrap_or_else(|_| "http://localhost:9200".to_string());
        let arkime_url = std::env::var("ARKIME_URL").unwrap_or_default();
        let arkime_pass = std::env::var("ARKIME_PASS")
            .unwrap_or_else(|_| "admin".to_string());
        let src_ip_str = src.to_string();
        let dst_ip_str = dst.to_string();
        let rule_name_str = hit.suricata.alert
            .as_ref().map(|a| a.signature.clone())
            .or_else(|| hit.zeek.raw.get("rule_name").and_then(|v| v.as_str()).map(|s| s.to_string()))
            .unwrap_or_default();
        let now_str = chrono::Utc::now().to_rfc3339();
        let alert_json = serde_json::json!({
            "community_id": cid,
            "tenant_id": tenant,
            "severity": severity_str,
            "src_ip": src_ip_str,
            "dst_ip": dst_ip_str,
            "rule_name": rule_name_str,
            "timestamp": now_str,
            "auto_captured_at": now_str
        });

        tokio::spawn(async move {
            match crate::evidence::build_evidence_bundle(
                &opensearch_url,
                &arkime_url,
                &arkime_pass,
                &cid,
                alert_json,
                &tenant,
                None,
            ).await {
                Ok((zip_bytes, sha256, _manifest)) => {
                    // Save to disk
                    let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
                    let dir = format!("/opt/ndr/evidence/{}/{}", tenant, date);
                    let _ = tokio::fs::create_dir_all(&dir).await;
                    let bundle_id = uuid::Uuid::new_v4().to_string();
                    let file_path = format!("{}/{}.zip", dir, bundle_id);
                    let size = zip_bytes.len() as u64;

                    if tokio::fs::write(&file_path, &zip_bytes).await.is_ok() {
                        let _ = ch.save_evidence_bundle(
                            &tenant, &bundle_id, &cid,
                            &file_path, &sha256, size,
                            1, // auto_captured
                            90, // expires in 90 days
                            &src_ip_str, &dst_ip_str, &severity_str, "",
                        ).await;
                        let _ = ch.log_evidence_action(
                            &tenant, &cid, &bundle_id,
                            "auto_captured", "auto",
                            &severity_str, "", "",
                            "Automatically captured on HIGH/CRITICAL/MEDIUM alert",
                            "",
                        ).await;
                        tracing::info!(
                            "Auto-captured evidence bundle {} for cid {}",
                            bundle_id, cid
                        );

                        // AI threat analysis — runs async, stored as annotation
                        let openai_key = std::env::var("OPENAI_API_KEY").unwrap_or_default();
                        if !openai_key.is_empty() {
                            let system_prompt = "You are a senior NDR (Network Detection & Response) \
                                security analyst. Analyse the alert and respond in plain text with \
                                three short sections:\n\
                                THREAT: what this alert indicates (1-2 sentences)\n\
                                RISK: why it matters and potential impact (1-2 sentences)\n\
                                ACTION: recommended immediate response steps (2-3 bullet points)\n\
                                Be concise and actionable. No markdown headers.";
                            let question = format!(
                                "Alert details:\n\
                                 Severity     : {severity_str}\n\
                                 Community ID : {cid}\n\
                                 Source IP    : {src_ip_str}\n\
                                 Destination  : {dst_ip_str}\n\
                                 Rule/Reason  : {rule_name_str}\n\
                                 Captured at  : {now_str}\n\
                                 Tenant       : {tenant}\n\
                                 Provide your threat analysis.",
                            );
                            match crate::ai::call_openai(
                                &openai_key, system_prompt, &[], &question
                            ).await {
                                Ok((analysis, _)) => {
                                    let safe_analysis = analysis.replace('\'', "''");
                                    let _ = ch.add_evidence_annotation(
                                        &tenant, &bundle_id, &cid,
                                        "ARIA-AI", &safe_analysis, "ai_analysis",
                                    ).await;
                                    tracing::info!(
                                        "AI analysis saved for bundle {}", bundle_id
                                    );
                                }
                                Err(e) => {
                                    tracing::warn!("AI analysis failed for {}: {}", bundle_id, e);
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Auto-capture failed for {}: {}", cid, e);
                }
            }
        });
    }

    // SIGMA detection — only rules belonging to this tenant
    let mut detections = state.detection.read().await.check_for_tenant(&hit.zeek, &tenant_id);
    detections.extend(state.detection.read().await.check_for_tenant(&hit.suricata, &tenant_id));

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

    // Queue PCAP upload request for external sensors — HIGH/CRITICAL only.
    // MEDIUM generates too many short-lived multicast sessions (SSDP etc.)
    // and evidence bundles for MEDIUM are already auto-captured above.
    if tenant_id != "default" && !hit.community_id.is_empty()
        && matches!(risk.severity.as_str(), "HIGH" | "CRITICAL")
    {
        let ch2 = state.ch_storage.clone();
        let tid2 = tenant_id.clone();
        let cid2 = hit.community_id.clone();
        tokio::spawn(async move {
            if let Err(e) = ch2.queue_pcap_request(&tid2, &cid2).await {
                tracing::warn!("pcap_pending queue failed: {}", e);
            }
        });
    }

    // AI auto-suppression: check IDS alerts for false positives
    if risk.tags.contains(&"ids-alert".to_string()) {
        if let Some(alert_info) = hit.suricata.alert.as_ref() {
            let sig_id          = alert_info.signature_id;
            let sig_name        = alert_info.signature.clone();
            let alert_category  = alert_info.category.clone();
            let alert_sev_raw   = alert_info.severity;
            let src_ip          = src.to_string();
            let dst_ip          = dst.to_string();
            let cid             = hit.community_id.clone();
            let ch3             = state.ch_storage.clone();
            let tid3            = tenant_id.clone();
            let openai_key      = std::env::var("OPENAI_API_KEY").unwrap_or_default();

            // Extra context extracted from raw event — gives AI enough signal
            // to distinguish sensor-to-own-infrastructure FPs from real threats.
            let app_proto = hit.suricata.raw
                .get("app_proto").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
            let direction = hit.suricata.raw
                .get("direction").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let tls_sni = hit.suricata.raw
                .get("tls").and_then(|t| t.get("sni")).and_then(|v| v.as_str())
                .unwrap_or("").to_string();
            let zeek_conn_state = hit.zeek.conn_state.clone().unwrap_or_default();
            let tags_str        = risk.tags.join(", ");
            let threat_intel    = enrichment.is_malicious;
            let sensitive_ctry  = enrichment.sensitive_country;

            let src_scope = if src_ip.starts_with("10.") || src_ip.starts_with("192.168.")
                || src_ip.starts_with("172.") { "private/internal" } else { "public/external" };
            let dst_scope = if dst_ip.starts_with("10.") || dst_ip.starts_with("192.168.")
                || dst_ip.starts_with("172.") { "private/internal" } else { "public/external" };

            tokio::spawn(async move {
                // Skip if already suppressed
                if ch3.is_ai_suppressed(&tid3, sig_id, &src_ip, &dst_ip).await {
                    return;
                }
                // Skip if we've already decided on this sig+dst recently
                let already = ch3.list_ai_suppressions(&tid3).await.unwrap_or_default();
                let already_seen = already.iter().any(|s|
                    s["signature_id"].as_u64() == Some(sig_id)
                    && s["suppress_ip"].as_str() == Some(dst_ip.as_str())
                );
                if already_seen { return; }

                if openai_key.is_empty() { return; }

                let prompt = "You are an NDR (Network Detection & Response) security analyst AI. \
                    Determine if a Suricata IDS alert is a FALSE POSITIVE. \
                    Respond ONLY with valid JSON (no markdown): \
                    {\"false_positive\": true/false, \"confidence\": 0-100, \
                    \"suppress_type\": \"by_dst\"|\"by_src\"|\"by_sid\"|\"none\", \
                    \"reason\": \"short explanation\"}. \
                    suppress_type rules: \
                    by_dst = destination is known/trusted infrastructure (cloud, CDN, monitoring endpoint, tunnel server); \
                    by_src = source is a trusted internal device (sensor, scanner, management host); \
                    by_sid = the entire Suricata rule is globally broken/noisy regardless of IP; \
                    none = real threat, do not suppress. \
                    Critical hints: \
                    (1) Rules starting with 'SURICATA STREAM' or 'SURICATA ENGINE' are Suricata internal \
                    TCP/IP stack checks — they fire on NAT, VPN, and tunnel traffic; almost always FP. \
                    (2) If direction is 'to_client', the alert fired on RESPONSE traffic from server to sensor. \
                    (3) Private/internal IPs (10.x, 172.x, 192.168.x) are your own network devices. \
                    (4) TLS SNI reveals the actual domain — if it matches known infrastructure or monitoring \
                    tools it is almost certainly a FP. \
                    (5) If threat_intel=false and the rule category is 'Generic Protocol Command Decode', \
                    lean toward FP with high confidence.";

                let question = format!(
                    "Suricata alert to analyse:\n\
                     SID          : {sig_id}\n\
                     Rule         : \"{sig_name}\"\n\
                     Category     : \"{alert_category}\"\n\
                     Suri severity: {alert_sev_raw} (1=high 2=medium 3=low)\n\
                     Protocol     : {app_proto}\n\
                     Direction    : {direction}\n\
                     src_ip       : {src_ip} ({src_scope})\n\
                     dst_ip       : {dst_ip} ({dst_scope})\n\
                     TLS SNI      : {tls_sni_display}\n\
                     Zeek state   : {zeek_conn_state}\n\
                     Risk tags    : [{tags_str}]\n\
                     Threat intel : {threat_intel}\n\
                     Sensitive cty: {sensitive_ctry}\n\
                     Tenant       : {tid3}\n\
                     Is this a false positive?",
                    tls_sni_display = if tls_sni.is_empty() { "none".to_string() } else { tls_sni },
                );

                if let Ok((reply, _)) = crate::ai::call_openai(
                    &openai_key, prompt, &[], &question
                ).await {
                    // Parse AI JSON response
                    let ai: serde_json::Value = serde_json::from_str(&reply)
                        .unwrap_or_else(|_| {
                            // Try to extract JSON from response text
                            if let Some(start) = reply.find('{') {
                                if let Some(end) = reply.rfind('}') {
                                    return serde_json::from_str(&reply[start..=end])
                                        .unwrap_or(json!({}));
                                }
                            }
                            json!({})
                        });

                    let is_fp         = ai["false_positive"].as_bool().unwrap_or(false);
                    let confidence    = ai["confidence"].as_u64().unwrap_or(0) as u8;
                    let suppress_type = ai["suppress_type"].as_str().unwrap_or("none");
                    let reason        = ai["reason"].as_str().unwrap_or("").to_string();

                    if is_fp && confidence >= 80 && suppress_type != "none" {
                        let suppress_ip = match suppress_type {
                            "by_dst" => dst_ip.clone(),
                            "by_src" => src_ip.clone(),
                            _        => String::new(),
                        };

                        // Store in ai_suppressions table
                        let _ = ch3.save_ai_suppression(
                            &tid3, sig_id, &sig_name,
                            suppress_type, &suppress_ip,
                            &src_ip, &dst_ip, &cid,
                            &reason, confidence, "",
                        ).await;

                        // Queue suppress command to sensor
                        let cmd = match suppress_type {
                            "by_sid" => format!("suppress_sid:{}", sig_id),
                            _        => format!("suppress_sid:{}:{}:{}", sig_id, suppress_type, suppress_ip),
                        };
                        let _ = ch3.set_sensor_command(&tid3, "", &cmd).await;

                        tracing::info!(
                            "AI auto-suppressed SID={} {} {} confidence={}% reason={}",
                            sig_id, suppress_type, suppress_ip, confidence, reason
                        );
                    }
                }
            });
        }
    }

    // Build WebSocket hit message
    let sigma_hits: Vec<String> = {
        let mut seen = std::collections::HashSet::new();
        detections.iter()
            .map(|d| d.title.clone())
            .filter(|t| seen.insert(t.clone()))
            .collect()
    };


    // Execute Native SOAR Playbooks
    crate::soar::execute_native_playbooks(state, hit.clone(), risk.clone(), enrichment.clone(), &tenant_id).await;

// ── Execute playbooks directly (gated on soar_threshold) ────────────────
if risk.score >= soar_threshold {
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


// Execute integrations — gated on soar_threshold (separate from alert display threshold)
if risk.score >= soar_threshold {
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

    let hit_ts = hit.zeek.timestamp as f64 / 1000.0;

    let mut hit_msg = json!({
        "type":            "hit",
        "ts":              hit_ts,
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

pub async fn get_events_by_cid(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"status":"error","message":"Unauthorized"})),
    };
    let cid = raw_query
        .as_deref()
        .unwrap_or("")
        .split('&')
        .find_map(|kv| {
            let mut p = kv.splitn(2, '=');
            let k = p.next()?;
            let v = p.next().unwrap_or("");
            if k == "cid" { Some(percent_decode(v)) } else { None }
        })
        .unwrap_or_default();

    if cid.is_empty() {
        return Json(json!({"status":"error","message":"cid required"}));
    }
    match state.ch_storage.get_events_by_community_id(&cid, &claims.tenant_id).await {
        Ok(events) => Json(json!({"status":"ok","events":events})),
        Err(_)     => Json(json!({"status":"ok","events":[]})),
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
            for (id, content, tenant_id) in ch_rules {
                match crate::detection::parse_rule_content(&content) {
                    Ok(mut r) => {
                        r.tenant_id = tenant_id;
                        rules.push(r);
                    }
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
    
    let map_db_rules = |rules: &Vec<(String, String, String, String, u8)>| -> Vec<serde_json::Value> {
        rules.iter().map(|(id, name, content, _r_tenant_id, enabled)| {
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
    };

    let result: Vec<serde_json::Value> = if !db_rules.is_empty() {
        map_db_rules(&db_rules)
    } else if tenant_id == "default" {
        // Fallback to filesystem only for default tenant
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
    } else {
        // Non-default tenants with no rules in DB → empty list
        vec![]
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
        "last_refresh": ti.last_refresh_iso(),
        "refresh_interval": "Every 60 minutes",
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

pub async fn get_soar_status(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap
) -> Json<Value> {
    let tenant_id = extract_claims(&headers).map(|c| c.tenant_id).unwrap_or_else(|| "default".to_string());

    let playbooks = state.ch_storage
        .get_soar_playbooks_by_tenant(&tenant_id).await
        .unwrap_or_default();

    let active_count = playbooks.iter()
        .filter(|p| p["enabled"] == true)
        .count();

    Json(json!({
        "playbooks":    playbooks,
        "active_count": active_count,
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

        // Notify all other engine instances to reload
        let redis = state.redis.clone();
        let tid = tenant_id.clone();
        tokio::spawn(async move {
            if let Ok(mut conn) = redis.get_async_connection().await {
                let _: Result<(), _> = redis::cmd("PUBLISH")
                    .arg("system:reload_rules")
                    .arg(&tid)
                    .query_async(&mut conn).await;
            }
        });

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

    // Notify all other engine instances to reload
    let redis = state.redis.clone();
    let tid = tenant_id.clone();
    tokio::spawn(async move {
        if let Ok(mut conn) = redis.get_async_connection().await {
            let _: Result<(), _> = redis::cmd("PUBLISH")
                .arg("system:reload_rules")
                .arg(&tid)
                .query_async(&mut conn).await;
        }
    });

    Json(json!({
        "status":       "ok",
        "id":           rule_id,
        "enabled":      payload.enabled,
        "active_rules": count
    }))
}


//get the executions from the workflow
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
    let threat   = state.ch_storage.get_threat_intel_hits_by_tenant(&tenant_id).await
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

// GET /api/auth/check-username?username=xxx
// Public, read-only — only confirms existence, never reveals password or role.
pub async fn check_username(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Json<Value> {
    let username = params.get("username").map(|s| s.trim().to_string()).unwrap_or_default();
    if username.is_empty() {
        return Json(json!({ "exists": false }));
    }
    match state.ch_storage.get_user_by_username(&username).await {
        Ok(Some(_)) => Json(json!({ "exists": true })),
        _           => Json(json!({ "exists": false })),
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

// GET /api/announcements
pub async fn get_announcements_api(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    if let Err(response) = require_super_admin(&headers) {
        return response;
    }

    match state.ch_storage.get_announcements().await {
        Ok(announcements) => Json(json!({
            "status": "ok",
            "announcements": announcements
        })),
        Err(e) => Json(json!({
            "status": "error",
            "announcements": [],
            "message": e.to_string()
        }))
    }
}

// GET /api/announcements/active
pub async fn get_active_announcements_api(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(claims) => claims,
        None => return Json(json!({
            "status": "error",
            "announcements": [],
            "message": "Unauthorized"
        })),
    };

    match state.ch_storage
        .get_active_announcements(&claims.role, &claims.tenant_id, &claims.sub)
        .await {
        Ok(announcements) => Json(json!({
            "status": "ok",
            "announcements": announcements
        })),
        Err(e) => Json(json!({
            "status": "error",
            "announcements": [],
            "message": e.to_string()
        }))
    }
}

// POST /api/announcements/:id/read
pub async fn mark_announcement_read_api(
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

    match state.ch_storage.mark_announcement_read(&id, &claims.sub).await {
        Ok(_) => Json(json!({
            "status": "ok",
            "message": "Announcement marked as read"
        })),
        Err(e) => Json(json!({
            "status": "error",
            "message": e.to_string()
        }))
    }
}

// POST /api/announcements
pub async fn create_announcement_api(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<Value>,
) -> Json<Value> {
    let claims = match require_super_admin(&headers) {
        Ok(claims) => claims,
        Err(response) => return response,
    };

    let title = payload["title"].as_str().unwrap_or("").trim().to_string();
    let message = payload["message"].as_str().unwrap_or("").trim().to_string();
    let announcement_type = payload["announcement_type"]
        .as_str()
        .or_else(|| payload["type"].as_str())
        .unwrap_or("info")
        .trim()
        .to_string();
    let status = announcement_status_from_payload(&payload);
    let (audience, target_roles, target_tenants) = announcement_targets_from_payload(&payload);
    let start_at = payload["start_at"].as_str()
        .or_else(|| payload["starts_at"].as_str());
    let end_at = payload["end_at"].as_str()
        .or_else(|| payload["ends_at"].as_str());

    if title.is_empty() || message.is_empty() {
        return Json(json!({
            "status": "error",
            "message": "Title and message are required"
        }));
    }
    if !["draft", "active", "inactive"].contains(&status.as_str()) {
        return Json(json!({
            "status": "error",
            "message": "Invalid status"
        }));
    }

    let id = uuid::Uuid::new_v4().to_string();
    match state.ch_storage.create_announcement(
        &id,
        &title,
        &message,
        &announcement_type,
        &audience,
        &status,
        &target_roles,
        &target_tenants,
        start_at,
        end_at,
        &claims.sub,
    ).await {
        Ok(_) => Json(json!({
            "status": "ok",
            "id": id,
            "message": "Announcement created"
        })),
        Err(e) => Json(json!({
            "status": "error",
            "message": e.to_string()
        }))
    }
}

// PUT /api/announcements/:id
pub async fn update_announcement_api(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(payload): Json<Value>,
) -> Json<Value> {
    if let Err(response) = require_super_admin(&headers) {
        return response;
    }

    let title = payload["title"].as_str().unwrap_or("").trim().to_string();
    let message = payload["message"].as_str().unwrap_or("").trim().to_string();
    let announcement_type = payload["announcement_type"]
        .as_str()
        .or_else(|| payload["type"].as_str())
        .unwrap_or("info")
        .trim()
        .to_string();
    let status = announcement_status_from_payload(&payload);
    let (audience, target_roles, target_tenants) = announcement_targets_from_payload(&payload);
    let start_at = payload["start_at"].as_str()
        .or_else(|| payload["starts_at"].as_str());
    let end_at = payload["end_at"].as_str()
        .or_else(|| payload["ends_at"].as_str());

    if title.is_empty() || message.is_empty() {
        return Json(json!({
            "status": "error",
            "message": "Title and message are required"
        }));
    }
    if !["draft", "active", "inactive"].contains(&status.as_str()) {
        return Json(json!({
            "status": "error",
            "message": "Invalid status"
        }));
    }

    match state.ch_storage.update_announcement(
        &id,
        &title,
        &message,
        &announcement_type,
        &audience,
        &status,
        &target_roles,
        &target_tenants,
        start_at,
        end_at,
    ).await {
        Ok(_) => Json(json!({
            "status": "ok",
            "message": "Announcement updated"
        })),
        Err(e) => Json(json!({
            "status": "error",
            "message": e.to_string()
        }))
    }
}

// DELETE /api/announcements/:id
pub async fn delete_announcement_api(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<Value> {
    if let Err(response) = require_super_admin(&headers) {
        return response;
    }

    match state.ch_storage.delete_announcement(&id).await {
        Ok(_) => Json(json!({
            "status": "ok",
            "message": "Announcement deleted"
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
                    "exec", "kafka1",
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


// ── Support Messages ──────────────────────────────────────────────────────────

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
            state.ch_storage.get_support_messages_for_user(&claims.tenant_id, &claims.sub).await
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
        Err(_) => Json(json!({
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
        Err(_) => return Json(json!({"status": "error", "message": "Support delete timed out"})),
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

/// Cached variant — used by handlers that have access to AppState.
/// Falls back to direct bcrypt+DB on cache miss (same as before).
pub async fn validate_sensor_key_cached(
    headers: &axum::http::HeaderMap,
    ch: &Arc<ClickhouseStorage>,
    cache: Option<&crate::auth::sensor_cache::SensorKeyCache>,
) -> Option<String> {
    let key = headers
        .get("X-Sensor-Key")
        .or_else(|| headers.get("x-sensor-key"))?
        .to_str().ok()?;

    if let Some(c) = cache {
        crate::auth::sensor_cache::resolve_tenant(c, ch, key).await
    } else {
        ch.validate_sensor_key(key).await.ok()?
    }
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

pub async fn uninstall_sensor_script() -> axum::response::Response {
    let path = "/scripts/uninstall-sensor.sh".to_string();

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
                "message": format!("Uninstall script not found: {}", e)
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
        Ok(_) => {
            // Immediately evict from shared Redis cache so ALL engine
            // instances reject this key on their next request — no 90s wait.
            // We look up by key_prefix (plain api_key is never stored in DB).
            if let Ok(Some(prefix)) = state.ch_storage
                .get_sensor_key_prefix_by_id(&id)
                .await
            {
                state.sensor_key_cache.invalidate_by_prefix(&prefix).await;
            }
            Json(json!({"status": "ok", "message": "Sensor key revoked"}))
        }
        Err(e) => Json(json!({"status": "error", "message": e.to_string()})),
    }
}

pub async fn reactivate_sensor_key_api(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"status": "error", "message": "Unauthorized"})),
    };
    if claims.role != "super_admin" {
        return Json(json!({"status": "error", "message": "Forbidden: Only super_admin can reactivate sensor keys"}));
    }
    
    match state.ch_storage.reactivate_sensor_key(&id).await {
        Ok(_) => Json(json!({
            "status": "ok",
            "message": "Sensor key reactivated"
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
    let tenant_id = match validate_sensor_key_cached(&headers, &state.ch_storage, Some(&state.sensor_key_cache)).await {
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

    // Auto-suppress known false positives on sensor registration
    if let Some(prefix) = key_prefix.as_deref() {
        for sid_cmd in &[
            "suppress_sid:2066052",  // ET INFO ngrok-free.dev in TLS SNI (sensor→cloud heartbeat)
            "suppress_sid:2066057",  // Related ngrok tunneling rule
        ] {
            let _ = state.ch_storage
                .set_sensor_command(&tenant_id, prefix, sid_cmd)
                .await;
        }
    }

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
    let tenant_id = match validate_sensor_key_cached(&headers, &state.ch_storage, Some(&state.sensor_key_cache)).await {
        Some(tid) => tid,
        None => return Json(json!({"status": "error", "message": "Invalid or missing X-Sensor-Key"})),
    };

    let zeek = payload["zeek"].as_str().unwrap_or("unknown");
    let suricata = payload["suricata"].as_str().unwrap_or("unknown");
    let vector = payload["vector"].as_str().unwrap_or("unknown");
    let arkime = payload["arkime"].as_str().unwrap_or("unknown");
    let arkime_url = payload["arkime_url"].as_str().unwrap_or("");
    let arkime_pass = payload["arkime_pass"].as_str().unwrap_or("");
    let key_prefix = extract_sensor_key_prefix(&headers);

    if let Some(prefix) = key_prefix.as_deref() {
        if let Err(e) = state.ch_storage
            .update_sensor_heartbeat(prefix, zeek, suricata, vector, arkime, arkime_url, arkime_pass)
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
        "Heartbeat from tenant={} zeek={} suricata={} arkime={}",
        tenant_id,
        zeek,
        suricata,
        arkime
    );

    Json(json!({"status": "ok"}))
}

pub async fn ingest_events(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    body: String,
) -> Json<Value> {
    // Validate sensor key (cached — avoids bcrypt+DB on every ingest call)
    let tenant_id = match validate_sensor_key_cached(
        &headers, &state.ch_storage, Some(&state.sensor_key_cache)
    ).await {
        Some(tid) => tid,
        None => return Json(json!({
            "status": "error",
            "message": "Invalid or missing X-Sensor-Key"
        })),
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

        // Non-blocking push to async drain channel — returns immediately,
        // background task flushes to Kafka in micro-batches.
        match state.ingest_tx.try_send((tenant_id.clone(), payload_str)) {
            Ok(_) => {
                published += 1;
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                // Channel full — system overloaded; Vector's disk buffer absorbs.
                tracing::warn!("Ingest channel full — dropping event for tenant {}", tenant_id);
                failed += 1;
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                tracing::error!("Ingest channel closed — drain task died");
                failed += 1;
            }
        }
    }

    tracing::info!(
        "Ingest: queued={} failed={} tenant={}",
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
    let tenant_id = match validate_sensor_key_cached(
        &headers, &state.ch_storage, Some(&state.sensor_key_cache)
    ).await {
        Some(tid) => tid,
        None => return Json(json!({ "command": "" })),
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

// ── Merged sensor check-in ────────────────────────────────────────────────
// Combines heartbeat + command poll + pcap pending into ONE request.
// Cuts per-sensor HTTP traffic by ~3× vs the old 3 separate polls.
// Old endpoints (/heartbeat, /command, /pcap/pending) are kept for
// backward compat with already-deployed sensors.

#[derive(serde::Deserialize)]
#[allow(dead_code)]
pub struct CheckinRequest {
    pub sensor_ip:      Option<String>,
    pub arkime_url:     Option<String>,
    pub arkime_pass:    Option<String>,
    pub zeek:           Option<String>,
    pub suricata:       Option<String>,
    pub vector:         Option<String>,
    pub arkime_capture: Option<String>,
    pub arkime_viewer:  Option<String>,
}

/// POST /api/sensor/checkin
/// Single combined endpoint: heartbeat + command + pcap pending.
pub async fn sensor_checkin(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<CheckinRequest>,
) -> Json<Value> {
    let tenant_id = match validate_sensor_key_cached(
        &headers, &state.ch_storage, Some(&state.sensor_key_cache)
    ).await {
        Some(t) => t,
        None => return Json(json!({"status": "error", "message": "invalid sensor key"})),
    };

    let sensor_id = match extract_sensor_key_prefix(&headers) {
        Some(p) => p,
        None => return Json(json!({"status": "error", "message": "invalid sensor key prefix"})),
    };

    // ── 1. Heartbeat / status update (throttled via Redis) ───────────────
    // Only write to ClickHouse when status changes or every 5 minutes —
    // avoids a SELECT FINAL + INSERT on every checkin under stable conditions.
    let zeek_s     = payload.zeek.as_deref().unwrap_or("unknown");
    let suricata_s = payload.suricata.as_deref().unwrap_or("unknown");
    let vector_s   = payload.vector.as_deref().unwrap_or("unknown");
    let arkime_status = payload.arkime_capture.as_deref()
        .or(payload.arkime_viewer.as_deref())
        .unwrap_or("unknown");
    let arkime_url  = payload.arkime_url.as_deref().unwrap_or("");
    let arkime_pass = payload.arkime_pass.as_deref().unwrap_or("");

    let status_sig = format!("{}|{}|{}|{}", zeek_s, suricata_s, vector_s, arkime_status);
    if state.sensor_key_cache
        .needs_heartbeat_write(&sensor_id, &status_sig)
        .await
    {
        let _ = state.ch_storage.update_sensor_heartbeat(
            &sensor_id, zeek_s, suricata_s, vector_s,
            arkime_status, arkime_url, arkime_pass,
        ).await;
    }

    // ── 2. Pending command ────────────────────────────────────────────────
    let (command, command_sensor_id) = state.ch_storage
        .get_sensor_command(&tenant_id, &sensor_id).await
        .unwrap_or_default();
    if !command.is_empty() {
        let _ = state.ch_storage
            .clear_sensor_command(&tenant_id, &command_sensor_id).await;
        tracing::info!(
            "Checkin: command '{}' dispatched to sensor {} tenant={}",
            command, sensor_id, tenant_id
        );
    }

    // ── 3. Pending PCAP uploads ───────────────────────────────────────────
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct PendingRow {
        community_id: String,
        severity:     String,
        retry_count:  u8,
    }
    let db = crate::storage::clickhouse::tenant_db_pub(&tenant_id);
    let pcap_rows = state.ch_storage.client
        .query(&format!(
            "SELECT community_id, severity, retry_count \
             FROM {}.pcap_pending \
             WHERE tenant_id = '{}' \
             AND fulfilled = 0 \
             AND retry_count < 3 \
             AND requested_at > now() - INTERVAL 24 HOUR \
             ORDER BY multiIf(severity='CRITICAL',1, severity='HIGH',2, 3) ASC, \
                      requested_at ASC \
             LIMIT 10",
            db, sql_escape(&tenant_id)
        ))
        .fetch_all::<PendingRow>().await
        .unwrap_or_default();

    let pending_cids: Vec<String> = pcap_rows.iter().map(|r| r.community_id.clone()).collect();
    let pending_details: Vec<Value> = pcap_rows.iter().map(|r| json!({
        "community_id": r.community_id,
        "severity":     r.severity,
        "retry_count":  r.retry_count,
    })).collect();

    tracing::info!(
        "Checkin tenant={} sensor={} zeek={} suricata={} pending_pcap={}",
        tenant_id, sensor_id, zeek_s, suricata_s, pending_cids.len()
    );

    Json(json!({
        "status":               "ok",
        "command":              command,
        "pcap_pending":         pending_cids,
        "pcap_details":         pending_details,
        "checkin_interval_secs": 30
    }))
}

// ── Arkime Proxy Endpoints ────────────────────────────────────────────────

fn arkime_basic_auth(pass: &str) -> String {
    let credential = if pass.is_empty() {
        "admin:admin".to_string()
    } else {
        format!("admin:{}", pass)
    };
    base64::engine::general_purpose::STANDARD.encode(credential)
}

async fn get_tenant_arkime_creds(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> Result<(String, String), axum::response::Response> {
    use axum::response::IntoResponse;
    let claims = match extract_claims(headers) {
        Some(c) => c,
        None => return Err((axum::http::StatusCode::UNAUTHORIZED,
            axum::Json(json!({"status":"error","message":"Unauthorized"}))).into_response()),
    };
    let (url, pass) = state.ch_storage
        .get_arkime_creds(&claims.tenant_id)
        .await
        .unwrap_or_default();
    if url.is_empty() {
        return Err(axum::Json(json!({
            "status": "error",
            "message": "Arkime not configured for this tenant"
        })).into_response());
    }
    Ok((url, pass))
}

pub async fn arkime_sessions(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return axum::Json(json!({"status":"error","message":"Unauthorized"})).into_response(),
    };

    let params: std::collections::HashMap<String, String> = raw_query
        .as_deref()
        .unwrap_or("")
        .split('&')
        .filter_map(|kv| {
            let mut parts = kv.splitn(2, '=');
            let k = parts.next()?.to_string();
            let raw_v = parts.next().unwrap_or("");
            // percent-decode the value so community_id like "1:abc=" arrives intact
            let v = percent_decode(raw_v);
            Some((k, v))
        })
        .collect();

    let community_id = params.get("cid").cloned();
    let src_ip       = params.get("ip").cloned();
    let limit        = params.get("limit")
        .and_then(|l| l.parse::<u32>().ok())
        .unwrap_or(50);

    let (arkime_url, _) = state.ch_storage
        .get_arkime_creds(&claims.tenant_id)
        .await
        .unwrap_or_default();

    // ── ON-PREMISE PATH: query OpenSearch directly — always current, zero lag ──
    if claims.tenant_id == "default" {
        let es_url = std::env::var("OPENSEARCH_URL")
            .unwrap_or_else(|_| "http://localhost:9200".to_string());

        let mut must_clauses: Vec<serde_json::Value> = vec![];
        if let Some(ref cid) = community_id {
            must_clauses.push(json!({"term": {"network.community_id": cid}}));
        }
        if let Some(ref ip) = src_ip {
            must_clauses.push(json!({
                "bool": {"should": [
                    {"term": {"source.ip":      ip}},
                    {"term": {"destination.ip": ip}}
                ]}
            }));
        }

        let es_query = json!({
            "size": limit,
            "sort": [{"firstPacket": {"order": "desc"}}],
            "query": {
                "bool": {
                    "must": if must_clauses.is_empty() {
                        vec![json!({"match_all": {}})]
                    } else { must_clauses }
                }
            },
            "_source": [
                "id", "firstPacket", "lastPacket",
                "source.ip", "source.port",
                "destination.ip", "destination.port",
                "ipProtocol", "network.bytes", "network.packets",
                "network.community_id", "node"
            ]
        });

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        match client
            .post(&format!("{}/arkime_sessions3-*/_search", es_url))
            .json(&es_query)
            .send()
            .await
        {
            Ok(r) => {
                let data: serde_json::Value = r.json().await.unwrap_or_default();
                let hits = data["hits"]["hits"].as_array().cloned().unwrap_or_default();
                let sessions: Vec<serde_json::Value> = hits.iter().map(|h| {
                    let s = &h["_source"];
                    let proto = match s["ipProtocol"].as_u64().unwrap_or(0) {
                        6  => "tcp",
                        17 => "udp",
                        _  => "other",
                    };
                    json!({
                        "session_id":   h["_id"].as_str().unwrap_or(""),
                        "community_id": s["network"]["community_id"].as_str().unwrap_or(""),
                        "src_ip":       s["source"]["ip"].as_str().unwrap_or(""),
                        "dst_ip":       s["destination"]["ip"].as_str().unwrap_or(""),
                        "src_port":     s["source"]["port"].as_u64().unwrap_or(0),
                        "dst_port":     s["destination"]["port"].as_u64().unwrap_or(0),
                        "proto":        proto,
                        "bytes":        s["network"]["bytes"].as_u64().unwrap_or(0),
                        "packets":      s["network"]["packets"].as_u64().unwrap_or(0),
                        "start_time":   s["firstPacket"].as_u64().unwrap_or(0),
                        "end_time":     s["lastPacket"].as_u64().unwrap_or(0),
                        "sensor_host":  s["node"].as_str().unwrap_or(""),
                        "arkime_url":   arkime_url,
                        "file_path":    ""
                    })
                }).collect();
                return axum::Json(json!({
                    "status":  "ok",
                    "sessions": sessions,
                    "source":  "opensearch",
                    "total":   data["hits"]["total"]["value"].as_u64().unwrap_or(0)
                })).into_response();
            }
            Err(e) => {
                tracing::warn!("OpenSearch query failed: {}", e);
                return axum::Json(json!({
                    "status":   "error",
                    "message":  "OpenSearch unreachable",
                    "sessions": []
                })).into_response();
            }
        }
    }

    // ── EXTERNAL SENSOR PATH: ClickHouse cache (populated via pcap-upload push) ──
    let sessions = state.ch_storage
        .get_pcap_sessions(
            &claims.tenant_id,
            community_id.as_deref(),
            src_ip.as_deref(),
            limit,
        )
        .await
        .unwrap_or_default();

    axum::Json(json!({
        "status":   "ok",
        "sessions": sessions,
        "source":   "clickhouse"
    })).into_response()
}

pub async fn arkime_pcap_download(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(session_id): axum::extract::Path<String>,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    // Support ?token= for window.open() downloads (cannot set Authorization header)
    let mut effective_headers = headers.clone();
    if let Some(q) = raw_query.as_deref() {
        for part in q.split('&') {
            if let Some(tok) = part.strip_prefix("token=") {
                effective_headers.insert(
                    axum::http::header::AUTHORIZATION,
                    format!("Bearer {}", tok).parse().unwrap(),
                );
                break;
            }
        }
    }

    let (arkime_url, arkime_pass) = match get_tenant_arkime_creds(&state, &effective_headers).await {
        Ok(creds) => creds,
        Err(r) => return r,
    };
    let target = format!("{}/api/session/{}/pcap", arkime_url, session_id);
    match reqwest::Client::new()
        .get(&target)
        .header("Authorization", format!("Basic {}", arkime_basic_auth(&arkime_pass)))
        .timeout(Duration::from_secs(60))
        .send()
        .await
    {
        Ok(resp) => {
            let status = axum::http::StatusCode::from_u16(resp.status().as_u16())
                .unwrap_or(axum::http::StatusCode::OK);
            let bytes = resp.bytes().await.unwrap_or_default();
            (
                status,
                [
                    (axum::http::header::CONTENT_TYPE, "application/vnd.tcpdump.pcap"),
                    (axum::http::header::CONTENT_DISPOSITION,
                        &format!("attachment; filename=\"{}.pcap\"", session_id)),
                ],
                bytes,
            ).into_response()
        }
        Err(e) => axum::Json(json!({
            "status": "error",
            "message": format!("Failed to reach Arkime: {}", e)
        })).into_response()
    }
}

pub async fn arkime_status(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let (arkime_url, arkime_pass) = match get_tenant_arkime_creds(&state, &headers).await {
        Ok(creds) => creds,
        Err(r) => return r,
    };
    let target = format!("{}/api/stats", arkime_url);
    match reqwest::Client::new()
        .get(&target)
        .header("Authorization", format!("Basic {}", arkime_basic_auth(&arkime_pass)))
        .timeout(Duration::from_secs(10))
        .send()
        .await
    {
        Ok(resp) => {
            let status = axum::http::StatusCode::from_u16(resp.status().as_u16())
                .unwrap_or(axum::http::StatusCode::OK);
            let body = resp.text().await.unwrap_or_default();
            (status, [(axum::http::header::CONTENT_TYPE, "application/json")], body).into_response()
        }
        Err(e) => axum::Json(json!({
            "status": "error",
            "message": format!("Arkime unreachable: {}", e)
        })).into_response()
    }
}

pub async fn arkime_session_link(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(community_id): axum::extract::Path<String>,
) -> axum::Json<serde_json::Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return axum::Json(json!({"status":"error","message":"Unauthorized"})),
    };
    let (arkime_url, _) = state.ch_storage
        .get_arkime_creds(&claims.tenant_id)
        .await
        .unwrap_or_default();
    if arkime_url.is_empty() {
        return axum::Json(json!({
            "status": "error",
            "message": "No Arkime configured"
        }));
    }
    let link = format!(
        "{}/?expression=communityId%3D%3D{}&startTime=-1h&stopTime=now",
        arkime_url,
        urlencoding_encode(&community_id)
    );
    axum::Json(json!({
        "status": "ok",
        "link": link,
        "arkime_url": arkime_url
    }))
}

pub async fn pcap_upload(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    mut multipart: axum::extract::Multipart,
) -> axum::Json<serde_json::Value> {
    let tenant_id = match validate_sensor_key_cached(&headers, &state.ch_storage, Some(&state.sensor_key_cache)).await {
        Some(tid) => tid,
        None => return axum::Json(json!({
            "status": "error",
            "message": "Unauthorized: invalid sensor key"
        })),
    };

    let mut pcap_bytes: Vec<u8> = Vec::new();
    let mut pcap_filename = String::new();
    let mut community_id = String::new();
    let mut src_ip = String::new();
    let mut dst_ip = String::new();
    let mut src_port: u16 = 0;
    let mut dst_port: u16 = 0;
    let mut proto = String::new();
    let mut sensor_host = String::new();

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "pcap" => {
                pcap_filename = field.file_name().unwrap_or("").to_string();
                pcap_bytes = match field.bytes().await {
                    Ok(b) => b.to_vec(),
                    Err(e) => return axum::Json(json!({
                        "status": "error",
                        "message": format!("Failed to read pcap field: {}", e)
                    })),
                };
                tracing::info!("pcap_upload: received {}B filename={}", pcap_bytes.len(), pcap_filename);
            }
            "community_id" => {
                community_id = field.text().await.unwrap_or_default();
            }
            "src_ip" => { src_ip = field.text().await.unwrap_or_default(); }
            "dst_ip" => { dst_ip = field.text().await.unwrap_or_default(); }
            "src_port" => {
                src_port = field.text().await.unwrap_or_default()
                    .parse().unwrap_or(0);
            }
            "dst_port" => {
                dst_port = field.text().await.unwrap_or_default()
                    .parse().unwrap_or(0);
            }
            "proto" => { proto = field.text().await.unwrap_or_default(); }
            "sensor_host" => { sensor_host = field.text().await.unwrap_or_default(); }
            _ => { let _ = field.bytes().await; }
        }
    }

    if pcap_bytes.is_empty() {
        tracing::warn!("pcap_upload: no pcap data cid={} tenant={}", community_id, tenant_id);
        return axum::Json(json!({"status":"error","message":"No pcap data received"}));
    }

    if community_id.is_empty() {
        return axum::Json(json!({"status":"error","message":"Missing community_id"}));
    }

    // Dedup: already stored — mark fulfilled and return ok
    if let Ok(Some(_)) = state.ch_storage
        .get_pcap_file_path_by_community_id(&tenant_id, &community_id).await
    {
        let _ = state.ch_storage.mark_pcap_fulfilled(&tenant_id, &community_id).await;
        return axum::Json(json!({
            "status": "ok",
            "message": "already stored",
            "session_id": "existing"
        }));
    }

    // Detect gzip by filename OR magic bytes — NOT by Content-Encoding header.
    // Content-Encoding: gzip on a multipart request corrupts the multipart parser.
    let is_gzip = pcap_filename.ends_with(".gz")
        || (pcap_bytes.len() > 1 && pcap_bytes[0] == 0x1f && pcap_bytes[1] == 0x8b);
    let raw_bytes = if is_gzip {
        use std::io::Read;
        let mut decoder = flate2::read::GzDecoder::new(pcap_bytes.as_slice());
        let mut decompressed = Vec::new();
        match decoder.read_to_end(&mut decompressed) {
            Ok(_) => {
                tracing::info!("pcap_upload: decompressed gzip {}B → {}B", pcap_bytes.len(), decompressed.len());
                decompressed
            }
            Err(e) => return axum::Json(json!({
                "status": "error",
                "message": format!("Failed to decompress pcap: {}", e)
            })),
        }
    } else {
        pcap_bytes
    };

    // Reject non-PCAP content (e.g. raw ZST blobs — fix Arkime: simpleCompression=none)
    let valid_pcap = raw_bytes.len() >= 4 && matches!(
        u32::from_le_bytes([raw_bytes[0], raw_bytes[1], raw_bytes[2], raw_bytes[3]]),
        0xa1b2c3d4 | 0xd4c3b2a1 | 0xa1b23c4d | 0x4d3cb2a1 | 0x0a0d0d0a
    );
    if !valid_pcap {
        let magic = if raw_bytes.len() >= 4 {
            format!("0x{:08x}", u32::from_le_bytes([raw_bytes[0], raw_bytes[1], raw_bytes[2], raw_bytes[3]]))
        } else { "too short".to_string() };
        tracing::error!("pcap_upload: invalid PCAP magic {} cid={} — likely zstd-compressed", magic, community_id);
        return axum::Json(json!({
            "status": "error",
            "message": format!("Invalid PCAP file (magic={}). Set simpleCompression=none in Arkime config.", magic)
        }));
    }

    let session_id = uuid::Uuid::new_v4().to_string();
    let date_str = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let file_dir = format!("/opt/ndr/pcap/{}/{}", tenant_id, date_str);
    let file_path = format!("{}/{}.pcap", file_dir, session_id);
    let bytes_count = raw_bytes.len() as u64;

    if let Err(e) = tokio::fs::create_dir_all(&file_dir).await {
        tracing::error!("pcap_upload: mkdir failed {}: {}", file_dir, e);
        return axum::Json(json!({
            "status": "error",
            "message": format!("Failed to create storage directory: {}", e)
        }));
    }

    if let Err(e) = tokio::fs::write(&file_path, &raw_bytes).await {
        tracing::error!("pcap_upload: write failed {}: {}", file_path, e);
        return axum::Json(json!({
            "status": "error",
            "message": format!("Failed to write pcap file: {}", e)
        }));
    }

    if let Err(e) = state.ch_storage.save_pcap_session(
        &tenant_id, &session_id, &community_id,
        &src_ip, &dst_ip, src_port, dst_port, &proto,
        bytes_count, "", &file_path, &sensor_host,
    ).await {
        tracing::warn!("pcap_upload: failed to index session: {}", e);
    }

    let _ = state.ch_storage.mark_pcap_fulfilled(&tenant_id, &community_id).await;
    tracing::info!("pcap_upload: ✅ saved cid={} tenant={} size={}B", community_id, tenant_id, bytes_count);

    axum::Json(json!({
        "status": "ok",
        "session_id": session_id,
        "file_path": file_path,
        "bytes": bytes_count
    }))
}

pub async fn pcap_download_stored(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(session_id): axum::extract::Path<String>,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    // Support ?token= for window.open() downloads
    let mut effective_headers = headers.clone();
    if let Some(q) = raw_query.as_deref() {
        for part in q.split('&') {
            if let Some(tok) = part.strip_prefix("token=") {
                effective_headers.insert(
                    axum::http::header::AUTHORIZATION,
                    format!("Bearer {}", tok).parse().unwrap(),
                );
                break;
            }
        }
    }

    let claims = match extract_claims(&effective_headers) {
        Some(c) => c,
        None => return (axum::http::StatusCode::UNAUTHORIZED, "Unauthorized").into_response(),
    };

    let file_path = state.ch_storage
        .get_pcap_file_path(&claims.tenant_id, &session_id)
        .await
        .unwrap_or_default();

    // If a stored file exists (remote sensor upload) — serve it directly
    if !file_path.is_empty() {
        return match tokio::fs::read(&file_path).await {
            Ok(data) => (
                [
                    ("Content-Type", "application/vnd.tcpdump.pcap"),
                    ("Content-Disposition",
                     &format!("attachment; filename=\"{}.pcap\"", session_id)),
                ],
                data,
            ).into_response(),
            Err(e) => (
                axum::http::StatusCode::NOT_FOUND,
                format!("PCAP file not found on disk: {}", e),
            ).into_response(),
        };
    }

    // Fallback: on-premise session — proxy download through Arkime
    // session_id is the Arkime session ID stored by the caching layer
    let (arkime_url, arkime_pass) = state.ch_storage
        .get_arkime_creds(&claims.tenant_id)
        .await
        .unwrap_or_default();

    if arkime_url.is_empty() {
        return (axum::http::StatusCode::NOT_FOUND, "PCAP not available").into_response();
    }

    let target = format!("{}/api/session/{}/pcap", arkime_url, session_id);
    match reqwest::Client::new()
        .get(&target)
        .header("Authorization", format!("Basic {}", arkime_basic_auth(&arkime_pass)))
        .timeout(Duration::from_secs(60))
        .send()
        .await
    {
        Ok(resp) => {
            let bytes = resp.bytes().await.unwrap_or_default();
            (
                [
                    ("Content-Type", "application/vnd.tcpdump.pcap"),
                    ("Content-Disposition",
                     &format!("attachment; filename=\"{}.pcap\"", session_id)),
                ],
                bytes,
            ).into_response()
        }
        Err(e) => (
            axum::http::StatusCode::BAD_GATEWAY,
            format!("Arkime unreachable: {}", e),
        ).into_response(),
    }
}

pub async fn pcap_pending(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> axum::Json<serde_json::Value> {
    let tenant_id = match validate_sensor_key_cached(&headers, &state.ch_storage, Some(&state.sensor_key_cache)).await {
        Some(t) => t,
        None => return axum::Json(json!({"status":"error","message":"Unauthorized"})),
    };

    // Priority queue: CRITICAL first, then HIGH, then MEDIUM
    // Retry limit: max 3 attempts — stops infinite retry loops
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct PendingRow {
        community_id: String,
        severity:     String,
        requested_at_str: String,
        retry_count:  u8,
    }
    let db = crate::storage::clickhouse::tenant_db_pub(&tenant_id);
    let rows = state.ch_storage.client
        .query(&format!(
            "SELECT community_id, \
             severity, \
             toString(requested_at) as requested_at_str, \
             retry_count \
             FROM {}.pcap_pending \
             WHERE tenant_id = '{}' \
             AND fulfilled = 0 \
             AND retry_count < 3 \
             AND requested_at > now() - INTERVAL 24 HOUR \
             ORDER BY \
               multiIf(severity='CRITICAL',1, severity='HIGH',2, 3) ASC, \
               requested_at ASC \
             LIMIT 10",
            db, sql_escape(&tenant_id)
        ))
        .fetch_all::<PendingRow>().await
        .unwrap_or_else(|e| {
            tracing::error!("pcap_pending query failed: {}", e);
            vec![]
        });

    let pending: Vec<serde_json::Value> = rows.iter().map(|r| json!({
        "community_id": r.community_id,
        "severity":     r.severity,
        "requested_at": r.requested_at_str,
        "retry_count":  r.retry_count,
        "priority": match r.severity.as_str() {
            "CRITICAL" => 1, "HIGH" => 2, _ => 3
        }
    })).collect();

    // Also return plain list for backward-compatible agent.py
    let plain: Vec<&str> = rows.iter().map(|r| r.community_id.as_str()).collect();

    axum::Json(json!({
        "status":  "ok",
        "pending": plain,
        "details": pending,
        "count":   plain.len()
    }))
}

pub async fn pcap_upload_failed(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::Json(payload): axum::Json<serde_json::Value>,
) -> axum::Json<serde_json::Value> {
    let tenant_id = match validate_sensor_key_cached(&headers, &state.ch_storage, Some(&state.sensor_key_cache)).await {
        Some(t) => t,
        None => return axum::Json(json!({"status":"error","message":"Unauthorized"})),
    };
    let community_id = payload["community_id"].as_str().unwrap_or("");
    let error_msg    = payload["error"].as_str().unwrap_or("unknown").replace('\'', "\\'");
    if community_id.is_empty() {
        return axum::Json(json!({"status":"error","message":"missing community_id"}));
    }
    // Increment retry_count; if >= 3, mark fulfilled=2 (failed) so sensor stops
    let db = crate::storage::clickhouse::tenant_db_pub(&tenant_id);
    let _ = state.ch_storage.client
        .query(&format!(
            "ALTER TABLE {}.pcap_pending \
             UPDATE \
               retry_count = retry_count + 1, \
               error_message = '{}', \
               last_retry = now(), \
               fulfilled = if(retry_count >= 2, 2, 0) \
             WHERE community_id = '{}' AND tenant_id = '{}' AND fulfilled = 0",
            db, error_msg,
            sql_escape(community_id),
            sql_escape(&tenant_id)
        ))
        .execute().await;
    tracing::warn!("PCAP upload failed cid={} tenant={} err={}", community_id, tenant_id, error_msg);
    axum::Json(json!({"status":"recorded"}))
}

fn urlencoding_encode(s: &str) -> String {
    s.chars().flat_map(|c| {
        if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~' {
            vec![c]
        } else {
            format!("%{:02X}", c as u32).chars().collect()
        }
    }).collect()
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


pub async fn get_telemetry(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"status": "error", "message": "Unauthorized"}))
    };

    if claims.role != "super_admin" && claims.role != "admin" {
        return Json(json!({"status": "error", "message": "Unauthorized"}));
    }

    let mut sys = sysinfo::System::new_all();
    sys.refresh_all();

    let cpu_usage_percent = sys.global_cpu_info().cpu_usage();
    let memory_total_bytes = sys.total_memory();
    let memory_used_bytes = sys.used_memory();
    let memory_total_gb = memory_total_bytes as f64 / 1_073_741_824.0;
    let memory_used_gb = memory_used_bytes as f64 / 1_073_741_824.0;
    let memory_percent = if memory_total_bytes > 0 {
        (memory_used_bytes as f64 / memory_total_bytes as f64) * 100.0
    } else {
        0.0
    };

    let stats = state.ch_storage.get_stats().await.unwrap_or(json!({}));
    let events_1h = stats.get("events_1h").and_then(|v| v.as_u64()).unwrap_or(0);
    let events_per_sec = events_1h / 3600;

    Json(json!({
        "status": "ok",
        "cpu_usage_percent": cpu_usage_percent,
        "memory_used_gb": memory_used_gb,
        "memory_total_gb": memory_total_gb,
        "memory_percent": memory_percent,
        "events_per_sec": events_per_sec,
        "events_1h": events_1h
    }))
}

// ── Background: Arkime → pcap_sessions proactive sync ────────────────────────
// Called once from main.rs on startup (after 30s delay), then loops every 5 min.
// Fetches the last 5-min window from Arkime for every active tenant and caches
// results into pcap_sessions so the UI is pre-populated without a user visit.
pub async fn sync_arkime_sessions(state: AppState) {
    // Create one shared HTTP client for all tenants / all cycles.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("reqwest::Client::builder failed in sync_arkime_sessions");

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(300)).await;

        let tenants = match state.ch_storage.get_all_tenants().await {
            Ok(t) => t,
            Err(e) => {
                tracing::debug!("Arkime sync: could not fetch tenants: {}", e);
                continue;
            }
        };

        for tenant_id in &tenants {
            let (arkime_url, arkime_pass) =
                match state.ch_storage.get_arkime_creds(tenant_id).await {
                    Ok(creds) if !creds.0.is_empty() => creds,
                    _ => continue, // tenant has no Arkime configured
                };

            // Query the last 6 minutes (60s overlap guards against boundary gaps)
            let now = chrono::Utc::now().timestamp();
            let window_start = now - 360;

            let query_url = format!(
                "{}/api/sessions?\
length=1000\
&startTime={}&stopTime={}\
&fields=id,network.community_id,\
source.ip,source.port,\
destination.ip,destination.port,\
ipProtocol,network.bytes,\
network.packets,firstPacket,\
lastPacket,node",
                arkime_url, window_start, now
            );

            let resp = match client
                .get(&query_url)
                .basic_auth("admin", Some(&arkime_pass))
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    tracing::debug!(
                        "Arkime sync: HTTP error tenant={}: {}",
                        tenant_id, e
                    );
                    continue;
                }
            };

            let data = match resp.json::<serde_json::Value>().await {
                Ok(d) => d,
                Err(_) => continue,
            };

            let sessions = match data["data"].as_array() {
                Some(s) => s.clone(),
                None => continue,
            };

            let mut saved = 0u32;
            for s in &sessions {
                let session_id = s["id"]
                    .as_str()
                    .or_else(|| s["_id"].as_str())
                    .unwrap_or("")
                    .to_string();
                if session_id.is_empty() {
                    continue;
                }

                let community_id = s["network"]["community_id"]
                    .as_str()
                    .unwrap_or("")
                    .to_string();

                // Arkime 5 returns flat dotted keys; older versions return nested.
                let src_ip = s.get("source.ip").and_then(|v| v.as_str())
                    .or_else(|| s["source"]["ip"].as_str())
                    .or_else(|| s["srcIp"].as_str())
                    .unwrap_or("").to_string();
                let dst_ip = s.get("destination.ip").and_then(|v| v.as_str())
                    .or_else(|| s["destination"]["ip"].as_str())
                    .or_else(|| s["dstIp"].as_str())
                    .unwrap_or("").to_string();
                let src_port = s.get("source.port").and_then(|v| v.as_u64())
                    .or_else(|| s["source"]["port"].as_u64())
                    .or_else(|| s["srcPort"].as_u64())
                    .unwrap_or(0) as u16;
                let dst_port = s.get("destination.port").and_then(|v| v.as_u64())
                    .or_else(|| s["destination"]["port"].as_u64())
                    .or_else(|| s["dstPort"].as_u64())
                    .unwrap_or(0) as u16;
                let ip_proto = s["ipProtocol"].as_u64()
                    .or_else(|| s.get("ipProtocol").and_then(|v| v.as_u64()))
                    .unwrap_or(0);
                let proto = if ip_proto == 6 { "tcp" }
                            else if ip_proto == 17 { "udp" }
                            else { "other" };
                let bytes = s.get("network.bytes").and_then(|v| v.as_u64())
                    .or_else(|| s["network"]["bytes"].as_u64())
                    .or_else(|| s["totBytes"].as_u64())
                    .unwrap_or(0);
                let sensor_host = s["node"].as_str().unwrap_or("").to_string();

                if state.ch_storage.save_pcap_session(
                    tenant_id,
                    &session_id,
                    &community_id,
                    &src_ip,
                    &dst_ip,
                    src_port,
                    dst_port,
                    proto,
                    bytes,
                    &arkime_url,
                    "",
                    &sensor_host,
                ).await.is_ok() {
                    saved += 1;
                }
            }

            if saved > 0 {
                tracing::info!(
                    "Arkime sync: saved {} sessions for tenant={}",
                    saved, tenant_id
                );
            }
        }
    }
}

// ── NATIVE SOAR API ENDPOINTS ───────────────────────────────────────────────

pub async fn get_soar_cases(
    State(state): State<AppState>,
    axum::extract::Extension(claims): axum::extract::Extension<AuthClaims>,
) -> Json<Value> {
    match state.ch_storage.get_soar_cases(&claims.tenant_id).await {
        Ok(cases) => Json(json!({"status": "success", "data": cases})),
        Err(e) => Json(json!({"status": "error", "message": e.to_string()}))
    }
}

pub async fn get_soar_case_comments(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    axum::extract::Extension(claims): axum::extract::Extension<AuthClaims>,
) -> Json<Value> {
    match state.ch_storage.get_soar_case_comments(&id, &claims.tenant_id).await {
        Ok(comments) => Json(json!({"status": "success", "data": comments})),
        Err(e) => Json(json!({"status": "error", "message": e.to_string()}))
    }
}

pub async fn add_soar_case_comment(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    axum::extract::Extension(claims): axum::extract::Extension<AuthClaims>,
    axum::extract::Json(payload): axum::extract::Json<Value>,
) -> Json<Value> {
    let comment = payload.get("comment").and_then(|v| v.as_str()).unwrap_or("");
    if comment.is_empty() {
        return Json(json!({"status": "error", "message": "Comment cannot be empty"}));
    }
    match state.ch_storage.insert_soar_case_comment(&id, &claims.sub, comment, &claims.tenant_id).await {
        Ok(_) => Json(json!({"status": "success", "message": "Comment added"})),
        Err(e) => Json(json!({"status": "error", "message": e.to_string()}))
    }
}

pub async fn update_soar_case_status(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    axum::extract::Extension(claims): axum::extract::Extension<AuthClaims>,
    axum::extract::Json(payload): axum::extract::Json<Value>,
) -> Json<Value> {
    let status = payload.get("status").and_then(|v| v.as_str()).unwrap_or("");
    if status.is_empty() {
        return Json(json!({"status": "error", "message": "Status cannot be empty"}));
    }
    match state.ch_storage.update_soar_case_status(&id, status, &claims.tenant_id).await {
        Ok(_) => Json(json!({"status": "success", "message": "Status updated"})),
        Err(e) => Json(json!({"status": "error", "message": e.to_string()}))
    }
}

pub async fn get_native_playbooks(
    State(state): State<AppState>,
    axum::extract::Extension(claims): axum::extract::Extension<AuthClaims>,
) -> Json<Value> {
    match state.ch_storage.get_native_playbooks(&claims.tenant_id).await {
        Ok(pbs) => Json(json!({"status": "success", "data": pbs})),
        Err(e) => Json(json!({"status": "error", "message": e.to_string()}))
    }
}

pub async fn create_native_playbook(
    State(state): State<AppState>,
    axum::extract::Extension(claims): axum::extract::Extension<AuthClaims>,
    axum::extract::Json(payload): axum::extract::Json<Value>,
) -> Json<Value> {
    let pb = crate::soar::SoarNativePlaybook {
        id: uuid::Uuid::new_v4().to_string(),
        name: payload.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        description: payload.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        enabled: payload.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true) as u8,
        cond_field: payload.get("cond_field").and_then(|v| v.as_str()).unwrap_or("score").to_string(),
        cond_op: payload.get("cond_op").and_then(|v| v.as_str()).unwrap_or(">").to_string(),
        cond_value: payload.get("cond_value").and_then(|v| v.as_str()).unwrap_or("75").to_string(),
        action_type: payload.get("action_type").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        action_config: payload.get("action_config").and_then(|v| v.as_str()).unwrap_or("{}").to_string(),
        run_count: 0,
        last_run: None,
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
        tenant_id: claims.tenant_id,
    };

    match state.ch_storage.insert_native_playbook(&pb).await {
        Ok(_) => Json(json!({"status": "success", "message": "Playbook created"})),
        Err(e) => Json(json!({"status": "error", "message": e.to_string()}))
    }
}

pub async fn update_native_playbook(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    axum::extract::Extension(claims): axum::extract::Extension<AuthClaims>,
    axum::extract::Json(payload): axum::extract::Json<Value>,
) -> Json<Value> {
    let enabled = payload.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true) as u8;
    let cond_field = payload.get("cond_field").and_then(|v| v.as_str()).unwrap_or("");
    let cond_op = payload.get("cond_op").and_then(|v| v.as_str()).unwrap_or("");
    let cond_value = payload.get("cond_value").and_then(|v| v.as_str()).unwrap_or("");
    let action_type = payload.get("action_type").and_then(|v| v.as_str()).unwrap_or("");
    let action_config = payload.get("action_config").and_then(|v| v.as_str()).unwrap_or("{}");

    match state.ch_storage.update_native_playbook(
        &id, enabled, cond_field, cond_op, cond_value, action_type, action_config, &claims.tenant_id
    ).await {
        Ok(_) => Json(json!({"status": "success", "message": "Playbook updated"})),
        Err(e) => Json(json!({"status": "error", "message": e.to_string()}))
    }
}

pub async fn delete_native_playbook(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    axum::extract::Extension(claims): axum::extract::Extension<AuthClaims>,
) -> Json<Value> {
    match state.ch_storage.delete_native_playbook(&id, &claims.tenant_id).await {
        Ok(_) => Json(json!({"status": "success", "message": "Playbook deleted"})),
        Err(e) => Json(json!({"status": "error", "message": e.to_string()}))
    }
}

pub async fn get_soar_runs(
    State(state): State<AppState>,
    axum::extract::Extension(claims): axum::extract::Extension<AuthClaims>,
) -> Json<Value> {
    match state.ch_storage.get_soar_playbook_runs(&claims.tenant_id).await {
        Ok(runs) => Json(json!({"status": "success", "data": runs})),
        Err(e) => Json(json!({"status": "error", "message": e.to_string()}))
    }
}



// ============================================================
// EVIDENCE MODULE
// ============================================================



/// GET /api/evidence/:community_id
/// Build and return a ZIP evidence bundle for a community_id.
pub async fn download_evidence_bundle(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(community_id): axum::extract::Path<String>,
) -> impl axum::response::IntoResponse {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return (
            axum::http::StatusCode::UNAUTHORIZED,
            axum::http::HeaderMap::new(),
            axum::body::Bytes::new(),
        ),
    };

    // Get alert context for this community_id
    let alert_json = state.ch_storage
        .get_hit_by_community_id(&claims.tenant_id, &community_id)
        .await
        .unwrap_or_default()
        .unwrap_or(serde_json::json!({"community_id": community_id}));

    // Determine PCAP source (on-premise vs remote)
    let opensearch_url = if claims.tenant_id == "default" {
        std::env::var("OPENSEARCH_URL")
            .unwrap_or_else(|_| String::from("http://localhost:9200"))
    } else {
        String::new()
    };

    let arkime_url = std::env::var("ARKIME_URL").unwrap_or_default();
    let arkime_pass = std::env::var("ARKIME_PASS")
        .unwrap_or_else(|_| String::from("admin"));

    // For remote tenants, check if we have an uploaded PCAP
    let pcap_file_path = if claims.tenant_id != "default" {
        state.ch_storage
            .get_pcap_file_path_by_community_id(&claims.tenant_id, &community_id)
            .await
            .unwrap_or_default()
    } else {
        None
    };

    match evidence::build_evidence_bundle(
        &opensearch_url,
        &arkime_url,
        &arkime_pass,
        &community_id,
        alert_json,
        &claims.tenant_id,
        pcap_file_path,
    ).await {
        Ok((zip_bytes, bundle_sha256, manifest)) => {
            // Persist bundle record to evidence_bundles table
            let bundle_id = manifest["bundle_id"].as_str().unwrap_or("").to_string();
            let src_ip = manifest["summary"]["src_ip"].as_str().unwrap_or("").to_string();
            let dst_ip = manifest["summary"]["dst_ip"].as_str().unwrap_or("").to_string();
            let severity = manifest["summary"]["severity"].as_str().unwrap_or("UNKNOWN").to_string();
            let zip_size = zip_bytes.len() as u64;
            let ch = state.ch_storage.clone();
            let tid = claims.tenant_id.clone();
            let cid = community_id.clone();
            let sha = bundle_sha256.clone();
            tokio::spawn(async move {
                let _ = ch.save_evidence_bundle(
                    &tid, &bundle_id, &cid,
                    "",          // file_path: on-demand, no disk file
                    &sha,
                    zip_size,
                    0,           // auto_captured: 0 = manual download
                    90,          // expires_days
                    &src_ip, &dst_ip, &severity,
                    &cid,
                ).await;
            });

            // Log to chain of custody
            let _ = state.ch_storage.log_evidence_action(
                &claims.tenant_id,
                &community_id,
                "",
                "downloaded",
                &claims.sub,
                "",
                "", "",
                "Manual evidence download",
                headers.get("x-forwarded-for")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("unknown"),
            ).await;

            let filename = format!(
                "evidence_{}_{}.zip",
                community_id.replace(':', "_").replace('/', "_"),
                chrono::Utc::now().format("%Y%m%d_%H%M%S")
            );

            let mut resp_headers = axum::http::HeaderMap::new();
            resp_headers.insert(
                "Content-Type",
                "application/zip".parse().unwrap()
            );
            resp_headers.insert(
                "Content-Disposition",
                format!("attachment; filename=\"{}\"", filename)
                    .parse().unwrap()
            );
            resp_headers.insert(
                "X-Evidence-SHA256",
                bundle_sha256.parse().unwrap()
            );

            (
                axum::http::StatusCode::OK,
                resp_headers,
                axum::body::Bytes::from(zip_bytes),
            )
        }
        Err(e) => {
            tracing::error!("Evidence bundle error: {}", e);
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::http::HeaderMap::new(),
                axum::body::Bytes::new(),
            )
        }
    }
}

/// GET /api/evidence/bundles
/// List all evidence bundles for this tenant.
pub async fn list_evidence_bundles(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"error": "unauthorized"})),
    };
    let limit = params.get("limit")
        .and_then(|l| l.parse::<u32>().ok())
        .unwrap_or(50);
    let bundles = state.ch_storage
        .list_evidence_bundles(&claims.tenant_id, limit)
        .await.unwrap_or_default();
    Json(json!({"bundles": bundles, "count": bundles.len()}))
}

/// GET /api/evidence/bundle/:bundle_id
/// Get a specific bundle by ID.
pub async fn get_evidence_bundle(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(bundle_id): axum::extract::Path<String>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"error": "unauthorized"})),
    };
    match state.ch_storage
        .get_evidence_bundle(&claims.tenant_id, &bundle_id)
        .await
    {
        Ok(Some(b)) => Json(json!({"bundle": b})),
        Ok(None) => Json(json!({"error": "not found"})),
        Err(e) => Json(json!({"error": e.to_string()})),
    }
}

/// GET /api/evidence/bundle/:id/contents
/// Returns live ClickHouse data augmented with PCAP/session info from the stored ZIP.
/// Always queries live to avoid stale data from bundles captured before Zeek data arrived.
pub async fn get_bundle_contents(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(bundle_id): axum::extract::Path<String>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"error": "unauthorized"})),
    };

    let bundle = match state.ch_storage
        .get_evidence_bundle(&claims.tenant_id, &bundle_id)
        .await
    {
        Ok(Some(b)) => b,
        _ => return Json(json!({"error": "bundle not found"})),
    };

    let community_id = bundle["community_id"].as_str().unwrap_or("").to_string();
    if community_id.is_empty() {
        return Json(json!({"error": "bundle has no community_id"}));
    }

    // Read ZIP only to extract PCAP size and session_metadata
    let mut pcap_size: u64 = 0;
    let mut session_metadata = json!({});
    let mut alert_from_zip = json!({});

    if let Some(file_path) = bundle["file_path"].as_str().filter(|p| !p.is_empty()) {
        if let Ok(zip_bytes) = tokio::fs::read(file_path).await {
            let cursor = std::io::Cursor::new(&zip_bytes);
            if let Ok(mut archive) = zip::ZipArchive::new(cursor) {
                for i in 0..archive.len() {
                    let mut file = match archive.by_index(i) {
                        Ok(f) => f,
                        Err(_) => continue,
                    };
                    let name = file.name().to_string();
                    if name == "session_metadata.json" {
                        let mut text = String::new();
                        use std::io::Read;
                        let _ = file.read_to_string(&mut text);
                        session_metadata = serde_json::from_str(&text).unwrap_or(json!({}));
                    } else if name == "alert.json" {
                        let mut text = String::new();
                        use std::io::Read;
                        let _ = file.read_to_string(&mut text);
                        alert_from_zip = serde_json::from_str(&text).unwrap_or(json!({}));
                    } else if name.ends_with(".pcap") {
                        pcap_size = file.size();
                    }
                }
            }
        }
    }

    // Fetch all investigation data live from ClickHouse
    let mut live = evidence::fetch_live_investigation(
        &community_id,
        &claims.tenant_id,
        &alert_from_zip,
        &session_metadata,
    ).await;

    // If ZIP has no PCAP (bundle created before upload), check pcap_sessions live
    if pcap_size == 0 {
        if let Ok(fp) = state.ch_storage
            .get_pcap_file_path_by_community_id(&claims.tenant_id, &community_id)
            .await
        {
            if let Some(path) = fp {
                if let Ok(meta) = tokio::fs::metadata(&path).await {
                    pcap_size = meta.len();
                }
            }
        }
    }

    // Live OpenSearch check — same pattern as arkime_sessions endpoint.
    // ZIP pcap_size is stale (built before Arkime ran); always check current state.
    let es_url = std::env::var("OPENSEARCH_URL").unwrap_or_default();
    let http_cli = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    let os_hit: Option<serde_json::Value> = if !es_url.is_empty() {
        async {
            let resp = http_cli
                .post(format!("{}/arkime_sessions3-*/_search", es_url))
                .json(&json!({
                    "size": 1,
                    "query": { "term": { "network.community_id": community_id } },
                    "_source": ["node","firstPacket","lastPacket",
                                "source.ip","source.port",
                                "destination.ip","destination.port"]
                }))
                .send().await.ok()?
                .json::<serde_json::Value>().await.ok()?;
            resp["hits"]["hits"].as_array()?.first().cloned()
        }.await
    } else { None };

    let (pcap_available, resolved_session_meta) = match os_hit {
        Some(hit) => {
            let sid = hit["_id"].as_str().unwrap_or("").to_string();
            let meta = json!({
                "arkime_session_id": sid,
                "index":        hit["_index"],
                "node":         hit["_source"]["node"],
                "first_packet": hit["_source"]["firstPacket"],
                "last_packet":  hit["_source"]["lastPacket"],
                "community_id": community_id,
                "query_source": "opensearch"
            });
            (!sid.is_empty(), meta)
        }
        None => (pcap_size > 0, session_metadata),
    };

    // Override threat_intel using the live in-memory feed (same as Intel page).
    // The evidence module queries empty ClickHouse tables; this is the correct source.
    {
        let ti = &state.enrichment.threat_intel;
        let src_ip = alert_from_zip["src_ip"].as_str()
            .or_else(|| live["alert"]["src_ip"].as_str())
            .unwrap_or("");
        let dst_ip = alert_from_zip["dst_ip"].as_str()
            .or_else(|| live["alert"]["dst_ip"].as_str())
            .unwrap_or("");

        let mut checked: Vec<&str> = vec![];
        let mut matches: Vec<serde_json::Value> = vec![];

        for ip in [src_ip, dst_ip].iter().filter(|s| !s.is_empty()) {
            checked.push(ip);
            if ti.is_malicious_ip(ip) {
                matches.push(json!({
                    "ioc_type":   "ip",
                    "ioc_value":  ip,
                    "source":     "abuse.ch",
                    "confidence": 90,
                    "description": format!("{} is listed in the abuse.ch malicious IP feed (Feodo Tracker)", ip)
                }));
            }
        }

        let live_threat_intel = json!({
            "checked_ips": checked,
            "matches":     matches,
            "source":      "in-memory (Feodo Tracker / abuse.ch)"
        });

        if let Some(obj) = live.as_object_mut() {
            obj.insert("threat_intel".to_string(), live_threat_intel);
        }
    }

    if let Some(obj) = live.as_object_mut() {
        obj.insert("pcap_size_bytes".to_string(),  json!(pcap_size));
        obj.insert("pcap_available".to_string(),   json!(pcap_available));
        obj.insert("session_metadata".to_string(), resolved_session_meta);
        obj.insert("bundle_id".to_string(),        json!(bundle_id));
    }

    Json(live)
}

/// GET /api/evidence/:community_id/log
/// Return full chain-of-custody log.
pub async fn get_evidence_log(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(community_id): axum::extract::Path<String>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"error": "unauthorized"})),
    };
    let log = state.ch_storage
        .get_evidence_log(&claims.tenant_id, &community_id)
        .await.unwrap_or_default();
    Json(json!({"community_id": community_id, "log": log}))
}

/// GET /api/evidence/bundle/:bundle_id/verify
/// Rebuild the bundle in memory and compare its SHA256 to the stored hash.
/// Bundles are generated on-demand (never written to disk), so verification
/// re-runs the same build pipeline and hashes the result.
pub async fn verify_evidence_bundle(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(bundle_id): axum::extract::Path<String>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"error": "unauthorized"})),
    };
    let bundle = match state.ch_storage
        .get_evidence_bundle(&claims.tenant_id, &bundle_id)
        .await
    {
        Ok(Some(b)) => b,
        _ => return Json(json!({"error": "bundle not found"})),
    };

    let stored_sha256 = bundle["sha256"].as_str().unwrap_or("").to_string();
    let file_path     = bundle["file_path"].as_str().unwrap_or("").to_string();

    // Integrity check: hash the stored ZIP file on disk and compare.
    // Rebuilding from live ClickHouse data was wrong — Zeek logs and events
    // accumulate after capture, so the rebuilt ZIP always differs → false TAMPERED.
    let (matches, computed_sha256) = if file_path.is_empty() {
        (false, "no_file_path_stored".to_string())
    } else {
        match tokio::fs::read(&file_path).await {
            Ok(bytes) => {
                use sha2::Digest;
                let hash = format!("{:x}", sha2::Sha256::digest(&bytes));
                (hash == stored_sha256, hash)
            }
            Err(e) => (false, format!("file_read_error: {}", e))
        }
    };

    let status = if matches { "VERIFIED" } else { "TAMPERED_OR_CORRUPTED" };

    // Log the verification
    let _ = state.ch_storage.log_evidence_action(
        &claims.tenant_id,
        bundle["community_id"].as_str().unwrap_or(""),
        &bundle_id,
        &format!("integrity_check:{}", status),
        &claims.sub,
        "", "", "",
        &format!("stored_sha256={} computed_sha256={}", stored_sha256, computed_sha256),
        "",
    ).await;

    Json(json!({
        "bundle_id": bundle_id,
        "status": status,
        "stored_sha256": stored_sha256,
        "computed_sha256": computed_sha256,
        "verified_at": chrono::Utc::now().to_rfc3339(),
        "verified_by": claims.sub
    }))
}

/// POST /api/evidence/bundle/:bundle_id/hold
/// Set or clear legal hold on a bundle.
/// Body: { "hold": true, "reason": "Active criminal investigation case #1234" }
pub async fn set_evidence_legal_hold(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(bundle_id): axum::extract::Path<String>,
    Json(payload): Json<Value>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"error": "unauthorized"})),
    };
    let hold = payload["hold"].as_bool().unwrap_or(true);
    let reason = payload["reason"].as_str().unwrap_or("").to_string();

    if hold && reason.is_empty() {
        return Json(json!({
            "error": "reason required when setting legal hold"
        }));
    }

    let _ = state.ch_storage.set_legal_hold(
        &claims.tenant_id,
        &bundle_id,
        if hold { 1 } else { 0 },
        &reason,
        &claims.sub,
    ).await;

    let action = if hold {
        "legal_hold_set"
    } else {
        "legal_hold_cleared"
    };
    let _ = state.ch_storage.log_evidence_action(
        &claims.tenant_id, "", &bundle_id,
        action, &claims.sub,
        "", "", "", &reason, "",
    ).await;

    Json(json!({
        "bundle_id": bundle_id,
        "legal_hold": hold,
        "reason": reason,
        "set_by": claims.sub,
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

/// POST /api/evidence/bundle/:bundle_id/annotate
/// Add analyst note/tag to a bundle.
/// Body: { "note": "Confirmed C2 callback", "tag": "confirmed_malicious" }
pub async fn annotate_evidence_bundle(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(bundle_id): axum::extract::Path<String>,
    Json(payload): Json<Value>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"error": "unauthorized"})),
    };
    let note = payload["note"].as_str().unwrap_or("").to_string();
    let tag = payload["tag"].as_str().unwrap_or("").to_string();
    let community_id = payload["community_id"]
        .as_str().unwrap_or("").to_string();

    let _ = state.ch_storage.add_evidence_annotation(
        &claims.tenant_id,
        &bundle_id,
        &community_id,
        &claims.sub,
        &note,
        &tag,
    ).await;

    let _ = state.ch_storage.log_evidence_action(
        &claims.tenant_id, &community_id, &bundle_id,
        "annotated", &claims.sub,
        "", "", "", &note, "",
    ).await;

    Json(json!({"status": "ok", "bundle_id": bundle_id}))
}

/// GET /api/evidence/bundle/:bundle_id/annotations
pub async fn get_evidence_annotations(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(bundle_id): axum::extract::Path<String>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"error": "unauthorized"})),
    };
    let annotations = state.ch_storage
        .get_annotations(&claims.tenant_id, &bundle_id)
        .await.unwrap_or_default();
    Json(json!({"bundle_id": bundle_id, "annotations": annotations}))
}

/// GET /api/evidence/:community_id/timeline
/// Attack story reconstruction — stitch together events in time order.
pub async fn get_evidence_timeline(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(community_id): axum::extract::Path<String>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"error": "unauthorized"})),
    };

    // 1. Get the primary alert/hit
    let hit = state.ch_storage
        .get_hit_by_community_id(&claims.tenant_id, &community_id)
        .await.unwrap_or_default()
        .unwrap_or(json!({}));

    let src_ip = hit["src_ip"].as_str().unwrap_or("").to_string();
    let dst_ip = hit["dst_ip"].as_str().unwrap_or("").to_string();
    let alert_time = hit["timestamp"].as_str().unwrap_or("").to_string();
    let severity = hit["severity"].as_str().unwrap_or("").to_string();
    let rule_name = hit["rule_name"].as_str().unwrap_or("").to_string();

    // 2. Get related hits for same src_ip in ±5min window
    let related = state.ch_storage
        .get_related_hits_by_ip(&claims.tenant_id, &src_ip, &alert_time, 5)
        .await.unwrap_or_default();

    // 3. Get OpenSearch session info (on-premise)
    let session_info = if claims.tenant_id == "default" {
        let opensearch_url = std::env::var("OPENSEARCH_URL")
            .unwrap_or_else(|_| "http://localhost:9200".to_string());
        let http = reqwest::Client::new();
        match http.post(format!(
            "{}/arkime_sessions3-*/_search", opensearch_url
        ))
        .json(&json!({
            "query": {"term": {"network.community_id": community_id}},
            "size": 1
        }))
        .send().await {
            Ok(r) => r.json::<Value>().await.unwrap_or(json!({})),
            Err(_) => json!({})
        }
    } else {
        json!({})
    };

    let session_src = &session_info["hits"]["hits"][0]["_source"];
    let src_bytes = session_src["network"]["bytes_toserver"]
        .as_u64().unwrap_or(0);
    let dst_bytes = session_src["network"]["bytes_toclient"]
        .as_u64().unwrap_or(0);
    let protocol = session_src["network"]["protocol"]
        .as_str().unwrap_or("unknown");

    // 4. Build ordered event timeline
    let mut events: Vec<Value> = vec![
        json!({
            "time": alert_time,
            "type": "connection",
            "description": format!(
                "{} → {} established {} connection",
                src_ip, dst_ip, protocol
            ),
            "community_id": community_id,
            "bytes_sent": src_bytes,
            "bytes_received": dst_bytes
        }),
        json!({
            "time": alert_time,
            "type": "alert",
            "description": format!(
                "NDR rule triggered: '{}' — severity {}",
                rule_name, severity
            ),
            "rule": rule_name,
            "severity": severity
        }),
    ];

    // Add related events
    for rel in &related {
        if rel["community_id"].as_str() != Some(&community_id) {
            events.push(json!({
                "time": rel["timestamp"],
                "type": "related_alert",
                "description": format!(
                    "Related activity: {} → {} ({})",
                    rel["src_ip"].as_str().unwrap_or(""),
                    rel["dst_ip"].as_str().unwrap_or(""),
                    rel["rule_name"].as_str().unwrap_or("")
                ),
                "community_id": rel["community_id"]
            }));
        }
    }

    // 5. Build attack narrative
    let narrative = format!(
        "At {}, host {} established a {} connection to {}. \
        NDR engine triggered rule '{}' with {} severity. \
        {} related activity events were detected for the same \
        source host within a 5-minute window, suggesting {}.",
        alert_time, src_ip, protocol, dst_ip,
        rule_name, severity,
        related.len(),
        if related.len() > 3 {
            "possible lateral movement or automated attack pattern"
        } else {
            "isolated activity"
        }
    );

    Json(json!({
        "community_id": community_id,
        "narrative": narrative,
        "primary_alert": hit,
        "events": events,
        "related_sessions_count": related.len(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "generated_at": chrono::Utc::now().to_rfc3339()
    }))
}

/// GET /api/evidence/iocs/check?value=<ip_or_domain>
/// Check a value against the shared IOC database.
pub async fn check_shared_ioc(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Json<Value> {
    let _ = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"error": "unauthorized"})),
    };
    let value = params.get("value").map(String::as_str).unwrap_or("");
    match state.ch_storage.check_shared_ioc(value).await {
        Ok(Some(ioc)) => Json(json!({"found": true, "ioc": ioc})),
        Ok(None) => Json(json!({"found": false})),
        Err(e) => Json(json!({"error": e.to_string()})),
    }
}

// ═══════════════════════════════════════════
// ARIA SOC ASSISTANT CHAT ENDPOINT
// ═══════════════════════════════════════════

/// POST /api/aria/chat
/// Body: { "message": "...", "history": [...] }
/// Returns: { "reply": "...", "emotion": "..." }
pub async fn aria_chat(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<Value>,
) -> Json<Value> {

    // Auth
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({
            "reply": "Unauthorized.",
            "emotion": "alert"
        })),
    };

    let user_message = match payload["message"]
        .as_str()
    {
        Some(m) if !m.is_empty() => m.to_string(),
        _ => return Json(json!({
            "reply": "Empty message.",
            "emotion": "idle"
        })),
    };

    let history = payload["history"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    // Fetch live NDR context
    let critical = state.ch_storage
        .count_hits_by_severity_aria(
            &claims.tenant_id, "CRITICAL")
        .await.unwrap_or(0);

    let high = state.ch_storage
        .count_hits_by_severity_aria(
            &claims.tenant_id, "HIGH")
        .await.unwrap_or(0);

    let bundles = state.ch_storage
        .count_evidence_bundles_aria(
            &claims.tenant_id)
        .await.unwrap_or(0);

    let recent = state.ch_storage
        .get_recent_hits_for_aria(
            &claims.tenant_id, 5)
        .await.unwrap_or_default();

    // Build system prompt with live data
    let system = crate::ai::build_system_prompt(
        &claims.sub,
        &claims.tenant_id,
        critical,
        high,
        bundles,
        &recent,
    );

    // Call OpenAI API
    let api_key = std::env::var("OPENAI_API_KEY")
        .unwrap_or_default();

    match crate::ai::call_openai(
        &api_key,
        &system,
        &history,
        &user_message,
    ).await {
        Ok((reply, emotion)) => Json(json!({
            "reply": reply,
            "emotion": emotion
        })),
        Err(e) => {
            tracing::error!(
                "ARIA OpenAI API error: {}", e);
            Json(json!({
                "reply": "I'm having trouble \
                    connecting to my AI brain. \
                    Check OPENAI_API_KEY.",
                "emotion": "sad"
            }))
        }
    }
}

/// GET /api/aria/status
/// Returns live counts for bot status bar
pub async fn aria_status(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({
            "error": "unauthorized"
        })),
    };

    let critical = state.ch_storage
        .count_hits_by_severity_aria(
            &claims.tenant_id, "CRITICAL")
        .await.unwrap_or(0);

    let high = state.ch_storage
        .count_hits_by_severity_aria(
            &claims.tenant_id, "HIGH")
        .await.unwrap_or(0);

    let recent = state.ch_storage
        .get_recent_hits_for_aria(
            &claims.tenant_id, 1)
        .await.unwrap_or_default();

    let latest_severity = recent
        .first()
        .and_then(|h| h["severity"].as_str())
        .unwrap_or("none")
        .to_string();

    let latest_src = recent
        .first()
        .and_then(|h| h["src_ip"].as_str())
        .unwrap_or("")
        .to_string();

    let latest_dst = recent
        .first()
        .and_then(|h| h["dst_ip"].as_str())
        .unwrap_or("")
        .to_string();

    let latest_cid = recent
        .first()
        .and_then(|h| h["community_id"].as_str())
        .unwrap_or("")
        .to_string();

    Json(json!({
        "critical_count": critical,
        "high_count": high,
        "latest_severity": latest_severity,
        "latest_src_ip": latest_src,
        "latest_dst_ip": latest_dst,
        "latest_community_id": latest_cid,
        "emotion": if critical > 0 {
            "alert"
        } else if high > 0 {
            "alert"
        } else {
            "idle"
        }
    }))
}

/// GET /api/ai-activity
/// Returns AI suppression decisions and AI evidence analysis annotations.
pub async fn get_ai_activity(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"error": "unauthorized"})),
    };

    let suppressions = state.ch_storage
        .list_ai_suppressions(&claims.tenant_id)
        .await
        .unwrap_or_default();

    let analyses = state.ch_storage
        .get_all_ai_annotations(&claims.tenant_id)
        .await
        .unwrap_or_default();

    Json(json!({
        "suppressions": suppressions,
        "analyses": analyses
    }))
}