// NDR Engine — Entry Point
// Boots all subsystems, wires them into AppState, starts background tasks.
// License: Apache-2.0

mod api;
mod consumer;
mod correlator;
mod detection;
mod enrichment;
mod normalizer;
mod scoring;
mod storage;

use api::{websocket::ws_handler, AppState};
use futures_util::StreamExt;
use axum::{routing::{get, post, delete, put}, Router};
use tower_http::cors::{Any, CorsLayer};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, ACCEPT};
use enrichment::{AsnLookup, EnrichmentPipeline, GeoIpLookup, ThreatIntel};
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::info;
#[tokio::main]
async fn main() {
    // ── Logging ───────────────────────────────────────────────────────────
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "ndr_engine=info".to_string())
                .as_str(),
        )
        .init();

    info!("🚀 NDR Engine starting on 172.25.86.150:3000");

    // ── GeoIP / ASN (optional — engine works without them) ───────────────
    let geoip = GeoIpLookup::open("data/GeoLite2-City.mmdb")
        .map_err(|e| info!("GeoIP unavailable ({}). Place GeoLite2-City.mmdb in data/", e))
        .ok();

    let asn = AsnLookup::open("data/GeoLite2-ASN.mmdb")
        .map_err(|e| info!("ASN DB unavailable ({}). Place GeoLite2-ASN.mmdb in data/", e))
        .ok();

    // ── Threat intel ──────────────────────────────────────────────────────
    let threat_intel = ThreatIntel::new();
    let ti_ref = Arc::new(threat_intel);

    // Initial fetch (non-blocking — starts immediately)
    {
        let ti = ti_ref.clone();
        tokio::spawn(async move { ti.refresh().await });
    }

    // ── Build AppState ────────────────────────────────────────────────────
    let (tx, _) = broadcast::channel::<String>(512);

    let redis_url = std::env::var("REDIS_URL")
        .unwrap_or_else(|_| "redis://localhost:6379".to_string());
    let redis_client = redis::Client::open(redis_url)
        .expect("Redis connection failed");

    let storage = storage::SqliteStorage::new("ndr.db")
        .expect("Failed to open SQLite database");

    let state = AppState {
        correlator: Arc::new(correlator::CorrelationEngine::new()),
        enrichment: Arc::new(EnrichmentPipeline {
            geoip,
            asn,
            threat_intel: ti_ref.clone(), // use same instance that gets refreshed, // separate instance for sync use
        }),
        scorer:     Arc::new(scoring::RiskScorer::new()),
        detection:  Arc::new(tokio::sync::RwLock::new(detection::DetectionEngine::new("rules"))),
        ch_storage: {
            let ch = Arc::new(storage::ClickhouseStorage::new());
            ch.init_tables().await;
            ch
        },
        storage:    Arc::new(storage),
        tx:         tx.clone(),
        redis:      Arc::new(redis_client.clone()),
    };

    // ── Background: session reaper (every 30s) ────────────────────────────
    {
        let eng = state.correlator.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
                eng.sweep_expired();
                tracing::debug!("Session sweep complete. Active: {}", eng.session_count());
            }
        });
    }

    // ── Background: threat intel refresh (every 60 min) ───────────────────
    // Fix background refresh — refresh NOW then every 60 min
{
    let ti = ti_ref.clone();
    tokio::spawn(async move {
        loop {
            ti.refresh().await;  // ← refresh first
            tokio::time::sleep(
                tokio::time::Duration::from_secs(3600)
            ).await;  // ← then wait
        }
    });
}
    // ── Kafka consumer (replaces HTTP /event endpoint) ────────────────────
    {
        let consumer_state = state.clone();
        tokio::spawn(async move {
            consumer::start_consumer(Arc::new(consumer_state)).await;
        });
    }


// Auto-restore SOAR config from ClickHouse
let ch = state.ch_storage.clone();
tokio::spawn(async move {
    tokio::time::sleep(
        std::time::Duration::from_secs(5)
    ).await;
    
    if let Ok(config) = ch.get_soar_config().await {
        if let Some(url) = config["webhook_url"]
            .as_str() {
            if !url.is_empty() {
                std::env::set_var(
                    "SHUFFLE_WEBHOOK_URL", url);
                tracing::info!(
                    "✅ SOAR webhook restored: {}", 
                    &url[..30.min(url.len())]
                );
            }
        }
        if let Some(key) = config["api_key"]
            .as_str() {
            if !key.is_empty() {
                std::env::set_var(
                    "SHUFFLE_API_KEY", key);
                tracing::info!(
                    "✅ SOAR API key restored");
            }
        }
    }
});

    // ── Migrate rules to ClickHouse ──────────────────────────────────────────
    {
        let ch = state.ch_storage.clone();
        let rules_dir = std::env::var("RULES_DIR")
            .unwrap_or_else(|_| "rules".to_string());
        
        tokio::spawn(async move {
            if let Ok(entries) = std::fs::read_dir(&rules_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                    if ext != "yml" && ext != "yaml" { continue; }
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        if let Ok(doc) = serde_yaml::from_str::<std::collections::HashMap<String, serde_yaml::Value>>(&content) {
                            let id = doc.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                            let name = doc.get("title").and_then(|v| v.as_str()).unwrap_or("").to_string();
                            if !id.is_empty() {
                                let exists = ch.get_sigma_rule_by_id(&id, "default").await.map(|r| r.is_some()).unwrap_or(false);
                                if !exists {
                                    if let Err(e) = ch.save_sigma_rule(&id, &name, &content, "default").await {
                                        tracing::warn!("Failed to migrate rule {}: {}", id, e);
                                    } else {
                                        tracing::info!("Migrated rule {} to ClickHouse", id);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
    }

    // ── Load rules from ClickHouse (or file fallback) ───────────────────────
    {
        let ch = state.ch_storage.clone();
        let det = state.detection.clone();
        let rules_dir = std::env::var("RULES_DIR")
            .unwrap_or_else(|_| "rules".to_string());
        tokio::spawn(async move {
            // Wait briefly for migration to complete
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            let rules = api::load_rules_from_clickhouse(&ch, &rules_dir).await;
            det.write().await.set_rules(rules);
        });
    }

    // ── Subscribe to Redis "system:reload_rules" ───────────────────────────
    {
        let ch = state.ch_storage.clone();
        let det = state.detection.clone();
        let redis_client = redis_client.clone();
        let rules_dir = std::env::var("RULES_DIR")
            .unwrap_or_else(|_| "rules".to_string());
        
        tokio::spawn(async move {
            if let Ok(conn) = redis_client.get_async_connection().await {
                let mut pubsub = conn.into_pubsub();
                if pubsub.subscribe("system:reload_rules").await.is_ok() {
                    let mut stream = pubsub.on_message();
                    while let Some(_) = stream.next().await {
                        tracing::info!("Reloading rules via Redis signal...");
                        let rules = api::load_rules_from_clickhouse(&ch, &rules_dir).await;
                        let count = rules.len();
                        det.write().await.set_rules(rules);
                        tracing::info!("Hot-reloaded {} SIGMA rules from Redis signal", count);
                    }
                }
            }
        });
    }



    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers([
            AUTHORIZATION,
            CONTENT_TYPE,
            ACCEPT,
        ]);

    let app = Router::new()
        .route("/ws",              get(ws_handler))
        .route("/api/health",          get(api::health))
        .route("/api/interfaces",  get(api::get_interfaces))
        .route("/api/interface",   get(api::get_interface).post(api::set_interface))
        .route("/api/start",       post(api::start_services))
        .route("/api/stop",        post(api::stop_services))
        .route("/api/agent-status",  get(api::get_agent_status))
        .route("/api/stats",         get(api::get_stats))
        .route("/api/events",        get(api::get_recent_events))
        .route("/api/top-ips",       get(api::get_top_ips))
        .route("/api/severity",      get(api::get_severity))
        .route("/api/hits",          get(api::get_hits))
        .route("/api/network-map", get(api::get_network_map))
        .route("/api/scale-status", get(api::get_scale_status))
        .route("/api/rules",          get(api::get_rules).post(api::create_rule))
        .route("/api/rules/reload",   post(api::reload_rules_api))     // ← MUST be before /:id
        .route("/api/rules/:id",      get(api::get_rule_by_id).delete(api::delete_rule))
        .route("/api/threat-intel",     get(api::get_threat_intel))
        .route("/api/threat-intel/:ip", get(api::lookup_ioc))
        .route("/api/rules/:id/toggle", post(api::toggle_rule))
        .route("/api/export", get(api::export_report))
        .route("/api/threat-intel/add", post(api::add_manual_ioc))
        .route("/api/soar/status",  get(api::get_soar_status))
        .route("/api/soar/setup",   post(api::setup_soar))
        .route("/api/soar/config",  post(api::update_soar_config))
        .route("/api/soar/test",    post(api::test_soar_webhook))
        .route("/api/soar/executions",    get(api::get_soar_executions))
        .route("/api/soar/actions",       get(api::get_soar_actions))
        .route("/api/soar/action/slack",  post(api::configure_slack))
        .route("/api/settings", get(api::get_settings).post(api::update_settings))
        .route("/api/soar/action/email", post(api::configure_email))       
        .route("/api/soar/playbook/toggle",post(api::toggle_playbook))
        .route("/api/soar/playbook/create",post(api::create_playbook))
        .route("/api/soar/integrations",get(api::get_integrations).post(api::save_integration))
        .route("/api/soar/integrations/test",post(api::test_integration_endpoint))
        .route("/api/soar/integrations/toggle",post(api::toggle_integration))
        .route("/api/soar/integrations/delete",post(api::delete_integration))
        .route("/api/soar/jira/tickets", post(api::get_jira_tickets))
        .route("/api/auth/login", post(api::login))
        .route("/api/auth/logout", post(api::logout))
        .route("/api/auth/me", get(api::get_me))
        .route("/api/auth/users",get(api::get_users).post(api::create_user))
        .route("/api/auth/users/:id",delete(api::delete_user))
        .route("/api/auth/users/:id/permissions", put(api::update_user_permissions_api))
        .route("/api/auth/tenants",get(api::get_tenants).post(api::create_tenant))
        .route("/api/admin/engines", get(api::get_engines))
        .route("/api/admin/engines/scale", post(api::scale_engines))
        .route("/api/sensor/register",  post(api::sensor_register))
        .route("/api/sensor/heartbeat", post(api::sensor_heartbeat))
        .with_state(state)
        .layer(axum::middleware::from_fn(api::auth_middleware))
        .layer(cors);

    info!("🌐 API active");
    info!("❤  Health:    GET  http://0.0.0.0:3000/health");
    info!("📡 Kafka:     ndr-events (broker: {})",
        std::env::var("KAFKA_BROKERS").unwrap_or_else(|_| "kafka:9092".to_string()));

// ── Background: agent status monitor ─────────────────────────────────
    {
        let tx = tx.clone();
        tokio::spawn(async move {
            let client = reqwest::Client::new();
            let agent = std::env::var("NDR_AGENT_URL")
                .unwrap_or_else(|_| "http://172.25.86.150:3001".to_string());
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                if let Ok(resp) = client.get(format!("{}/agent/status", agent)).send().await {
                    if let Ok(data) = resp.json::<serde_json::Value>().await {
                        let msg = serde_json::json!({
                            "type": "agent_status",
                            "zeek": data.get("zeek").and_then(|v| v.as_str()).unwrap_or("stopped"),
                            "suricata": data.get("suricata").and_then(|v| v.as_str()).unwrap_or("stopped"),
                            "vector": data.get("vector").and_then(|v| v.as_str()).unwrap_or("stopped"),

                            "interface": data.get("interface").and_then(|v| v.as_str()).unwrap_or("eth0"),
                        });
                        let _ = tx.send(msg.to_string());
                    }
                }
            }
        });
    }

    // ── THIS MUST BE LAST — blocks forever ───────────────────────────────
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();

}









