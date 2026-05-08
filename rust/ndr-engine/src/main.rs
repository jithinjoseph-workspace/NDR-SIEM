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
mod settings;
mod storage;

use api::{websocket::ws_handler, AppState};
use axum::{routing::{get, post}, Router};
use tower_http::cors::{Any, CorsLayer};
use enrichment::{AsnLookup, EnrichmentPipeline, GeoIpLookup, ThreatIntel};
use settings::NdrSettings;
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

    // ── Build AppState ────────────────────────────────────────────────────
    let (tx, _) = broadcast::channel::<String>(512);

    let storage = storage::SqliteStorage::new("ndr.db")
        .expect("Failed to open SQLite database");

    // ── Load settings from SQLite (or defaults on first boot) ────────────
    let saved_kv = storage.get_settings();
    let ndr_settings = NdrSettings::from_kv(saved_kv);
    info!("⚙ Settings loaded: org='{}', theme='{}', severity=[{},{},{},{}], TI refresh={}min, hot-reload={}min",
        ndr_settings.org_name, ndr_settings.theme,
        ndr_settings.severity_critical, ndr_settings.severity_high,
        ndr_settings.severity_medium, ndr_settings.severity_low,
        ndr_settings.ti_refresh_interval_min, ndr_settings.hot_reload_interval_min);

    let rules_dir = ndr_settings.sigma_rules_dir.clone();
    let settings_arc = Arc::new(tokio::sync::RwLock::new(ndr_settings));

    let state = AppState {
        correlator: Arc::new(correlator::CorrelationEngine::new()),
        enrichment: Arc::new(EnrichmentPipeline {
            geoip,
            asn,
            threat_intel: ti_ref.clone(),
        }),
        scorer:     Arc::new(scoring::RiskScorer::new()),
        detection:  Arc::new(tokio::sync::RwLock::new(detection::DetectionEngine::new(&rules_dir))),
        ch_storage:  Arc::new(storage::ClickhouseStorage::new()),
        storage:    Arc::new(storage),
        tx:         tx.clone(),
        settings:   settings_arc.clone(),
    };

    // ── Restore Custom IOCs from SQLite ───────────────────────────────────
    let custom_iocs = state.storage.get_active_custom_iocs();
    let loaded_count = custom_iocs.len();
    for (ioc_type, value) in custom_iocs {
        ti_ref.add_ioc(&ioc_type, &value);
    }
    if loaded_count > 0 {
        info!("Restored {} custom IOCs from persistent storage", loaded_count);
    }

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

    // ── Background: threat intel refresh (dynamic interval from settings) ─
    {
        let ti = ti_ref.clone();
        let settings_ref = settings_arc.clone();
        tokio::spawn(async move {
            loop {
                let s = settings_ref.read().await;
                let interval_min = s.ti_refresh_interval_min.max(1) as u64;
                let feodo = s.feed_feodo_enabled;
                let malware = s.feed_malwarebazaar_enabled;
                let urlhaus = s.feed_urlhaus_enabled;
                let custom_url = s.custom_ioc_feed_url.clone();
                drop(s); // release lock before network I/O

                ti.refresh_with_settings(feodo, malware, urlhaus, &custom_url).await;

                tokio::time::sleep(
                    tokio::time::Duration::from_secs(interval_min * 60)
                ).await;
            }
        });
    }

    // ── Background: SIGMA rules hot-reload (dynamic interval from settings)
    {
        let detection = state.detection.clone();
        let ch = state.ch_storage.clone();
        let settings_ref = settings_arc.clone();
        tokio::spawn(async move {
            loop {
                let s = settings_ref.read().await;
                let interval_min = s.hot_reload_interval_min.max(1) as u64;
                let dir = s.sigma_rules_dir.clone();
                drop(s);

                tokio::time::sleep(
                    tokio::time::Duration::from_secs(interval_min * 60)
                ).await;

                let disabled = ch.get_disabled_rules().await.unwrap_or_default();
                let all_rules = detection::load_rules_from_dir(&dir);
                let active: Vec<_> = all_rules.into_iter()
                    .filter(|r| !disabled.contains(&r.id))
                    .collect();
                let count = active.len();
                detection.write().await.set_rules(active);
                tracing::info!("Hot-reload: {} SIGMA rules from '{}'", count, dir);
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


    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

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
        .route("/api/settings",           get(api::get_settings).post(api::update_settings))
        .route("/api/settings/upload-iocs", post(api::upload_iocs))
        .with_state(state)
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
