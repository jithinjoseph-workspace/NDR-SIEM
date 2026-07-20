// NDR Engine — Entry Point
// Boots all subsystems, wires them into AppState, starts background tasks.
// License: Apache-2.0

mod api;
mod auth;
mod ratelimit;
mod siem;
mod consumer;
mod correlator;
mod detection;
mod enrichment;
mod normalizer;
mod scoring;
mod storage;
mod evidence;
mod ai;
pub mod soar;
mod monitor;
mod threat;
mod leader;

use api::{websocket::ws_handler, AppState};
use futures_util::StreamExt;
use axum::{routing::{get, post, put, delete, patch}, Router};
use axum::extract::DefaultBodyLimit;
use tower_http::cors::{Any, CorsLayer, AllowOrigin};
use axum::http::HeaderValue;
use tower_http::decompression::RequestDecompressionLayer;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, ACCEPT};

async fn security_headers(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert("X-Frame-Options",        HeaderValue::from_static("SAMEORIGIN"));
    h.insert("X-Content-Type-Options", HeaderValue::from_static("nosniff"));
    h.insert("Content-Security-Policy", HeaderValue::from_static(
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
         connect-src 'self' ws: wss:; img-src 'self' data:; font-src 'self';"
    ));
    res
}
use enrichment::{AsnLookup, AssetIdentifier, EnrichmentPipeline, GeoIpLookup, ThreatIntel};
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::info;
const KAFKA_DEFAULT: &str = "kafka:9092";

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

    info!("NDR Engine starting");

    // ── Production credential warnings ────────────────────────────────────
    let default_jwt = "1c14f97d4d12b77a471227ab268ae22b1765df18b188cdceb9c5d4668189e85c";
    if std::env::var("JWT_SECRET").as_deref() == Ok(default_jwt) {
        tracing::warn!("SECURITY: JWT_SECRET is still the default value — change it in .env before production!");
    }
    if std::env::var("NDR_AGENT_SECRET").unwrap_or_default().contains("change-this") {
        tracing::warn!("SECURITY: NDR_AGENT_SECRET is still the default placeholder — set a strong secret in .env!");
    }
    if std::env::var("CORS_ORIGIN").unwrap_or_default().is_empty() {
        tracing::warn!("SECURITY: CORS_ORIGIN not set — API accepts requests from any origin. Set CORS_ORIGIN in .env for production!");
    }

    // ── Ensure required storage directories exist ─────────────────────────
    for dir in &["/opt/ndr/pcap", "/opt/ndr/evidence"] {
        if let Err(e) = std::fs::create_dir_all(dir) {
            tracing::warn!("Could not create storage dir {}: {}", dir, e);
        }
    }

    // ── GeoIP / ASN (optional — engine works without them) ───────────────
    let geoip = GeoIpLookup::open("data/GeoLite2-City.mmdb")
        .map_err(|e| info!("GeoIP unavailable ({}). Place GeoLite2-City.mmdb in data/", e))
        .ok();

    let asn_arc: Arc<Option<AsnLookup>> = Arc::new(
        AsnLookup::open("data/GeoLite2-ASN.mmdb")
            .map_err(|e| info!("ASN DB unavailable ({}). Place GeoLite2-ASN.mmdb in data/", e))
            .ok()
    );

    // ── Threat intel ──────────────────────────────────────────────────────
    let threat_intel = ThreatIntel::new();
    let ti_ref = Arc::new(threat_intel);

    // ── Build AppState ────────────────────────────────────────────────────
    let (tx, _) = broadcast::channel::<String>(512);

    let redis_url = std::env::var("REDIS_URL")
        .unwrap_or_else(|_| "redis://localhost:6379".to_string());
    let redis_client = redis::Client::open(redis_url.clone())
        .expect("Redis connection failed");
    // Shared multiplexed connection for publishing — avoids opening a new
    // TCP connection on every event (was causing per-event latency spikes)
    let redis_mux = {
        let mut conn = None;
        let mut last_err = String::new();
        for attempt in 1u8..=6 {
            match redis_client.get_multiplexed_async_connection().await {
                Ok(c) => { conn = Some(c); break; }
                Err(e) => {
                    last_err = e.to_string();
                    tracing::warn!("Redis not ready (attempt {}/6): {} — retrying in 5s", attempt, e);
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                }
            }
        }
        conn.unwrap_or_else(|| {
            tracing::error!(
                "Redis unreachable after 30 s ({}). \
                 Check REDIS_URL={} or ensure the Redis container is running. Exiting.",
                last_err, redis_url
            );
            std::process::exit(1);
        })
    };

    let storage = storage::SqliteStorage::new("ndr.db")
        .expect("Failed to open SQLite database");

    use rdkafka::producer::FutureProducer;
    use rdkafka::ClientConfig;

    let kafka_producer: FutureProducer = ClientConfig::new()
        .set("bootstrap.servers", 
             std::env::var("KAFKA_BROKERS")
             .unwrap_or_else(|_| KAFKA_DEFAULT.to_string()))
        .set("message.timeout.ms", "5000")
        .set("queue.buffering.max.messages", "100000")
        .set("batch.num.messages", "1000")
        .set("linger.ms", "5")
        .create()
        .expect("Kafka producer creation failed");

    let kafka_producer = Arc::new(kafka_producer);

    // ── Sensor key auth cache (Redis-backed, shared across all engine instances)
    let sensor_key_cache = Arc::new(
        auth::sensor_cache::SensorKeyCache::new(Arc::new(redis_client.clone()))
    );

    // ── Async ingest channel (50k event headroom before backpressure) ─────
    let (ingest_tx, mut ingest_rx) =
        tokio::sync::mpsc::channel::<(String, String)>(50_000);

    // Background drain: flushes channel to Kafka in micro-batches of ≤200
    // events every 100ms. /api/ingest returns immediately without waiting.
    {
        use rdkafka::producer::FutureRecord;
        let producer = kafka_producer.clone();
        tokio::spawn(async move {
            let mut batch: Vec<(String, String)> = Vec::with_capacity(200);
            let mut ticker = tokio::time::interval(
                std::time::Duration::from_millis(100)
            );
            loop {
                tokio::select! {
                    maybe = ingest_rx.recv() => {
                        match maybe {
                            Some(ev) => {
                                batch.push(ev);
                                if batch.len() >= 200 {
                                    for (_, payload) in batch.drain(..) {
                                        let rec = FutureRecord::<str, str>::to("ndr-events")
                                            .payload(&payload);
                                        if let Err((e, _)) = producer
                                            .send(rec, std::time::Duration::from_secs(5))
                                            .await
                                        {
                                            tracing::error!("Kafka publish error: {}", e);
                                        }
                                    }
                                }
                            }
                            None => break,
                        }
                    }
                    _ = ticker.tick() => {
                        if !batch.is_empty() {
                            for (_, payload) in batch.drain(..) {
                                let rec = FutureRecord::<str, str>::to("ndr-events")
                                    .payload(&payload);
                                if let Err((e, _)) = producer
                                    .send(rec, std::time::Duration::from_secs(5))
                                    .await
                                {
                                    tracing::error!("Kafka publish error: {}", e);
                                }
                            }
                        }
                    }
                }
            }
        });
    }

    let ch_storage_arc = {
        let ch = Arc::new(storage::ClickhouseStorage::new());
        ch.init_tables().await;
        ch.migrate_ipam_subnets().await;
        ch.seed_local_sensor().await;
        ch.seed_doh_providers().await;
        ch
    };

    // ── DoH provider IP cache (DB-backed, refreshed every 24h) ──────────────
    let doh_ips = {
        let set = ch_storage_arc.load_doh_providers().await.unwrap_or_default();
        Arc::new(tokio::sync::RwLock::new(set))
    };
    {
        let ch_doh = ch_storage_arc.clone();
        let doh_ref = Arc::clone(&doh_ips);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(86_400)).await;
                if let Ok(set) = ch_doh.load_doh_providers().await {
                    *doh_ref.write().await = set;
                }
            }
        });
    }

    // ── SIEM syslog forwarder (optional, set SIEM_SYSLOG_HOST to enable) ────
    let siem: Option<Arc<crate::siem::SiemForwarder>> =
        if let Ok(host) = std::env::var("SIEM_SYSLOG_HOST") {
            let port: u16 = std::env::var("SIEM_SYSLOG_PORT")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(514);
            match crate::siem::SiemForwarder::new(&host, port).await {
                Ok(f) => {
                    tracing::info!("SIEM syslog forwarder enabled → {}:{}", host, port);
                    Some(Arc::new(f))
                }
                Err(e) => {
                    tracing::warn!("SIEM forwarder init failed (disabling): {}", e);
                    None
                }
            }
        } else {
            None
        };

    // ── Seed in-memory threat-intel from persisted IOC watchlist ─────────
    {
        let ch_wl = ch_storage_arc.clone();
        let ti_wl = ti_ref.clone();
        tokio::spawn(async move {
            match ch_wl.load_watchlist_iocs().await {
                Ok(iocs) if !iocs.is_empty() => {
                    let n = iocs.len();
                    for (ioc_type, value) in iocs {
                        ti_wl.add_ioc(&ioc_type, &value);
                    }
                    tracing::info!("Loaded {} manual IOCs from ioc_watchlist", n);
                }
                _ => {}
            }
        });
    }

    // ── Background: Threat tasks with Redis leader election ───────────────
    let sensor_ip: Option<std::net::IpAddr> = std::env::var("HOST_IP").ok()
        .and_then(|s| s.trim().parse().ok());
    if let Some(ip) = sensor_ip {
        tracing::info!("Sensor self-IP: {} — own trusted traffic will be filtered", ip);
    }

    let entity_cache: Arc<dashmap::DashMap<String, f32>> = Arc::new(dashmap::DashMap::new());
    let (election, trusted) = threat::spawn_all(
        ch_storage_arc.clone(), &redis_url, Arc::clone(&asn_arc),
        entity_cache.clone(),
        redis_mux.clone(),
        tx.clone(),
    );

    // Start sensor key cache refresh loop (after ch_storage is ready)
    auth::sensor_cache::spawn_refresh_loop(
        sensor_key_cache.clone(),
        ch_storage_arc.clone(),
    );

    let state = AppState {
        correlator: Arc::new(correlator::CorrelationEngine::new()),
        enrichment: Arc::new(EnrichmentPipeline {
            geoip,
            asn: Arc::clone(&asn_arc),
            threat_intel: ti_ref.clone(),
            asset_id: Arc::new(AssetIdentifier::new()),
        }),
        scorer:     Arc::new(scoring::RiskScorer::new()),
        detection:  Arc::new(tokio::sync::RwLock::new(detection::DetectionEngine::new("rules"))),
        ch_storage: ch_storage_arc.clone(),
        storage:    Arc::new(storage),
        tx:         tx.clone(),
        redis:      Arc::new(redis_client.clone()),
        redis_mux:  redis_mux,
        kafka_producer: kafka_producer.clone(),
        correlation_semaphore: Arc::new(tokio::sync::Semaphore::new(16)),
        sensor_key_cache,
        ingest_tx,
        http_client: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("NDR-Engine/1.0")
            .build()
            .unwrap_or_default(),
        trusted,
        sensor_ip,
        entity_cache,
        doh_ips,
        siem,
    };

    // ── Background: OUI vendor database auto-updater ─────────────────────
    state.enrichment.asset_id.clone().spawn_auto_updater();

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
    // ── Background: vendor backfill via Redis SET ─────────────────────────
    // On startup: seed Redis SET with all existing Unknown-vendor assets.
    // Worker: SPOP one item, OUI lookup, write DB. Sleeps 1s when set empty.
    // SADD in consumer ensures no duplicates; SPOP is atomic across instances.
    {
        let ch_seed = state.ch_storage.clone();
        let mut redis_seed = state.redis_mux.clone();
        tokio::spawn(async move {
            if let Ok(tenants) = ch_seed.get_all_tenants().await {
                for tenant in &tenants {
                    if let Ok(assets) = ch_seed.get_assets_by_tenant(tenant).await {
                        for asset in assets {
                            if (asset.vendor.is_empty() || asset.vendor == "Unknown") && !asset.mac.is_empty() {
                                let qi = format!("{}|{}|{}", asset.tenant_id, asset.ip, asset.mac);
                                let _: Result<i64, _> = redis::cmd("SADD")
                                    .arg("ndr:vendor_pending").arg(qi)
                                    .query_async(&mut redis_seed).await;
                            }
                        }
                    }
                }
            }
        });
    }
    {
        let ch = state.ch_storage.clone();
        let asset_id = state.enrichment.asset_id.clone();
        let redis_client_vb = redis_client.clone();
        tokio::spawn(async move {
            let mut conn = match redis_client_vb.get_async_connection().await {
                Ok(c) => c,
                Err(e) => { tracing::warn!("Vendor backfill: Redis connect failed: {}", e); return; }
            };
            loop {
                let item: Option<String> = redis::cmd("SPOP")
                    .arg("ndr:vendor_pending")
                    .query_async(&mut conn)
                    .await
                    .unwrap_or(None);

                match item {
                    Some(entry) => {
                        let parts: Vec<&str> = entry.splitn(3, '|').collect();
                        if parts.len() == 3 {
                            let (tenant, ip, mac) = (parts[0], parts[1], parts[2]);
                            let vendor = asset_id.lookup_vendor(mac);
                            if !vendor.is_empty() && vendor != "Unknown" {
                                if let Ok(Some(mut asset)) = ch.get_asset_by_ip(tenant, ip).await {
                                    if asset.vendor.is_empty() || asset.vendor == "Unknown" {
                                        asset.vendor = vendor.clone();
                                        let _ = ch.upsert_asset(&asset).await;
                                        info!("Vendor backfill: {} → {}", ip, vendor);
                                    }
                                }
                            }
                            // Randomized MACs (no OUI) are silently dropped — correct
                        }
                    }
                    None => {
                        // Set empty — all vendors resolved, sleep until new unknown arrives
                        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    }
                }
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


    let rules_dir = std::env::var("RULES_DIR").unwrap_or_else(|_| "rules".to_string());

    // ── Migrate rules to ClickHouse ──────────────────────────────────────────
    {
        let ch = state.ch_storage.clone();
        let rules_dir = rules_dir.clone();
        
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
        let rules_dir = rules_dir.clone();
        tokio::spawn(async move {
            // Wait briefly for migration to complete
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            let (rules, overrides) = api::load_rules_from_clickhouse(&ch, &rules_dir).await;
            det.write().await.set_rules(rules, overrides);
        });
    }

    // ── Subscribe to Redis "system:reload_rules" ───────────────────────────
    {
        let ch = state.ch_storage.clone();
        let det = state.detection.clone();
        let redis_client = redis_client.clone();
        let rules_dir = rules_dir.clone();

        tokio::spawn(async move {
            if let Ok(conn) = redis_client.get_async_connection().await {
                let mut pubsub = conn.into_pubsub();
                if pubsub.subscribe("system:reload_rules").await.is_ok() {
                    let mut stream = pubsub.on_message();
                    while let Some(_) = stream.next().await {
                        tracing::info!("Reloading rules via Redis signal...");
                        let (rules, overrides) = api::load_rules_from_clickhouse(&ch, &rules_dir).await;
                        let count = rules.len();
                        det.write().await.set_rules(rules, overrides);
                        tracing::info!("Hot-reloaded {} SIGMA rules from Redis signal", count);
                    }
                }
            }
        });
    }

    // ── Periodic rule reload (safety net — bounds propagation to ≤60s) ────────
    {
        let ch = state.ch_storage.clone();
        let det = state.detection.clone();
        let rules_dir = rules_dir.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            interval.tick().await; // skip the immediate first tick
            loop {
                interval.tick().await;
                let (rules, overrides) = api::load_rules_from_clickhouse(&ch, &rules_dir).await;
                det.write().await.set_rules(rules, overrides);
            }
        });
    }

    // ── Weekly SigmaHQ community rules auto-updater ────────────────────────
    // Remove any blocked rules that slipped into the DB (e.g. before blocklist existed)
    {
        let ch_bl = ch_storage_arc.clone();
        tokio::spawn(async move {
            for &id in detection::updater::GLOBAL_RULE_BLOCKLIST {
                let _ = ch_bl.delete_community_rule(id).await;
            }
        });
    }

    detection::spawn_sigma_updater(
        rules_dir.clone(),
        redis_url.clone(),
        state.detection.clone(),
        state.ch_storage.clone(),
    );

    // ── Multi-flow correlator (Tier 1/2/3 cross-flow detection) ───────────
    // Runs only on the elected leader — same election as threat tasks
    // so all singleton background work stays on one instance.
    detection::multiflow::spawn(ch_storage_arc.clone(), election.clone());



    let cors_origin: AllowOrigin = match std::env::var("CORS_ORIGIN") {
        Ok(origin) if !origin.is_empty() => {
            // Support comma-separated list of allowed origins
            let origins: Vec<HeaderValue> = origin
                .split(',')
                .filter_map(|o| o.trim().parse::<HeaderValue>().ok())
                .collect();
            if origins.is_empty() {
                AllowOrigin::any()
            } else {
                AllowOrigin::list(origins)
            }
        }
        _ => AllowOrigin::any(), // dev fallback
    };

    let cors = CorsLayer::new()
        .allow_origin(cors_origin)
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
        .route("/api/protocols",     get(api::get_protocols))
        .route("/api/severity",      get(api::get_severity))
        .route("/api/hits",          get(api::get_hits))
        .route("/api/entity-scores", get(api::get_entity_scores))
        .route("/api/network-map", get(api::get_network_map))
        .route("/api/network-map/node/:ip", get(api::get_network_map_node))
        .route("/api/network-map/search", get(api::search_network_map))
        .route("/api/scale-status", get(api::get_scale_status))
        .route("/api/rules",          get(api::get_rules).post(api::create_rule))
        .route("/api/rules/reload",   post(api::reload_rules_api))     // ← MUST be before /:id
        .route("/api/rules/sync-community", post(api::sync_community_rules_api))
        .route("/api/rules/hit-counts", get(api::get_rule_hit_counts))
        .route("/api/rules/:id",      get(api::get_rule_by_id).delete(api::delete_rule))
        .route("/api/threat-intel",     get(api::get_threat_intel))
        .route("/api/threat-intel/:ip", get(api::lookup_ioc))
        .route("/api/rules/:id/toggle", post(api::toggle_rule))
        .route("/api/export", get(api::export_report))
        .route("/api/export-logs", get(api::export_logs))
        .route("/api/threat-intel/add", post(api::add_manual_ioc))
        .route("/api/soar/status",  get(api::get_soar_status))
        .route("/api/settings", get(api::get_settings).post(api::update_settings))
        .route("/api/settings/ai", get(api::get_ai_config).post(api::update_ai_config))
        .route("/api/settings/ai/providers", get(api::list_ai_providers).post(api::save_ai_provider))
        .route("/api/settings/ai/providers/test", post(api::test_ai_provider))
        .route("/api/settings/ai/providers/:name", delete(api::delete_ai_provider))
        .route("/api/settings/trusted-cloud", get(api::get_trusted_cloud_settings).put(api::update_trusted_cloud_settings))
        .route("/api/settings/trusted-cloud/suggestions/approve", post(api::approve_trusted_cloud_suggestion))
        .route("/api/settings/trusted-cloud/suggestions/reject",  post(api::reject_trusted_cloud_suggestion))
        .route("/api/trusted-domains",            get(api::list_trusted_domains).post(api::add_trusted_domain))
        .route("/api/trusted-domains/delete",     post(api::delete_trusted_domain))
        .route("/api/trusted-domains/ai-suggest", post(api::ai_suggest_trusted_domains))
        .route("/api/assets",                  get(api::get_assets))
        .route("/api/assets/:ip",              get(api::get_asset_by_ip).put(api::update_asset_name))
        .route("/api/assets/:ip/trusted",      patch(api::set_asset_trusted_handler))
        .route("/api/assets/subnet-roles",     get(api::get_subnet_roles).put(api::set_subnet_roles))
        .route("/api/ipam/subnets", get(api::get_ipam_subnets))
        .route("/api/soar/playbook/toggle",post(api::toggle_playbook))
        .route("/api/soar/playbook/create",post(api::create_playbook))
        .route("/api/soar/integrations",get(api::get_integrations).post(api::save_integration))
        .route("/api/soar/integrations/test",post(api::test_integration_endpoint))
        .route("/api/soar/integrations/toggle",post(api::toggle_integration))
        .route("/api/soar/cases", get(api::get_soar_cases))
        .route("/api/soar/cases/:id/comments", get(api::get_soar_case_comments).post(api::add_soar_case_comment))
        .route("/api/soar/cases/:id/status", put(api::update_soar_case_status))
        .route("/api/soar/native/playbooks", get(api::get_native_playbooks).post(api::create_native_playbook))
        .route("/api/soar/native/playbooks/:id", put(api::update_native_playbook).delete(api::delete_native_playbook))
        .route("/api/soar/runs", get(api::get_soar_runs))
        .route("/api/soar/integrations/delete",post(api::delete_integration))
        .route("/api/soar/integrations/:id", put(api::update_integration))
        .route("/api/soar/jira/tickets", post(api::get_jira_tickets))
        .route("/api/auth/login",          post(api::login))
        .route("/api/auth/check-username",  get(api::check_username))
        .route("/api/auth/logout",          post(api::logout))
        .route("/api/auth/me",              get(api::get_me))
        .route("/api/auth/users",get(api::get_users).post(api::create_user))
        .route("/api/auth/users/:id",put(api::update_user_api).delete(api::delete_user))
        .route("/api/auth/users/:id/status", post(api::set_user_status_api))
        .route("/api/auth/users/:id/permissions", put(api::update_user_permissions_api))
        .route("/api/auth/users/:id/password", post(api::reset_user_password_api))
        .route("/api/auth/tenants",get(api::get_tenants).post(api::create_tenant))
        .route("/api/auth/tenants/:id", put(api::update_tenant_api))
        .route("/api/auth/tenants/:id/status", post(api::set_tenant_status_api))
        .route("/api/auth/tenants/:id/ai-enabled", post(api::set_tenant_ai_enabled_api))
        .route("/api/announcements",
            get(api::get_announcements_api)
            .post(api::create_announcement_api))
        .route("/api/announcements/active", get(api::get_active_announcements_api))
        .route("/api/announcements/:id/read", post(api::mark_announcement_read_api))
        .route("/api/announcements/:id",
            put(api::update_announcement_api)
            .delete(api::delete_announcement_api))
        .route("/api/support/messages", get(api::get_support_messages).post(api::create_support_message))
        .route("/api/support/messages/:id/review", post(api::review_support_message))
        .route("/api/support/messages/:id/reply", post(api::reply_support_message))
        .route("/api/support/messages/:id/forward", post(api::forward_support_message))
        .route("/api/support/messages/:id", delete(api::delete_support_message_api))
        .route("/api/admin/engines", get(api::get_engines))
        .route("/api/admin/engines/scale", post(api::scale_engines))
        .route("/api/admin/telemetry", get(api::get_telemetry))
        .route("/api/install-sensor.sh", get(api::install_sensor_script))
        .route("/api/uninstall-sensor.sh", get(api::uninstall_sensor_script))
        .route("/api/sensor-keys", 
            get(api::get_sensor_keys)
            .post(api::create_sensor_key_api))
        .route("/api/sensor-keys/:id",
            delete(api::revoke_sensor_key_api))
        .route("/api/sensor-keys/:id/reactivate",
            post(api::reactivate_sensor_key_api))
        .route("/api/sensor/register",  post(api::sensor_register))
        .route("/api/sensor/heartbeat", post(api::sensor_heartbeat))
        .route("/api/sensor/checkin",   post(api::sensor_checkin))
        .route("/api/sensors/assign",   post(api::assign_sensor_to_user).delete(api::remove_sensor_from_user))
        .route("/api/sensors/assignments", get(api::list_sensor_assignments))
        .route("/api/ingest",           post(api::ingest_events))
        .route("/api/sensor/command",   get(api::get_sensor_command_api))
        .route("/api/sensor/control",   post(api::sensor_control_api))
        .route("/api/arkime/sessions",           get(api::arkime_sessions))
        .route("/api/arkime/pcap/:id",           get(api::arkime_pcap_download))
        .route("/api/arkime/status",             get(api::arkime_status))
        .route("/api/arkime/link/:community_id", get(api::arkime_session_link))
        .route("/api/events/by-cid",             get(api::get_events_by_cid))
        .route("/api/pcap/upload",               post(api::pcap_upload))
        .route("/api/pcap/upload-failed",        post(api::pcap_upload_failed))
        .route("/api/pcap/pending",              get(api::pcap_pending))
        .route("/api/pcap/:session_id",          get(api::pcap_download_stored))
        // Evidence routes
.route("/api/evidence/bundles", get(api::list_evidence_bundles))
.route("/api/evidence/bundle/:id", get(api::get_evidence_bundle))
.route("/api/evidence/bundle/:id/verify", get(api::verify_evidence_bundle))
.route("/api/evidence/bundle/:id/hold", post(api::set_evidence_legal_hold))
.route("/api/evidence/bundle/:id/annotate", post(api::annotate_evidence_bundle))
.route("/api/evidence/bundle/:id/annotations", get(api::get_evidence_annotations))
.route("/api/evidence/bundle/:id/contents", get(api::get_bundle_contents))
.route("/api/evidence/:cid", get(api::download_evidence_bundle))
.route("/api/evidence/:cid/log", get(api::get_evidence_log))
.route("/api/evidence/:cid/timeline", get(api::get_evidence_timeline))
.route("/api/evidence/iocs/check", get(api::check_shared_ioc))
 .route("/api/aria/chat",        post(api::aria_chat))
.route("/api/aria/status",      get(api::aria_status))
.route("/api/aria/investigate", post(api::aria_investigate))
.route("/api/aria/verdict",     get(api::aria_get_verdict))
.route("/api/ai-activity", get(api::get_ai_activity))
.route("/api/ai-suppressions",                get(api::list_ai_suppressions).post(api::create_manual_suppression))
.route("/api/ai-suppressions/:id/deactivate", patch(api::deactivate_ai_suppression_handler))
.route("/api/ai-suppressions/:id", delete(api::delete_ai_suppression_handler))
.route("/api/blocks",          get(api::list_active_blocks))
.route("/api/blocks/manual",   post(api::manual_block))
.route("/api/blocks/revoke",   post(api::revoke_active_block))
.route("/api/incidents",                          get(api::list_incidents))
.route("/api/incidents/:id/status/:status",       post(api::update_incident_status))
.route("/api/doh-providers",                      get(api::list_doh_providers).post(api::add_doh_provider))
.route("/api/doh-providers/:ip",                  delete(api::delete_doh_provider))
.route("/api/isolations",      get(api::list_isolations))
.route("/api/isolate",         post(api::isolate_device_handler))
.route("/api/unisolate",       post(api::unisolate_device_handler))
.route("/api/threat/predictions",         get(api::get_threat_predictions))
.route("/api/threat/predictions/history", get(api::get_threat_predictions_history))
.route("/api/threat/exposure",            get(api::get_threat_exposure))
.route("/api/threat/patterns",            get(api::get_threat_patterns))
.route("/api/admin/leader-status",        get(api::get_leader_status))
.route("/api/monitor/kafka", get(monitor::kafka::kafka_status))
        .with_state(state.clone())
        .layer(axum::middleware::from_fn_with_state(state.clone(), api::auth_middleware))
        .layer(axum::middleware::from_fn(ratelimit::rate_limit_middleware))
        .layer(axum::middleware::from_fn(security_headers))
        .layer(DefaultBodyLimit::max(500 * 1024 * 1024)) // 500MB for PCAP uploads
        .layer(RequestDecompressionLayer::new())
        .layer(cors);

    info!("🌐 API active");
    info!("❤  Health:    GET  http://0.0.0.0:3000/health");
    info!("📡 Kafka:     ndr-events (broker: {})",
        std::env::var("KAFKA_BROKERS").unwrap_or_else(|_| KAFKA_DEFAULT.to_string()));

// ── Background: agent status monitor ─────────────────────────────────
    {
        let tx = tx.clone();
        tokio::spawn(async move {
            let client = reqwest::Client::new();
            let agent = std::env::var("NDR_AGENT_URL")
                .unwrap_or_else(|_| "http://host.docker.internal:3001".to_string());
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                if let Ok(resp) = client.get(format!("{}/agent/status", agent)).send().await {
                    if let Ok(data) = resp.json::<serde_json::Value>().await {
                        let msg = serde_json::json!({
                            "type": "agent_status",
                            "agent-z": data.get("agent-z").and_then(|v| v.as_str()).unwrap_or("stopped"),
                            "agent-s": data.get("agent-s").and_then(|v| v.as_str()).unwrap_or("stopped"),
                            "vector": data.get("vector").and_then(|v| v.as_str()).unwrap_or("stopped"),

                            "interface": data.get("interface").and_then(|v| v.as_str()).unwrap_or("eth0"),
                        });
                        let _ = tx.send(msg.to_string());
                    }
                }
            }
        });
    }

    // ── Background: Arkime → pcap_sessions sync — leader only ───────────────
    {
        let arkime_state = state.clone();
        let election_arkime = election.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            if election_arkime.is_leader() {
                api::sync_arkime_sessions(arkime_state).await;
            }
        });
    }

    // ── Background: daily PCAP file cleanup — leader only ────────────────────
    {
        let ch_cleanup = state.ch_storage.clone();
        let election_pcap = election.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            loop {
                if election_pcap.is_leader() {
                    cleanup_expired_pcaps(&ch_cleanup).await;
                }
                tokio::time::sleep(
                    std::time::Duration::from_secs(86400)
                ).await;
            }
        });
    }

    // ── Start server + graceful shutdown with leader release ─────────────
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    let server   = axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>());

    tokio::select! {
        res = server => {
            if let Err(e) = res { tracing::error!("Server error: {}", e); }
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Shutdown signal received — releasing leadership...");
            election.release().await;
            tracing::info!("Leadership released. Shutting down.");
        }
    }
}

/// Delete PCAP files older than 30 days from disk and remove their pcap_sessions rows.
/// Runs once per day. Queries every tenant DB for expired sessions.
async fn cleanup_expired_pcaps(ch: &storage::clickhouse::ClickhouseStorage) {
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct ExpiredRow { file_path: String, session_id: String, #[allow(dead_code)] tenant_id: String }

    // Get all tenant DBs from the tenants table
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct TenantRow { id: String }
    let tenants = ch.client
        .query("SELECT id FROM ndr.tenants WHERE active = 1")
        .fetch_all::<TenantRow>().await
        .unwrap_or_default();

    let mut total_deleted = 0usize;

    for t in &tenants {
        let db = if t.id == "default" {
            "ndr".to_string()
        } else {
            format!("ndr_{}", t.id.replace('-', "_"))
        };

        let rows = ch.client.query(&format!(
            "SELECT file_path, session_id, tenant_id \
             FROM {}.pcap_sessions \
             WHERE start_time < now() - INTERVAL 30 DAY \
             AND file_path != '' LIMIT 500",
            db
        )).fetch_all::<ExpiredRow>().await.unwrap_or_default();

        for row in &rows {
            // Delete file from disk only — pcap_sessions has TTL start_time + INTERVAL 30 DAY
            // so ClickHouse cleans up the DB rows automatically; ALTER TABLE DELETE is redundant
            // and heavyweight (async mutation, doesn't reclaim space immediately).
            if std::fs::remove_file(&row.file_path).is_ok() {
                total_deleted += 1;
            }
        }
    }

    if total_deleted > 0 {
        tracing::info!("PCAP cleanup: deleted {} expired files", total_deleted);
    }
}




