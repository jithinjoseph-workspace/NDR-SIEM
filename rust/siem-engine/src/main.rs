use std::net::SocketAddr;
use axum::{Router, Json};
use axum::http::StatusCode;
use serde_json::{json, Value};
use tower_http::cors::{CorsLayer, Any};
use tracing::info;

mod api;
mod correlation;

fn require_env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("{} is required", key))
}

#[derive(Clone)]
pub struct AppState {
    pub jwt_secret:     String,
    pub valkey_url:     String,
    pub clickhouse_url: String,
    pub kafka_brokers:  String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env()
            .add_directive("siem_engine=info".parse().unwrap()))
        .init();

    let jwt_secret     = require_env("JWT_SECRET");
    let valkey_url     = std::env::var("VALKEY_URL")
        .unwrap_or_else(|_| "redis://localhost:6379".to_string());
    let clickhouse_url = std::env::var("CLICKHOUSE_URL")
        .unwrap_or_else(|_| "http://localhost:8123".to_string());
    let kafka_brokers  = std::env::var("KAFKA_BROKERS")
        .unwrap_or_else(|_| "kafka:9092".to_string());
    let listen_addr: SocketAddr = std::env::var("LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:3002".to_string())
        .parse()
        .expect("Invalid LISTEN_ADDR");

    let state = AppState {
        jwt_secret,
        valkey_url:     valkey_url.clone(),
        clickhouse_url: clickhouse_url.clone(),
        kafka_brokers:  kafka_brokers.clone(),
    };

    // ── Start SIEM Correlation Engine (Dev 2) ─────────────────────────────────
    correlation::start(kafka_brokers, clickhouse_url, valkey_url).await?;

    // ── CORS ──────────────────────────────────────────────────────────────────
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // ── Routes ────────────────────────────────────────────────────────────────
    let app = Router::new()
        .route("/api/health",          axum::routing::get(health))
        // Dev 1 routes (stubs — implemented on siem/ingest branch)
        .route("/api/siem/ingest",     axum::routing::post(api::ingest::handle))
        // Dev 2 routes
        .route("/api/xdr/alerts",      axum::routing::get(api::alerts::list))
        .route("/api/siem/rules",      axum::routing::get(api::rules::list_rules))
        .route("/api/siem/rules/:id",  axum::routing::put(api::rules::update_rule))
        .layer(cors)
        .with_state(state);

    info!("siem-engine listening on {}", listen_addr);
    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> (StatusCode, Json<Value>) {
    (StatusCode::OK, Json(json!({
        "status":  "ok",
        "service": "siem-engine",
        "modules": [
            "correlation-engine",
            "kafka-consumer",
            "ueba-baseline",
            "sla-checker",
            "living-genome"
        ]
    })))
}



