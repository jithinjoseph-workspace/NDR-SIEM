use std::net::SocketAddr;
use axum::{Router, Json};
use serde_json::{json, Value};
use tower_http::cors::{CorsLayer, Any};
use tracing::info;

mod api;

fn require_env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("{} is required", key))
}

#[derive(Clone)]
pub struct AppState {
    pub jwt_secret:   String,
    pub valkey_url:   String,
    pub clickhouse_url: String,
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
    let listen_addr: SocketAddr = std::env::var("LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:3002".to_string())
        .parse()
        .expect("Invalid LISTEN_ADDR");

    let state = AppState { jwt_secret, valkey_url, clickhouse_url };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/api/health", axum::routing::get(health))
        .route("/api/siem/ingest", axum::routing::post(api::ingest::handle))
        .route("/api/xdr/alerts",  axum::routing::get(api::alerts::list))
        .layer(cors)
        .with_state(state);

    info!("siem-engine listening on {}", listen_addr);
    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> Json<Value> {
    Json(json!({ "status": "ok", "service": "siem-engine" }))
}
