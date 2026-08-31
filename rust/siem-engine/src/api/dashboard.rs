// GET /api/siem/dashboard — ingest health stats for the SIEM dashboard page

use axum::{extract::{State, Extension}, Json, http::StatusCode};
use serde::Serialize;
use tracing::error;

use crate::AppState;
use crate::api::middleware::Claims;

#[derive(Serialize)]
pub struct DashboardResponse {
    pub stats:   SiemStats,
    pub sources: Vec<SourceHealth>,
}

#[derive(Serialize)]
pub struct SiemStats {
    pub eps_current:    f64,
    pub logs_today:     u64,
    pub logs_last_hour: u64,
    pub parse_errors:   u64,
    pub active_sources: u64,
    pub total_sources:  u64,
    pub kafka_lag:      u64,
}

#[derive(Serialize)]
pub struct SourceHealth {
    pub source_id:    String,
    pub name:         String,
    pub source_type:  String,
    pub status:       String,
    pub last_seen_at: String,
    pub eps:          f64,
}

pub async fn handler(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<DashboardResponse>, StatusCode> {
    let db = tenant_db(&claims.tenant_id);
    let client = reqwest::Client::new();

    // Logs ingested today
    let logs_today = query_u64(&client, &state.clickhouse_url, &db,
        "SELECT count() FROM siem_logs WHERE toDate(timestamp) = today()").await;

    // Logs last hour
    let logs_last_hour = query_u64(&client, &state.clickhouse_url, &db,
        "SELECT count() FROM siem_logs WHERE timestamp >= now() - INTERVAL 1 HOUR").await;

    // EPS = logs last 60 seconds / 60
    let logs_last_min = query_u64(&client, &state.clickhouse_url, &db,
        "SELECT count() FROM siem_logs WHERE timestamp >= now() - INTERVAL 1 MINUTE").await;
    let eps_current = logs_last_min as f64 / 60.0;

    // Parse errors today
    let parse_errors = query_u64(&client, &state.clickhouse_url, &db,
        "SELECT count() FROM siem_parse_errors WHERE toDate(created_at) = today()").await;

    // Source counts
    let total_sources = query_u64(&client, &state.clickhouse_url, &db,
        "SELECT count() FROM siem_sources FINAL").await;
    let active_sources = query_u64(&client, &state.clickhouse_url, &db,
        "SELECT count() FROM siem_sources FINAL WHERE status = 'active'").await;

    // Source health list
    let sources = query_sources(&client, &state.clickhouse_url, &db).await;

    Ok(Json(DashboardResponse {
        stats: SiemStats {
            eps_current,
            logs_today,
            logs_last_hour,
            parse_errors,
            active_sources,
            total_sources,
            kafka_lag: 0,  // TODO: pull from Kafka consumer group lag API
        },
        sources,
    }))
}

async fn query_u64(client: &reqwest::Client, url: &str, db: &str, sql: &str) -> u64 {
    let resp = client.get(url)
        .query(&[("query", &format!("{sql} FORMAT TabSeparated")), ("database", &db.to_string())])
        .send().await;

    match resp {
        Ok(r) if r.status().is_success() => {
            r.text().await.unwrap_or_default().trim().parse().unwrap_or(0)
        }
        Ok(r) => { error!("CH query failed: {}", r.text().await.unwrap_or_default()); 0 }
        Err(e) => { error!("CH request error: {e}"); 0 }
    }
}

async fn query_sources(client: &reqwest::Client, url: &str, db: &str) -> Vec<SourceHealth> {
    let sql = "SELECT source_id, name, source_type, status, last_seen_at \
               FROM siem_sources FINAL ORDER BY name LIMIT 100 FORMAT JSONEachRow";
    let resp = client.get(url)
        .query(&[("query", sql), ("database", db)])
        .send().await;

    match resp {
        Ok(r) if r.status().is_success() => {
            let text = r.text().await.unwrap_or_default();
            text.lines().filter_map(|line| {
                let v: serde_json::Value = serde_json::from_str(line).ok()?;
                Some(SourceHealth {
                    source_id:   v["source_id"].as_str().unwrap_or("").to_string(),
                    name:        v["name"].as_str().unwrap_or("").to_string(),
                    source_type: v["source_type"].as_str().unwrap_or("").to_string(),
                    status:      v["status"].as_str().unwrap_or("active").to_string(),
                    last_seen_at:v["last_seen_at"].as_str().unwrap_or("").to_string(),
                    eps:         0.0,
                })
            }).collect()
        }
        _ => vec![],
    }
}

fn tenant_db(tenant_id: &str) -> String {
    if tenant_id == "default" { "ndr".into() } else { format!("ndr_{}", tenant_id) }
}
