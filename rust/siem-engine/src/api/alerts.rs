use axum::{extract::State, Json};
use axum::http::StatusCode;
use serde_json::{json, Value};
use crate::AppState;

/// GET /api/xdr/alerts — unified alert queue (NDR + SIEM + corroborated).
/// Reads from ndr.unified_alerts in ClickHouse, filtered by tenant_id from JWT.
pub async fn list(
    State(_state): State<AppState>,
) -> (StatusCode, Json<Value>) {
    // TODO Phase 1: extract tenant_id from JWT, query unified_alerts with filters
    (StatusCode::OK, Json(json!({ "alerts": [], "total": 0 })))
}
