use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use redis::AsyncCommands;

use crate::AppState;
use provigil_common::validate_jwt;

// ─────────────────────────────────────────────────────────────────────────────
// Token extraction helper (cookie first, then Bearer header)
// ─────────────────────────────────────────────────────────────────────────────

fn extract_token(headers: &HeaderMap) -> Option<String> {
    let from_cookie = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|c| c.split(';').find_map(|p| {
            p.trim().strip_prefix("ndr_token=").map(str::to_owned)
        }));
    if from_cookie.is_some() {
        return from_cookie;
    }
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|v| v.trim().to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// Auth helper — validate JWT + Valkey session check (force-logout enforcement)
// ─────────────────────────────────────────────────────────────────────────────

async fn auth(headers: &HeaderMap, state: &AppState)
    -> Result<provigil_common::Claims, (StatusCode, Json<serde_json::Value>)>
{
    let token = extract_token(headers).ok_or_else(|| (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "status": "error", "message": "Unauthorized" })),
    ))?;
    let claims = validate_jwt(&token, &state.jwt_secret).map_err(|_| (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "status": "error", "message": "Token invalid or expired" })),
    ))?;
    let key = format!("provigil:session:{}", claims.jti);
    let alive: bool = state.valkey.clone().exists(&key).await.unwrap_or(false);
    if !alive {
        return Err((StatusCode::UNAUTHORIZED,
            Json(json!({ "status": "error", "message": "Session revoked — please log in again" }))));
    }
    Ok(claims)
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/auth/tenants
// ─────────────────────────────────────────────────────────────────────────────

pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let claims = match auth(&headers, &state).await {
        Ok(c)  => c,
        Err((s, j)) => return (s, j).into_response(),
    };

    if claims.role != "super_admin" && claims.role != "tenant_admin" {
        return (StatusCode::FORBIDDEN,
            Json(json!({ "status": "error", "message": "Forbidden" }))).into_response();
    }

    match state.db.get_all_tenants().await {
        Ok(tenants) => (StatusCode::OK, Json(json!({ "status": "ok", "tenants": tenants }))).into_response(),
        Err(e) => {
            tracing::error!("get_all_tenants error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": "Failed to fetch tenants" }))).into_response()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/tenants
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateTenantPayload {
    pub name: String,
}

pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateTenantPayload>,
) -> impl IntoResponse {
    let claims = match auth(&headers, &state).await {
        Ok(c)  => c,
        Err((s, j)) => return (s, j).into_response(),
    };

    if claims.role != "super_admin" {
        return (StatusCode::FORBIDDEN,
            Json(json!({ "status": "error", "message": "Forbidden" }))).into_response();
    }

    let name = payload.name.trim();
    if name.is_empty() {
        return (StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "message": "Tenant name is required" }))).into_response();
    }

    let id = Uuid::new_v4().to_string();
    match state.db.create_tenant(&id, name).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "ok", "id": id, "message": "Tenant created" }))).into_response(),
        Err(e) => {
            tracing::error!("create_tenant error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": "Failed to create tenant" }))).into_response()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PUT /api/auth/tenants/:id
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct UpdateTenantPayload {
    pub name:   String,
    pub active: Option<bool>,
}

pub async fn update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<UpdateTenantPayload>,
) -> impl IntoResponse {
    let claims = match auth(&headers, &state).await {
        Ok(c)  => c,
        Err((s, j)) => return (s, j).into_response(),
    };

    if claims.role != "super_admin" {
        return (StatusCode::FORBIDDEN,
            Json(json!({ "status": "error", "message": "Forbidden" }))).into_response();
    }

    let active = payload.active.unwrap_or(true);
    match state.db.update_tenant(&id, payload.name.trim(), active).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "ok", "message": "Tenant updated" }))).into_response(),
        Err(e) => {
            tracing::error!("update_tenant error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": "Failed to update tenant" }))).into_response()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/tenants/:id/status
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SetStatusPayload {
    pub active: bool,
}

pub async fn set_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<SetStatusPayload>,
) -> impl IntoResponse {
    let claims = match auth(&headers, &state).await {
        Ok(c)  => c,
        Err((s, j)) => return (s, j).into_response(),
    };

    if claims.role != "super_admin" {
        return (StatusCode::FORBIDDEN,
            Json(json!({ "status": "error", "message": "Forbidden" }))).into_response();
    }

    match state.db.set_tenant_active(&id, payload.active).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "ok" }))).into_response(),
        Err(e) => {
            tracing::error!("set_tenant_active error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": "Failed to update tenant status" }))).into_response()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/tenants/:id/ai-enabled
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SetAiEnabledPayload {
    pub enabled: bool,
}

pub async fn set_ai_enabled(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(payload): Json<SetAiEnabledPayload>,
) -> impl IntoResponse {
    let claims = match auth(&headers, &state).await {
        Ok(c)  => c,
        Err((s, j)) => return (s, j).into_response(),
    };

    if claims.role != "super_admin" {
        return (StatusCode::FORBIDDEN,
            Json(json!({ "status": "error", "message": "Forbidden" }))).into_response();
    }

    match state.db.set_tenant_ai_enabled(&id, payload.enabled).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "ok" }))).into_response(),
        Err(e) => {
            tracing::error!("set_tenant_ai_enabled error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": "Failed to update AI setting" }))).into_response()
        }
    }
}
