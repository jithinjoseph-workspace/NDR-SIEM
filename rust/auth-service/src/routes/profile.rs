use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;

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
// PUT /api/auth/me/gmail
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct UpdateGmailPayload {
    pub gmail: String,
}

pub async fn update_gmail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<UpdateGmailPayload>,
) -> impl IntoResponse {
    let claims = match auth(&headers, &state).await {
        Ok(c)  => c,
        Err((s, j)) => return (s, j).into_response(),
    };

    let gmail = payload.gmail.trim();

    // Validate email format
    if !gmail.is_empty() && !is_valid_email(gmail) {
        return (StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "message": "Invalid email format" }))).into_response();
    }

    // We need the user's DB id. Use sub (username) to look up by username
    let user = match state.db.get_user(&claims.sub, &claims.tenant_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return (StatusCode::NOT_FOUND,
            Json(json!({ "status": "error", "message": "User not found" }))).into_response(),
        Err(e) => {
            tracing::error!("get_user error in update_gmail: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": "DB error" }))).into_response();
        }
    };

    match state.db.update_user_gmail(&user.id, gmail).await {
        Ok(()) => (StatusCode::OK,
            Json(json!({ "status": "ok", "gmail": gmail, "message": "Email updated" }))).into_response(),
        Err(e) => {
            tracing::error!("update_user_gmail error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": "Failed to update email" }))).into_response()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/me/regenerate-secret
// ─────────────────────────────────────────────────────────────────────────────

pub async fn regenerate_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let claims = match auth(&headers, &state).await {
        Ok(c)  => c,
        Err((s, j)) => return (s, j).into_response(),
    };

    // Generate 6-char alphanumeric code (in own scope before async)
    let code = {
        use rand::Rng;
        rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(6)
            .map(char::from)
            .collect::<String>()
    };

    let user = match state.db.get_user(&claims.sub, &claims.tenant_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return (StatusCode::NOT_FOUND,
            Json(json!({ "status": "error", "message": "User not found" }))).into_response(),
        Err(e) => {
            tracing::error!("get_user error in regenerate_secret: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": "DB error" }))).into_response();
        }
    };

    match state.db.update_user_secret_code(&user.id, &code).await {
        Ok(()) => (StatusCode::OK,
            Json(json!({ "status": "ok", "secret_code": code }))).into_response(),
        Err(e) => {
            tracing::error!("update_user_secret_code error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": "Failed to regenerate secret" }))).into_response()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn is_valid_email(email: &str) -> bool {
    let parts: Vec<&str> = email.splitn(2, '@').collect();
    if parts.len() != 2 { return false; }
    let domain = parts[1];
    !parts[0].is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
}
