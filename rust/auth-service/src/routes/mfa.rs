use axum::{extract::State, http::HeaderMap, response::IntoResponse, Json};
use axum::http::StatusCode;
use redis::AsyncCommands;
use serde::Deserialize;
use serde_json::json;

use crate::{AppState, mfa as totp_verify};
use super::login::issue_full_token;

#[derive(Deserialize)]
pub struct MfaPayload {
    pub mfa_session: String,
    pub code:        String,
}

/// POST /api/auth/mfa/verify
///
/// Second step of login when MFA is enabled.
/// Client sends the mfa_session token from step 1 + the 6-digit TOTP code.
/// Returns the same full JWT response as a successful login.
pub async fn handle(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<MfaPayload>,
) -> impl IntoResponse {
    let pending_key = format!("provigil:mfa_pending:{}", payload.mfa_session);
    let mut conn = state.valkey.clone();

    let user_id: Option<String> = match conn.get(&pending_key).await {
        Ok(v)  => v,
        Err(_) => return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "status": "error", "message": "MFA session expired" })),
        ).into_response(),
    };

    let user_id = match user_id {
        Some(v) => v,
        None    => return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "status": "error", "message": "MFA session not found or expired" })),
        ).into_response(),
    };

    let user = match state.db.get_user_by_id(&user_id).await {
        Ok(Some(u)) => u,
        _ => return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "status": "error", "message": "User not found" })),
        ).into_response(),
    };

    // MFA fields not in current schema — placeholder for future support
    // Consume the one-time MFA session token
    let _: redis::RedisResult<()> = conn.del(&pending_key).await;

    issue_full_token(
        &state, &headers,
        &user.id, &user.username, &user.role, &user.tenant_id,
        &user.permissions, &user.gmail, &user.secret_code,
    ).await
}
