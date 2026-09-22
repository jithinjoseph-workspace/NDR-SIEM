use axum::{extract::State, http::HeaderMap, Json};
use redis::AsyncCommands;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::AppState;
use provigil_common::validate_jwt;
use super::login::validate_password_strength;

#[derive(Deserialize)]
pub struct ResetPasswordPayload {
    pub username:     String,
    pub tenant_id:    String,
    pub new_password: String,
    /// Present for self-service reset; absent for admin-initiated reset.
    pub old_password: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Token extraction + session check (same pattern as users.rs/tenants.rs)
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

async fn auth(headers: &HeaderMap, state: &AppState) -> Result<provigil_common::Claims, Json<Value>> {
    let token = extract_token(headers)
        .ok_or_else(|| Json(json!({ "status": "error", "message": "Unauthorized" })))?;
    let claims = validate_jwt(&token, &state.jwt_secret)
        .map_err(|_| Json(json!({ "status": "error", "message": "Token invalid or expired" })))?;
    let key = format!("provigil:session:{}", claims.jti);
    let alive: bool = state.valkey.clone().exists(&key).await.unwrap_or(false);
    if !alive {
        return Err(Json(json!({ "status": "error", "message": "Session revoked — please log in again" })));
    }
    Ok(claims)
}

/// POST /api/auth/reset-password
///
/// Self-service: validates old_password before accepting new_password — proof
/// of identity is knowing the current password, no session required, same as
/// before.
///
/// Admin reset (old_password absent): TC-084 — this branch used to trust the
/// request body alone with NO auth check whatsoever (the handler took no
/// HeaderMap, so it could not have checked one even if it tried), letting
/// anyone reset any account's password with just a username + tenant_id.
/// Now requires a live super_admin or tenant_admin session; tenant_admin is
/// restricted to their own tenant and to the same manageable-roles set
/// already enforced on the equivalent id-based endpoint in users.rs.
pub async fn handle(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ResetPasswordPayload>,
) -> Json<Value> {
    let username     = payload.username.trim();
    let tenant_id    = payload.tenant_id.trim();
    let new_password = payload.new_password.trim();

    if let Err(msg) = validate_password_strength(new_password) {
        return Json(json!({ "status": "error", "message": msg }));
    }

    let user = match state.db.get_user(username, tenant_id).await {
        Ok(Some(u)) => u,
        Ok(None)    => return Json(json!({ "status": "error", "message": "User not found" })),
        Err(e) => {
            tracing::error!("DB error in reset-password: {}", e);
            return Json(json!({ "status": "error", "message": "Service unavailable" }));
        }
    };

    match payload.old_password.as_deref() {
        // Self-service path — verify current password before accepting the change
        Some(old_pw) => {
            match bcrypt::verify(old_pw, &user.password_hash) {
                Ok(true) => {}
                Ok(false) => return Json(json!({ "status": "error", "message": "Current password is incorrect" })),
                Err(_)    => return Json(json!({ "status": "error", "message": "Internal error" })),
            }
        }
        // Admin reset path — now actually requires the JWT the doc comment always claimed it checked
        None => {
            let claims = match auth(&headers, &state).await {
                Ok(c) => c,
                Err(j) => return j,
            };
            if claims.role != "super_admin" && claims.role != "tenant_admin" {
                return Json(json!({ "status": "error", "message": "Forbidden" }));
            }
            if user.role == "super_admin" {
                return Json(json!({ "status": "error", "message": "Super admin password cannot be changed here" }));
            }
            if claims.role == "tenant_admin" {
                let manageable_roles = ["analyst", "senior_analyst", "viewer"];
                if claims.tenant_id != user.tenant_id || !manageable_roles.contains(&user.role.as_str()) {
                    return Json(json!({ "status": "error", "message": "Forbidden" }));
                }
            }
        }
    }

    let new_hash = match bcrypt::hash(new_password, bcrypt::DEFAULT_COST) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("bcrypt hash error: {}", e);
            return Json(json!({ "status": "error", "message": "Internal error" }));
        }
    };

    match state.db.set_password_hash(&user.id, &new_hash).await {
        Ok(()) => Json(json!({ "status": "ok", "message": "Password updated successfully" })),
        Err(e) => {
            tracing::error!("Failed to update password: {}", e);
            Json(json!({ "status": "error", "message": "Failed to update password" }))
        }
    }
}
