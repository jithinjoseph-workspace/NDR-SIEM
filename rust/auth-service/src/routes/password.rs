use axum::{extract::State, Json};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::AppState;
use super::login::validate_password_strength;

#[derive(Deserialize)]
pub struct ResetPasswordPayload {
    pub username:     String,
    pub tenant_id:    String,
    pub new_password: String,
    /// Present for self-service reset; absent for admin-initiated reset.
    pub old_password: Option<String>,
}

/// POST /api/auth/reset-password
///
/// Self-service: validates old_password before accepting new_password.
/// Admin reset: no old_password required — relies on the caller holding
///              a valid super_admin or tenant_admin JWT.
pub async fn handle(
    State(state): State<AppState>,
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

    // Self-service path — verify current password before accepting the change
    if let Some(old_pw) = payload.old_password.as_deref() {
        match bcrypt::verify(old_pw, &user.password_hash) {
            Ok(true) => {}
            Ok(false) => return Json(json!({ "status": "error", "message": "Current password is incorrect" })),
            Err(_)    => return Json(json!({ "status": "error", "message": "Internal error" })),
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
