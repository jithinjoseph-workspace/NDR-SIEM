use anyhow::Result;
use redis::AsyncCommands;

use crate::AppState;

/// Revoke a specific session JTI (used by logout and token refresh rotation).
///
/// Deletes both session namespaces: provigil:session:{jti}, which this
/// service's own auth() check reads, and ndr:session:{jti}, which
/// ndr-engine's auth_middleware reads. Both are written together at login
/// (login.rs), so leaving either one behind lets that jti keep working on
/// whichever service still sees it as alive.
///
/// Also removes the jti from the 4 tracking sets login.rs adds it to
/// (provigil:user_sessions, provigil:tenant_sessions, ndr:user_sessions,
/// ndr:tenant_sessions) - previously left behind on every single logout,
/// so the concurrent-session eviction check in login.rs (which reads these
/// sets) accumulated one permanent ghost entry per logout forever. Found
/// live: tenant-admin's set was already at the 5-session cap with 3 of the
/// 5 being dead ghosts, silently shrinking real session capacity to 2.
/// Must read the hash's username/tenant_id *before* deleting it - that's
/// the only place this function learns which sets to clean.
pub async fn revoke_session(state: &AppState, jti: &str) -> Result<()> {
    let mut conn = state.valkey.clone();
    let session_key = format!("provigil:session:{}", jti);

    let fields: std::collections::HashMap<String, String> =
        conn.hgetall(&session_key).await.unwrap_or_default();

    conn.del::<_, ()>(&session_key).await?;
    conn.del::<_, ()>(format!("ndr:session:{}", jti)).await?;

    if let (Some(username), Some(tenant_id)) = (fields.get("username"), fields.get("tenant_id")) {
        let _: redis::RedisResult<i64> = conn.srem(format!("provigil:user_sessions:{}:{}", tenant_id, username), jti).await;
        let _: redis::RedisResult<i64> = conn.srem(format!("provigil:tenant_sessions:{}", tenant_id), jti).await;
        let _: redis::RedisResult<i64> = conn.srem(format!("ndr:user_sessions:{}:{}", tenant_id, username), jti).await;
        let _: redis::RedisResult<i64> = conn.srem(format!("ndr:tenant_sessions:{}", tenant_id), jti).await;
    }

    Ok(())
}
