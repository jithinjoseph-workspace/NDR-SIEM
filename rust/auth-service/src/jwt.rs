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
pub async fn revoke_session(state: &AppState, jti: &str) -> Result<()> {
    let mut conn = state.valkey.clone();
    conn.del::<_, ()>(format!("provigil:session:{}", jti)).await?;
    conn.del::<_, ()>(format!("ndr:session:{}", jti)).await?;
    Ok(())
}
