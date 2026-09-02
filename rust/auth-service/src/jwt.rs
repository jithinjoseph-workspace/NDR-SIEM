use anyhow::Result;
use redis::AsyncCommands;

use crate::AppState;

/// Revoke a specific session JTI (used by force-logout per device).
pub async fn revoke_session(state: &AppState, jti: &str) -> Result<()> {
    let mut conn = state.valkey.clone();
    let key = format!("provigil:session:{}", jti);
    conn.del::<_, ()>(key).await?;
    Ok(())
}
