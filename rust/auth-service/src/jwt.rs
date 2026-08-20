use anyhow::Result;
use redis::AsyncCommands;

use crate::AppState;

/// Register a session in Valkey so force-logout and refresh can find it.
///
/// key  : `provigil:session:{jti}`
/// value: username
/// TTL  : refresh_ttl (7 days by default)
pub async fn register_session(
    state: &AppState,
    jti: &str,
    username: &str,
) -> Result<()> {
    let mut conn = state.valkey.clone();
    let key = format!("provigil:session:{}", jti);
    conn.set_ex::<_, _, ()>(key, username, state.refresh_ttl).await?;
    Ok(())
}

/// Store a refresh token in Valkey.
///
/// key  : `provigil:refresh:{user_id}`
/// value: refresh token string
/// TTL  : refresh_ttl
pub async fn store_refresh_token(
    state: &AppState,
    user_id: &str,
    refresh_token: &str,
) -> Result<()> {
    let mut conn = state.valkey.clone();
    let key = format!("provigil:refresh:{}", user_id);
    conn.set_ex::<_, _, ()>(key, refresh_token, state.refresh_ttl).await?;
    Ok(())
}

/// Retrieve and validate a stored refresh token.
/// Returns the stored token string if it exists and matches.
pub async fn validate_refresh_token(
    state: &AppState,
    user_id: &str,
    presented: &str,
) -> Result<bool> {
    let mut conn = state.valkey.clone();
    let key = format!("provigil:refresh:{}", user_id);
    let stored: Option<String> = conn.get(key).await?;
    Ok(stored.as_deref() == Some(presented))
}

/// Revoke all sessions for a user (logout).
pub async fn revoke_refresh_token(state: &AppState, user_id: &str) -> Result<()> {
    let mut conn = state.valkey.clone();
    let key = format!("provigil:refresh:{}", user_id);
    conn.del::<_, ()>(key).await?;
    Ok(())
}

/// Revoke a specific session JTI (used by force-logout per device).
pub async fn revoke_session(state: &AppState, jti: &str) -> Result<()> {
    let mut conn = state.valkey.clone();
    let key = format!("provigil:session:{}", jti);
    conn.del::<_, ()>(key).await?;
    Ok(())
}
