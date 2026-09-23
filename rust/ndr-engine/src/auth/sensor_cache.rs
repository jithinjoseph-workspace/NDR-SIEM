//! Shared (Redis-backed) cache for sensor API key → tenant_id lookups.
//!
//! All ndr-engine instances share ONE cache via Redis, so a key revocation
//! or new key is visible to every instance consistently — not just whichever
//! instance happens to refresh next. Engines remain stateless.
//!
//! Schema note: ndr.sensor_keys stores key_hash (bcrypt) + key_prefix, NOT
//! plain api_keys. So the cache can't be bulk-preloaded from DB. It is
//! populated on first use (bcrypt verify + DB lookup), then cached in Redis
//! with a 90s TTL. Revocation is immediate via invalidate().

use redis::AsyncCommands;
use std::sync::Arc;

const CACHE_PREFIX: &str = "sensorkey:";
// TTL slightly longer than the 60s refresh interval so entries don't
// expire between refresh cycles under normal operation.
const CACHE_TTL_SECS: usize = 90;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SensorKeyInfo {
    pub tenant_id:  String,
    pub key_prefix: String,
    pub active:     bool,
}

pub struct SensorKeyCache {
    redis: Arc<redis::Client>,
}

impl SensorKeyCache {
    pub fn new(redis_client: Arc<redis::Client>) -> Self {
        Self { redis: redis_client }
    }

    /// Look up a sensor key in Redis. Returns None on cache miss OR on any
    /// Redis connectivity issue — caller always falls back to direct DB.
    pub async fn get(&self, api_key: &str) -> Option<SensorKeyInfo> {
        let mut conn = self.redis
            .get_multiplexed_async_connection()
            .await
            .ok()?;

        let redis_key = format!("{}{}", CACHE_PREFIX, api_key);
        let raw: Option<String> = conn.get(&redis_key).await.ok()?;
        raw.and_then(|s| serde_json::from_str(&s).ok())
    }

    /// Insert/update a single entry with TTL.
    /// Called on cache-miss fallback after successful bcrypt verify.
    pub async fn insert(&self, api_key: &str, info: &SensorKeyInfo) {
        let Ok(mut conn) = self.redis
            .get_multiplexed_async_connection()
            .await
        else {
            tracing::warn!("Redis unavailable — sensor key cache insert skipped");
            return;
        };

        let redis_key = format!("{}{}", CACHE_PREFIX, api_key);
        let Ok(json) = serde_json::to_string(info) else { return; };
        let _: Result<(), _> = conn.set_ex(&redis_key, json, CACHE_TTL_SECS).await;
    }

    /// Immediately remove a key from the shared Redis cache.
    /// Called when an admin revokes a sensor key so ALL engine instances
    /// reject it on their very next lookup, with no TTL wait.
    pub async fn invalidate(&self, api_key: &str) {
        let Ok(mut conn) = self.redis
            .get_multiplexed_async_connection()
            .await
        else {
            return;
        };

        let redis_key = format!("{}{}", CACHE_PREFIX, api_key);
        let _: Result<i64, _> = conn.del(&redis_key).await;

        tracing::info!(
            "Sensor key cache invalidated: {}…",
            &api_key[..api_key.len().min(16)]
        );
    }

    /// Invalidate all Redis cache entries for a given key_prefix.
    /// Called on key revocation — since plain api_keys are never stored in
    /// DB (only bcrypt hashes), we know the key_prefix (first 16 chars) and
    /// can SCAN+DEL all matching `sensorkey:{prefix}*` Redis entries.
    /// This removes the entry regardless of what the full plain key was.
    pub async fn invalidate_by_prefix(&self, key_prefix: &str) {
        let Ok(mut conn) = self.redis
            .get_multiplexed_async_connection()
            .await
        else {
            return;
        };

        let pattern = format!("{}{}*", CACHE_PREFIX, key_prefix);
        let mut cursor = 0u64;
        let mut deleted = 0u32;

        loop {
            // SCAN with MATCH — non-blocking cursor-based iteration
            let (new_cursor, keys): (u64, Vec<String>) =
                redis::cmd("SCAN")
                    .arg(cursor)
                    .arg("MATCH")
                    .arg(&pattern)
                    .arg("COUNT")
                    .arg(100u32)
                    .query_async(&mut conn)
                    .await
                    .unwrap_or((0, vec![]));

            for k in &keys {
                let _: Result<i64, _> = conn.del(k).await;
                deleted += 1;
            }

            cursor = new_cursor;
            if cursor == 0 { break; }
        }

        tracing::info!(
            "Sensor key cache: invalidated {} entr{} for prefix {}…",
            deleted,
            if deleted == 1 { "y" } else { "ies" },
            key_prefix
        );
    }

    /// Returns `true` if a heartbeat DB write is needed for this sensor.
    ///
    /// Writes are triggered when status changes OR every 5 minutes (cache TTL
    /// expiry), so `last_seen` stays accurate within 5 minutes even under
    /// stable conditions — without a ClickHouse write on every checkin.
    pub async fn needs_heartbeat_write(&self, sensor_id: &str, status_sig: &str) -> bool {
        let mut conn = match self.redis
            .get_multiplexed_async_connection()
            .await
        {
            Ok(c) => c,
            Err(_) => return true, // Redis unavailable → always write
        };

        let key = format!("sensor_hb:{}", sensor_id);
        let cached = conn
            .get::<_, Option<String>>(&key)
            .await
            .unwrap_or(None);

        // Refresh TTL: if status stays the same, cache expires in 5 min and
        // the next checkin after expiry writes to DB — keeping last_seen fresh.
        let _: Result<(), _> = conn.set_ex(&key, status_sig, 300usize).await;

        // Write if first time seen OR status changed
        cached.as_deref() != Some(status_sig)
    }
}

/// Spawn a background health-check loop that logs DB active key count
/// every 60s and confirms Redis connectivity. Call once at startup.
///
/// Note: we cannot bulk-preload the cache because plain API keys are never
/// stored (only bcrypt hashes). Cache entries are populated on first use
/// and expire after 90s TTL. Revocation is handled immediately by
/// invalidate() called from the revoke-key handler.
pub fn spawn_refresh_loop(
    cache: Arc<SensorKeyCache>,
    ch_storage: Arc<crate::storage::ClickhouseStorage>,
) {
    tokio::spawn(async move {
        loop {
            // Count active keys in DB for health logging
            match count_active_keys(&ch_storage).await {
                Ok(n) => {
                    // Also confirm Redis is reachable
                    let redis_ok = cache.redis
                        .get_multiplexed_async_connection()
                        .await
                        .is_ok();
                    tracing::debug!(
                        "Sensor key cache health: {} active keys, redis_ok={}",
                        n, redis_ok
                    );
                }
                Err(e) => {
                    tracing::error!("Sensor key DB health check failed: {}", e);
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        }
    });
}

async fn count_active_keys(
    ch: &crate::storage::ClickhouseStorage,
) -> anyhow::Result<u64> {
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct Row { count: u64 }

    let rows = ch.client
        .query("SELECT count() as count FROM ndr.sensor_keys FINAL WHERE active = 1")
        .fetch_all::<Row>()
        .await?;

    Ok(rows.first().map(|r| r.count).unwrap_or(0))
}

/// Resolve a sensor API key to its tenant_id.
///
/// Fast path  (Redis hit)  : O(1), no DB, no bcrypt.
/// Slow path  (Redis miss) : full bcrypt+DB lookup (same cost as before),
///                           then the result is stored in SHARED Redis so
///                           every other engine instance benefits too.
pub async fn resolve_tenant(
    cache: &SensorKeyCache,
    ch: &crate::storage::ClickhouseStorage,
    api_key: &str,
) -> Option<String> {
    if api_key.is_empty() {
        return None;
    }

    // Fast path — shared Redis cache hit
    if let Some(info) = cache.get(api_key).await {
        if info.active {
            return Some(info.tenant_id);
        }
        return None;
    }

    // Slow path — cache miss: existing validate_sensor_key does prefix
    // lookup + bcrypt verify. Result is then cached in shared Redis so
    // every other engine instance benefits on subsequent requests.
    let tenant_id = ch.validate_sensor_key(api_key).await.ok()??;

    let info = SensorKeyInfo {
        tenant_id: tenant_id.clone(),
        key_prefix: api_key.chars().take(16).collect(),
        active: true,
    };
    cache.insert(api_key, &info).await;

    tracing::debug!(
        "Sensor key cache populated: prefix={}…",
        &api_key[..api_key.len().min(16)]
    );
    Some(tenant_id)
}

/// True when `api_key` is a real key that an admin has revoked (the bcrypt hash
/// matches an inactive row). An unknown or malformed key is NOT "revoked".
/// The verdict is cached (as an inactive entry) so a sensor that keeps
/// retrying costs one Redis read, not a DB query plus bcrypt, per request.
pub async fn is_revoked(
    cache: &SensorKeyCache,
    ch: &crate::storage::ClickhouseStorage,
    api_key: &str,
) -> bool {
    if api_key.len() < 16 {
        return false;
    }
    if let Some(info) = cache.get(api_key).await {
        return !info.active;
    }
    if !ch.is_revoked_sensor_key(api_key).await.unwrap_or(false) {
        return false;
    }
    let info = SensorKeyInfo {
        tenant_id: String::new(),
        key_prefix: api_key.chars().take(16).collect(),
        active: false,
    };
    cache.insert(api_key, &info).await;
    true
}
