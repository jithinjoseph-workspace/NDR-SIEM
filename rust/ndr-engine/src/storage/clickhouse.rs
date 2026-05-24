use clickhouse::Client;
use bcrypt;
use serde::{Serialize, Deserialize};
use serde_json::json;



#[derive(Debug, Serialize, clickhouse::Row)]
pub struct NdrEvent {
    pub timestamp:    u32,
    pub source:       String,
    pub src_ip:       String,
    pub dst_ip:       String,
    pub src_port:     u16,
    pub dst_port:     u16,
    pub proto:        String,
    pub event_type:   String,
    pub community_id: String,
    pub raw:          String,
    pub tenant_id:    String,
}

#[derive(Debug, Serialize, clickhouse::Row)]
pub struct NdrHit {
    pub timestamp:    u32,
    pub community_id: String,
    pub src_ip:       String,
    pub dst_ip:       String,
    pub score:        f32,
    pub severity:     String,
    pub tags:         Vec<String>,
    pub sigma_hits:   Vec<String>,
    pub threat_intel: u8,
    pub src_country:  String,
    pub dst_country:  String,
    pub tenant_id:    String,
}

#[derive(Debug, Serialize, Deserialize, clickhouse::Row)]
#[allow(dead_code)]
pub struct TopIp {
    pub ip:    String,
    pub count: u64,
}


#[derive(Debug, Serialize, Deserialize, clickhouse::Row)]
pub struct NetworkPair {
    pub src_ip:      String,
    pub dst_ip:      String,
    pub connections: u64,
    pub protocols:   Vec<String>,
}


#[derive(Debug, Serialize, Deserialize, clickhouse::Row)]
#[allow(dead_code)]
pub struct RecentEvent {
    pub timestamp:    u32,
    pub source:       String,
    pub src_ip:       String,
    pub dst_ip:       String,
    pub proto:        String,
    pub event_type:   String,
    pub community_id: String,
}
#[derive(Debug, Serialize, Deserialize, clickhouse::Row)]
#[allow(dead_code)]
pub struct RecentHit {
    pub timestamp:    u32,
    pub community_id: String,
    pub src_ip:       String,
    pub dst_ip:       String,
    pub score:        f32,
    pub severity:     String,
    pub threat_intel: u8,
    pub src_country:  String,
    pub dst_country:  String,
}
#[derive(Debug, Serialize, Deserialize, clickhouse::Row)]
pub struct ThreatIntelHit {
    pub src_ip:    String,
    pub dst_ip:    String,
    pub hits:      u64,
    pub last_seen: u32,
}
pub struct ClickhouseStorage {
    client: Client,
}

fn sql_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\'', "\\'")
}

pub fn default_permissions(role: &str) -> String {
  match role {
    "super_admin" =>
      "dashboard,alerts,logs,live,rules,soar,network-map,intel,settings,health,users,setup",
    "admin" =>
      "dashboard,alerts,logs,live,rules,soar,network-map,intel,settings,health,users,setup",
    "tenant_admin" =>
      "dashboard,alerts,logs,live,rules,soar,network-map,intel,health,users",
    "default_user" =>
      "dashboard,alerts,logs,live,rules,soar,network-map,intel,settings,health,setup",
    "senior_analyst" =>
      "dashboard,alerts,logs,live,rules,soar,network-map,intel,health",
    "analyst" =>
      "dashboard,alerts,logs,live,network-map,intel,health",
    _ => "dashboard,alerts,health",
  }.to_string()
}

fn tenant_db(tenant_id: &str) -> String {
    if tenant_id == "default" {
        "ndr".to_string()
    } else {
        format!("ndr_{}", tenant_id.replace("-", "_"))
    }
}

#[allow(dead_code)]
impl ClickhouseStorage {


// ── User auth ──────────────────────────────────────────────────────────────
// All writes to ndr.users use `SETTINGS mutations_sync=1` so ALTER TABLE UPDATE
// is synchronous. A FINAL read here always reflects the actual current state.
pub async fn verify_user(
    &self,
    username: &str,
    password: &str,
) -> anyhow::Result<Option<serde_json::Value>> {
    let esc = sql_escape(username);

    let rows = self.client
        .query(&format!(
            "SELECT id, username, password_hash, role, tenant_id, permissions, active \
             FROM ndr.users FINAL \
             WHERE username = '{}' \
             LIMIT 1",
            esc
        ))
        .fetch_all::<(String, String, String, String, String, String, u8)>()
        .await?;

    let Some(row) = rows.first() else {
        return Ok(None); // user not found
    };

    // Disabled accounts are blocked before password check.
    // Returns a typed sentinel so the caller shows a specific error message.
    if row.6 != 1 {
        return Ok(Some(json!({ "__disabled__": true })));
    }

    if !bcrypt::verify(password, &row.2).unwrap_or(false) {
        return Ok(None); // wrong password — same response as user-not-found to prevent enumeration
    }

    Ok(Some(json!({
        "id":          row.0,
        "username":    row.1,
        "role":        row.3,
        "tenant_id":   row.4,
        "permissions": row.5,
    })))
}


pub async fn get_users(
    &self
) -> anyhow::Result<Vec<serde_json::Value>> {
    let result = self.client
        .query("SELECT id, username, role, tenant_id, permissions, active, toString(created_at) FROM ndr.users FINAL ORDER BY created_at")
        .fetch_all::<(String,String,String,String,String,u8,String)>()
        .await?;
    Ok(result.iter().map(|r| json!({
        "id": r.0,
        "username": r.1,
        "role": r.2,
        "tenant_id": r.3,
        "permissions": r.4,
        "active": r.5 == 1,
        "created_at": r.6
    })).collect())
}

pub async fn get_users_by_tenant(
    &self,
    tenant_id: &str,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let tenant_id = sql_escape(tenant_id);
    let query = format!(
        "SELECT id, username, role, tenant_id, permissions, active, toString(created_at)
         FROM ndr.users FINAL
         WHERE tenant_id = '{}'
         ORDER BY created_at",
        tenant_id
    );
    let result = self.client
        .query(&query)
        .fetch_all::<(String,String,String,String,String,u8,String)>()
        .await?;
    Ok(result.iter().map(|r| json!({
        "id": r.0,
        "username": r.1,
        "role": r.2,
        "tenant_id": r.3,
        "permissions": r.4,
        "active": r.5 == 1,
        "created_at": r.6
    })).collect())
}

pub async fn get_user_identity(
    &self,
    id: &str,
) -> anyhow::Result<Option<(String, String, String)>> {
    let id = sql_escape(id);
    let query = format!(
        "SELECT username, role, tenant_id
         FROM ndr.users FINAL
         WHERE id = '{}'
         LIMIT 1",
        id
    );
    let result = self.client
        .query(&query)
        .fetch_all::<(String, String, String)>()
        .await?;
    Ok(result.first().cloned())
}

pub async fn get_user_by_id(
    &self,
    id: &str,
) -> anyhow::Result<Option<serde_json::Value>> {
    let id = sql_escape(id);
    let query = format!(
        "SELECT id, username, role, tenant_id, permissions, toString(created_at)
         FROM ndr.users FINAL
         WHERE id = '{}'
         LIMIT 1",
        id
    );
    let result = self.client
        .query(&query)
        .fetch_all::<(String, String, String, String, String, String)>()
        .await?;

    Ok(result.first().map(|r| json!({
        "id": r.0,
        "username": r.1,
        "role": r.2,
        "tenant_id": r.3,
        "permissions": r.4,
        "created_at": r.5
    })))
}

pub async fn get_user_by_username(
    &self,
    username: &str,
) -> anyhow::Result<Option<serde_json::Value>> {
    let username = sql_escape(username);
    let query = format!(
        "SELECT id, username, role, tenant_id, permissions, toString(created_at)
         FROM ndr.users FINAL
         WHERE username = '{}'
         LIMIT 1",
        username
    );
    let result = self.client
        .query(&query)
        .fetch_all::<(String, String, String, String, String, String)>()
        .await?;

    Ok(result.first().map(|r| json!({
        "id": r.0,
        "username": r.1,
        "role": r.2,
        "tenant_id": r.3,
        "permissions": r.4,
        "created_at": r.5
    })))
}

pub async fn create_user(
    &self,
    username: &str,
    password_hash: &str,
    role: &str,
    tenant_id: &str,
    permissions: &str,
) -> anyhow::Result<()> {
    let username = sql_escape(username);
    let password_hash = sql_escape(password_hash);
    let role = sql_escape(role);
    let tenant_id = sql_escape(tenant_id);
    let permissions = sql_escape(permissions);
    let query = format!(
        "INSERT INTO ndr.users \
         (username, password_hash, role, tenant_id, permissions, active) \
         VALUES ('{}','{}','{}','{}','{}',1)",
        username, password_hash, role, tenant_id, permissions
    );
    self.client.query(&query).execute().await?;
    Ok(())
}

pub async fn update_user_permissions(
    &self,
    id: &str,
    permissions: &str,
) -> anyhow::Result<()> {
    let id = sql_escape(id);
    let permissions = sql_escape(permissions);
    // mutations_sync=1: wait until mutation is applied on disk before returning.
    let query = format!(
        "ALTER TABLE ndr.users UPDATE permissions = '{}' WHERE id = '{}' SETTINGS mutations_sync=1",
        permissions, id
    );
    self.client.query(&query).execute().await?;
    Ok(())
}

pub async fn update_user(
    &self,
    id: &str,
    role: &str,
    tenant_id: &str,
    permissions: &str,
    active: bool,
    password_hash: Option<&str>,
) -> anyhow::Result<()> {
    let esc_id          = sql_escape(id);
    let esc_role        = sql_escape(role);
    let esc_tenant_id   = sql_escape(tenant_id);
    let esc_permissions = sql_escape(permissions);
    let active_flag     = if active { 1 } else { 0 };

    // mutations_sync=1: block until the mutation is applied on disk.
    // Without this, ALTER TABLE UPDATE is async — a disabled user could still
    // log in for seconds/minutes until ClickHouse applies the background mutation.
    let query = match password_hash {
        Some(hash) => {
            let esc_hash = sql_escape(hash);
            format!(
                "ALTER TABLE ndr.users \
                 UPDATE role = '{}', tenant_id = '{}', permissions = '{}', \
                 active = {}, password_hash = '{}' \
                 WHERE id = '{}' \
                 SETTINGS mutations_sync=1",
                esc_role, esc_tenant_id, esc_permissions,
                active_flag, esc_hash, esc_id
            )
        }
        None => {
            format!(
                "ALTER TABLE ndr.users \
                 UPDATE role = '{}', tenant_id = '{}', permissions = '{}', active = {} \
                 WHERE id = '{}' \
                 SETTINGS mutations_sync=1",
                esc_role, esc_tenant_id, esc_permissions, active_flag, esc_id
            )
        }
    };

    self.client.query(&query).execute().await?;
    Ok(())
}

pub async fn set_user_active(
    &self,
    id: &str,
    active: bool,
) -> anyhow::Result<()> {
    let id = sql_escape(id);
    // mutations_sync=1: force synchronous mutation so the active flag is
    // immediately enforced on the next query. Without this, ALTER TABLE UPDATE
    // is a background operation — disabled users could still log in for
    // seconds or minutes after being disabled.
    let query = format!(
        "ALTER TABLE ndr.users UPDATE active = {} WHERE id = '{}' SETTINGS mutations_sync=1",
        if active { 1 } else { 0 },
        id
    );
    self.client.query(&query).execute().await?;
    Ok(())
}

pub async fn set_user_password(
    &self,
    id: &str,
    password_hash: &str,
) -> anyhow::Result<()> {
    let id = sql_escape(id);
    let hash = sql_escape(password_hash);
    let query = format!(
        "ALTER TABLE ndr.users UPDATE password_hash = '{}' WHERE id = '{}'",
        hash, id
    );
    self.client.query(&query).execute().await?;
    Ok(())
}

pub async fn delete_user(
    &self, id: &str
) -> anyhow::Result<()> {
    let id = sql_escape(id);
    let query = format!(
        "ALTER TABLE ndr.users DELETE WHERE id = '{}'",
        id
    );
    self.client.query(&query).execute().await?;
    Ok(())
}

pub async fn get_tenants(
    &self
) -> anyhow::Result<Vec<serde_json::Value>> {
    let result = self.client
        .query("SELECT id, name, active FROM ndr.tenants FINAL ORDER BY created_at")
        .fetch_all::<(String,String,u8)>()
        .await?;
    Ok(result.iter().map(|r| json!({
        "id": r.0,
        "name": r.1,
        "active": r.2 == 1
    })).collect())
}

pub async fn create_tenant(
    &self,
    id: &str,
    name: &str,
) -> anyhow::Result<()> {
    let id = sql_escape(id);
    let name = sql_escape(name);
    // 1. Insert into main tenants table
    let query = format!(
        "INSERT INTO ndr.tenants (id, name, active, updated_at) \
         VALUES ('{}','{}',1,now())",
        id, name
    );
    self.client.query(&query).execute().await?;

    // 2. Create dedicated database for tenant
    let db_name = format!("ndr_{}", id.replace("-", "_"));
    self.client.query(&format!(
        "CREATE DATABASE IF NOT EXISTS {}", db_name
    )).execute().await?;

    // 3. Load init.sql and create tables in the tenant DB namespace dynamically
    let install_dir = std::env::var("INSTALL_DIR")
        .unwrap_or_else(|_| ".".to_string());
    let paths = vec![
        "/app/config/clickhouse/init.sql".to_string(),
        format!("{}/config/clickhouse/init.sql", install_dir),
        "./config/clickhouse/init.sql".to_string(),
    ];

    let mut sql_content = None;
    for sql_path in &paths {
        if let Ok(sql) = std::fs::read_to_string(sql_path) {
            sql_content = Some(sql);
            break;
        }
    }

    if let Some(sql) = sql_content {
        for stmt in sql.split(';') {
            let stmt = stmt.trim()
                .lines()
                .filter(|l| !l.trim().starts_with("--"))
                .collect::<Vec<_>>()
                .join("\n")
                .trim()
                .to_string();

            if stmt.is_empty() {
                continue;
            }

            // Skip main tables and other configurations not needed inside individual tenant databases
            if stmt.contains("CREATE DATABASE IF NOT EXISTS ndr") 
                || stmt.contains("ndr.users") 
                || stmt.contains("ndr.tenants") 
                || stmt.contains("ndr.rules_state")
            {
                continue;
            }

            // Replace database namespace with tenant DB and set its default tenant_id
            let mut tenant_stmt = stmt.replace("ndr.", &format!("{}.", db_name));
            tenant_stmt = tenant_stmt.replace("DEFAULT 'default'", &format!("DEFAULT '{}'", id));

            if let Err(e) = self.client
                .query(&tenant_stmt)
                .execute().await {
                tracing::warn!(
                    "Dynamic table creation warning for tenant DB {}: {}. Error: {}", 
                    db_name, tenant_stmt, e
                );
            }
        }
        tracing::info!(
            "✅ Tenant DB created and schema dynamically initialized from init.sql: {}", db_name
        );
    } else {
        tracing::warn!("init.sql not found while provisioning tenant DB {}!", db_name);
    }

    Ok(())
}

pub async fn update_tenant(
    &self,
    id: &str,
    name: &str,
    active: bool,
) -> anyhow::Result<()> {
    let esc_id   = sql_escape(id);
    let esc_name = sql_escape(name);
    // Direct in-place mutation — consistent with set_tenant_active.
    // No read-then-rewrite; eliminates the ReplacingMergeTree FINAL race.
    // updated_at is refreshed so the version column stays current.
    let query = format!(
        "ALTER TABLE ndr.tenants \
         UPDATE name = '{}', active = {}, updated_at = now() \
         WHERE id = '{}'",
        esc_name,
        if active { 1 } else { 0 },
        esc_id
    );
    self.client.query(&query).execute().await?;
    Ok(())
}

pub async fn set_tenant_active(
    &self,
    id: &str,
    active: bool,
) -> anyhow::Result<()> {
    let id = sql_escape(id);
    // ALTER TABLE UPDATE is an atomic, in-place mutation.
    // It does NOT require reading the row first, eliminating the
    // ReplacingMergeTree async-merge race condition entirely.
    // updated_at is also refreshed so the version column stays current.
    let query = format!(
        "ALTER TABLE ndr.tenants UPDATE active = {}, updated_at = now() WHERE id = '{}'",
        if active { 1 } else { 0 },
        id
    );
    self.client.query(&query).execute().await?;
    Ok(())
}
    pub fn new() -> Self {
        let url = std::env::var("CLICKHOUSE_URL")
            .unwrap_or_else(|_| "http://localhost:8123".to_string());
        let user = std::env::var("CLICKHOUSE_USER")
            .unwrap_or_else(|_| "ndr".to_string());
        let password = std::env::var("CLICKHOUSE_PASSWORD")
            .unwrap_or_else(|_| "ndr123".to_string());
        Self {
            client: Client::default()
                .with_url(url)
                .with_user(user)
                .with_password(password)
                .with_database("ndr"),
        }
    }

    pub async fn init_tables(&self) {
    let install_dir = std::env::var("INSTALL_DIR")
        .unwrap_or_else(|_| ".".to_string());
    
    // Try Docker path first, then local path
    let paths = vec![
        "/app/config/clickhouse/init.sql".to_string(),
        format!("{}/config/clickhouse/init.sql", install_dir),
        "./config/clickhouse/init.sql".to_string(),
    ];
    
    for sql_path in &paths {
        if let Ok(sql) = std::fs::read_to_string(sql_path) {
           for stmt in sql.split(';') {
    let stmt = stmt.trim()
        .lines()
        .filter(|l| !l.trim().starts_with("--"))
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string();
    if !stmt.is_empty() {
        if let Err(e) = self.client
            .query(&stmt)
            .execute()
            .await {
            tracing::debug!(
                "SQL init stmt skipped: {}", e
            );
        }
    }
}
            tracing::info!(
                "✅ ClickHouse tables initialized from {}", 
                sql_path
            );
            
            // Ensure tenant_id columns exist
            for alter in &[
                "ALTER TABLE ndr.ndr_events ADD COLUMN IF NOT EXISTS tenant_id String DEFAULT 'default'",
                "ALTER TABLE ndr.ndr_hits ADD COLUMN IF NOT EXISTS tenant_id String DEFAULT 'default'",
                "ALTER TABLE ndr.soar_integrations ADD COLUMN IF NOT EXISTS tenant_id String DEFAULT 'default'",
                "ALTER TABLE ndr.soar_playbooks ADD COLUMN IF NOT EXISTS tenant_id String DEFAULT 'default'",
                "ALTER TABLE ndr.soar_config ADD COLUMN IF NOT EXISTS tenant_id String DEFAULT 'default'",
                "ALTER TABLE ndr.rules_state ADD COLUMN IF NOT EXISTS tenant_id String DEFAULT 'default'",
                "ALTER TABLE ndr.sigma_rules ADD COLUMN IF NOT EXISTS tenant_id String DEFAULT 'default'",
                "ALTER TABLE ndr.users ADD COLUMN IF NOT EXISTS permissions String DEFAULT 'dashboard,alerts'",
                "ALTER TABLE ndr.users ADD COLUMN IF NOT EXISTS active UInt8 DEFAULT 1",
                "ALTER TABLE ndr.tenants ADD COLUMN IF NOT EXISTS updated_at DateTime DEFAULT now()",
            ] {
                if let Err(e) = self.client
                    .query(alter)
                    .execute().await {
                    tracing::debug!("Column add skipped: {}", e);
                }
            }
            tracing::info!("✅ tenant_id columns verified");
            return;
        }
    }
    tracing::warn!("init.sql not found!");
}





    pub async fn get_threat_intel_hits_by_tenant(&self, tenant_id: &str) -> anyhow::Result<Vec<serde_json::Value>> {
    let db_name = tenant_db(tenant_id);
    let query = format!("
        SELECT
            src_ip,
            dst_ip,
            count() as hits,
            max(timestamp) as last_seen
        FROM {}.ndr_hits
        WHERE threat_intel = 1
        GROUP BY src_ip, dst_ip
        ORDER BY hits DESC
        LIMIT 50
    ", db_name);
    let hits = self.client.query(&query)
        .fetch_all::<ThreatIntelHit>()
        .await
        .unwrap_or_default();

    Ok(hits.iter().map(|h| serde_json::json!({
        "src_ip":    h.src_ip,
        "dst_ip":    h.dst_ip,
        "hits":      h.hits,
        "last_seen": h.last_seen,
    })).collect())
}

pub async fn get_threat_intel_hits(&self) -> anyhow::Result<Vec<serde_json::Value>> {
    self.get_threat_intel_hits_by_tenant("default").await
}

    // ── Insert methods ────────────────────────────────────────────────────

    pub async fn insert_event(&self, event: NdrEvent) -> anyhow::Result<()> {
        let mut insert = self.client.insert("ndr_events")?;
        insert.write(&event).await?;
        insert.end().await?;
        Ok(())
    }

    pub async fn insert_event_for_tenant(&self, event: NdrEvent, tenant_id: &str) -> anyhow::Result<()> {
        let db_name = tenant_db(tenant_id);
        let table_name = format!("{}.ndr_events", db_name);
        let mut insert = self.client.insert(&table_name)?;
        insert.write(&event).await?;
        insert.end().await?;
        Ok(())
    }

    pub async fn insert_hit(&self, hit: NdrHit) -> anyhow::Result<()> {
        let mut insert = self.client.insert("ndr_hits")?;
        insert.write(&hit).await?;
        insert.end().await?;
        Ok(())
    }

    pub async fn insert_hit_for_tenant(&self, hit: NdrHit, tenant_id: &str) -> anyhow::Result<()> {
        let db_name = tenant_db(tenant_id);
        let table_name = format!("{}.ndr_hits", db_name);
        let mut insert = self.client.insert(&table_name)?;
        insert.write(&hit).await?;
        insert.end().await?;
        Ok(())
    }

    // ── Query methods ─────────────────────────────────────────────────────

    pub async fn get_stats(&self) -> anyhow::Result<serde_json::Value> {
        let events_total: u64 = self.client
            .query("SELECT count() FROM ndr_events")
            .fetch_one::<u64>()
            .await
            .unwrap_or(0);

        let hits_total: u64 = self.client
            .query("SELECT count() FROM ndr_hits")
            .fetch_one::<u64>()
            .await
            .unwrap_or(0);

        let events_1h: u64 = self.client
            .query("SELECT count() FROM ndr_events WHERE timestamp > now() - INTERVAL 1 HOUR")
            .fetch_one::<u64>()
            .await
            .unwrap_or(0);

        let hits_1h: u64 = self.client
            .query("SELECT count() FROM ndr_hits WHERE timestamp > now() - INTERVAL 1 HOUR")
            .fetch_one::<u64>()
            .await
            .unwrap_or(0);

        let zeek_count: u64 = self.client
            .query("SELECT count() FROM ndr_events WHERE source = 'zeek'")
            .fetch_one::<u64>()
            .await
            .unwrap_or(0);

        let suricata_count: u64 = self.client
            .query("SELECT count() FROM ndr_events WHERE source = 'suricata'")
            .fetch_one::<u64>()
            .await
            .unwrap_or(0);

        Ok(serde_json::json!({
            "events_total":    events_total,
            "hits_total":      hits_total,
            "events_1h":       events_1h,
            "hits_1h":         hits_1h,
            "zeek_events":     zeek_count,
            "suricata_events": suricata_count,
        }))
    }
    
    pub async fn set_rule_enabled(&self, id: &str, enabled: bool, tenant_id: &str) -> anyhow::Result<()> {
        self.client.query("INSERT INTO ndr.rules_state (id, enabled, tenant_id, updated) VALUES (?, ?, ?, now())")
            .bind(id)
            .bind(enabled as u8)
            .bind(tenant_id)
            .execute().await?;
        Ok(())
    }

    pub async fn get_disabled_rules(&self, tenant_id: &str) -> anyhow::Result<Vec<String>> {
        let ids = self.client
            .query(
                "SELECT id FROM ndr.rules_state
                 FINAL
                 WHERE enabled = 0 AND tenant_id = ?"
            )
            .bind(tenant_id)
            .fetch_all::<String>()
            .await
            .unwrap_or_default();
        Ok(ids)
    }

    pub async fn delete_rule_state(&self, id: &str, tenant_id: &str) -> anyhow::Result<()> {
        self.client
            .query("ALTER TABLE ndr.rules_state DELETE WHERE id = ? AND tenant_id = ?")
            .bind(id)
            .bind(tenant_id)
            .execute()
            .await?;
        Ok(())
    }
    pub async fn get_sigma_rules(&self, tenant_id: &str) -> anyhow::Result<Vec<(String, String)>> {
        let db = tenant_db(tenant_id);
        let result = self.client
            .query(&format!("SELECT id, content FROM {}.sigma_rules FINAL WHERE enabled = 1", db))
            .fetch_all::<(String, String)>()
            .await?;
        Ok(result)
    }

    pub async fn get_all_enabled_sigma_rules(&self) -> anyhow::Result<Vec<(String, String)>> {
        let result = self.client
            .query("SELECT id, content FROM ndr.sigma_rules FINAL WHERE enabled = 1")
            .fetch_all::<(String, String)>()
            .await?;
        Ok(result)
    }

    pub async fn save_sigma_rule(&self, id: &str, name: &str, content: &str, tenant_id: &str) -> anyhow::Result<()> {
        let db = tenant_db(tenant_id);
        self.client
            .query(&format!("INSERT INTO {}.sigma_rules (id, name, content, tenant_id, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, 1, now(), now())", db))
            .bind(id)
            .bind(name)
            .bind(content)
            .bind(tenant_id)
            .execute()
            .await?;
        Ok(())
    }

    pub async fn delete_sigma_rule(&self, id: &str, tenant_id: &str) -> anyhow::Result<()> {
        let db = tenant_db(tenant_id);
        self.client
            .query(&format!("ALTER TABLE {}.sigma_rules DELETE WHERE id = ?", db))
            .bind(id)
            .execute()
            .await?;
        Ok(())
    }

    pub async fn toggle_sigma_rule(&self, id: &str, enabled: bool, tenant_id: &str) -> anyhow::Result<()> {
        let db = tenant_db(tenant_id);
        let query = format!("INSERT INTO {}.sigma_rules (id, name, content, tenant_id, enabled, updated_at) SELECT id, name, content, tenant_id, ?, now() FROM {}.sigma_rules FINAL WHERE id = ?", db, db);
        self.client.query(&query).bind(enabled as u8).bind(id).execute().await?;
        Ok(())
    }

    pub async fn get_sigma_rule_by_id(&self, id: &str, tenant_id: &str) -> anyhow::Result<Option<(String, String, String, String, u8)>> {
        let db = tenant_db(tenant_id);
        let result = self.client
            .query(&format!("SELECT id, name, content, tenant_id, enabled FROM {}.sigma_rules FINAL WHERE id = ? LIMIT 1", db))
            .bind(id)
            .fetch_all::<(String, String, String, String, u8)>()
            .await?;
        Ok(result.first().cloned())
    }

    pub async fn get_all_sigma_rules(&self, tenant_id: &str) -> anyhow::Result<Vec<(String, String, String, String, u8)>> {
        let db = tenant_db(tenant_id);
        let result = self.client
            .query(&format!("SELECT id, name, content, tenant_id, enabled FROM {}.sigma_rules FINAL", db))
            .fetch_all::<(String, String, String, String, u8)>()
            .await?;
        Ok(result)
    }

//soar integrations

pub async fn get_integrations_by_tenant(
    &self, tenant_id: &str
) -> anyhow::Result<Vec<serde_json::Value>> {
    let db = tenant_db(tenant_id);
    let query = format!("
        SELECT id, name, type, config, enabled
        FROM {}.soar_integrations
        FINAL
        ORDER BY created_at
    ", db);
    let result = self.client
        .query(&query)
        .fetch_all::<(String,String,String,String,u8)>()
        .await?;
    Ok(result.iter().map(|r| {
        let config: serde_json::Value =
            serde_json::from_str(&r.3)
                .unwrap_or(serde_json::json!({}));
        serde_json::json!({
            "id":      r.0,
            "name":    r.1,
            "type":    r.2,
            "config":  config,
            "enabled": r.4 == 1
        })
    }).collect())
}

pub async fn get_integrations(&self) -> anyhow::Result<Vec<serde_json::Value>> {
    self.get_integrations_by_tenant("default").await
}

pub async fn save_integration(
    &self,
    id: &str,
    name: &str,
    int_type: &str,
    config: &str,
    tenant_id: &str,
) -> anyhow::Result<()> {
    let db = tenant_db(tenant_id);
    let query = format!(
        "INSERT INTO {}.soar_integrations \
         (id, name, type, config, enabled, tenant_id) \
         VALUES ('{}','{}','{}','{}',1,'{}')",
        db, id, name, int_type,
        config.replace("'", "\\'"), tenant_id
    );
    self.client.query(&query).execute().await?;
    Ok(())
}

pub async fn toggle_integration(
    &self, id: &str, enabled: bool, tenant_id: &str
) -> anyhow::Result<()> {
    let db = tenant_db(tenant_id);
    let query = format!(
        "INSERT INTO {}.soar_integrations \
         (id, name, type, config, enabled, tenant_id) \
         SELECT id, name, type, config, {}, tenant_id \
         FROM {}.soar_integrations \
         WHERE id = '{}'",
        db, if enabled { 1 } else { 0 }, db, id
    );
    self.client.query(&query).execute().await?;
    Ok(())
}

pub async fn delete_integration(
    &self, id: &str, tenant_id: &str
) -> anyhow::Result<()> {
    let db = tenant_db(tenant_id);
    let query = format!(
        "ALTER TABLE {}.soar_integrations \
         DELETE WHERE id = '{}'",
        db, id
    );
    self.client.query(&query).execute().await?;
    Ok(())
}


//save soar config
pub async fn save_soar_config_by_tenant(
    &self, key: &str, value: &str, tenant_id: &str
) -> anyhow::Result<()> {
    let db = tenant_db(tenant_id);
    let query = format!(
        "INSERT INTO {}.soar_config (key, value, tenant_id) \
         VALUES ('{}', '{}', '{}')",
        db, key, value, tenant_id
    );
    self.client.query(&query).execute().await?;
    Ok(())
}

pub async fn save_soar_config(&self, key: &str, value: &str) -> anyhow::Result<()> {
    self.save_soar_config_by_tenant(key, value, "default").await
}


//get soar config
pub async fn get_soar_config_by_tenant(
    &self, tenant_id: &str
) -> anyhow::Result<serde_json::Value> {
    let db = tenant_db(tenant_id);
    let query = format!("
        SELECT key, value
        FROM {}.soar_config
        FINAL
        ORDER BY key
    ", db);
    let result = self.client
        .query(&query)
        .fetch_all::<(String, String)>()
        .await?;
    let mut map = serde_json::Map::new();
    for (key, val) in result {
        map.insert(key, serde_json::json!(val));
    }
    Ok(serde_json::Value::Object(map))
}

pub async fn get_soar_config(&self) -> anyhow::Result<serde_json::Value> {
    self.get_soar_config_by_tenant("default").await
}


//soar playbooks
pub async fn get_soar_playbooks_by_tenant(
    &self, tenant_id: &str
) -> anyhow::Result<Vec<serde_json::Value>> {
    let db = tenant_db(tenant_id);
    let query = format!("
        SELECT id, name, description,
               trigger, action_type,
               config, enabled, runs
        FROM {}.soar_playbooks
        FINAL
        ORDER BY created_at
    ", db);
    let result = self.client
        .query(&query)
        .fetch_all::<(
            String, String, String,
            String, String, String,
            u8, u64
        )>()
        .await?;
    Ok(result.iter().map(|r| serde_json::json!({
        "id":          r.0,
        "name":        r.1,
        "description": r.2,
        "trigger":     r.3,
        "action_type": r.4,
        "config":      r.5,
        "enabled":     r.6 == 1,
        "runs":        r.7
    })).collect())
}

pub async fn get_soar_playbooks(&self) -> anyhow::Result<Vec<serde_json::Value>> {
    self.get_soar_playbooks_by_tenant("default").await
}

//enable/disable playbook
pub async fn update_playbook_enabled(
    &self, id: &str, enabled: bool, tenant_id: &str
) -> anyhow::Result<()> {
    let db = tenant_db(tenant_id);
    let query = format!(
        "INSERT INTO {}.soar_playbooks \
         (id, name, description, trigger, \
          action_type, enabled, tenant_id) \
         SELECT id, name, description, trigger, \
                action_type, {}, tenant_id \
         FROM {}.soar_playbooks \
         WHERE id = '{}'",
        db, if enabled { 1 } else { 0 }, db, id
    );
    self.client.query(&query).execute().await?;
    Ok(())
}

pub async fn create_playbook(
    &self,
    id: &str,
    name: &str,
    description: &str,
    trigger: &str,
    action_type: &str,
    config: &str,
    tenant_id: &str,
) -> anyhow::Result<()> {
    let db = tenant_db(tenant_id);
    let query = format!(
        "INSERT INTO {}.soar_playbooks \
         (id, name, description, trigger, \
          action_type, config, enabled, tenant_id) \
         VALUES ('{}','{}','{}','{}','{}','{}',1,'{}')",
        db, id, name, description,
        trigger, action_type, config, tenant_id
    );
    self.client.query(&query).execute().await?;
    Ok(())
}


//get settings

pub async fn get_settings_by_tenant(&self, tenant_id: &str) -> anyhow::Result<serde_json::Value> {
    let db = tenant_db(tenant_id);
    let query = format!("
        SELECT key, value
        FROM {}.settings
        FINAL
        ORDER BY key
    ", db);
    let result = self.client
        .query(&query)
        .fetch_all::<(String, String)>()
        .await?;
    let mut map = serde_json::Map::new();
    for (key, val) in result {
        if let Ok(n) = val.parse::<f64>() {
            map.insert(key, serde_json::json!(n));
        }
    }
    Ok(serde_json::Value::Object(map))
}

pub async fn get_settings(&self) -> anyhow::Result<serde_json::Value> {
    self.get_settings_by_tenant("default").await
}

pub async fn save_setting_by_tenant(
    &self, key: &str, value: &str, tenant_id: &str
) -> anyhow::Result<()> {
    let db = tenant_db(tenant_id);
    let query = format!(
        "INSERT INTO {}.settings (key, value) \
         VALUES ('{}', '{}')",
        db, key, value
    );
    self.client.query(&query).execute().await?;
    Ok(())
}

pub async fn save_setting(
    &self, key: &str, value: &str
) -> anyhow::Result<()> {
    self.save_setting_by_tenant(key, value, "default").await
}


    //recent hits
    pub async fn get_recent_hits(&self, limit: u64) -> anyhow::Result<Vec<RecentHit>> {
    let hits = self.client
        .query("SELECT timestamp, community_id, src_ip, dst_ip, score, severity, threat_intel, src_country, dst_country FROM ndr_hits ORDER BY timestamp DESC LIMIT ?")
        .bind(limit)
        .fetch_all::<RecentHit>()
        .await
        .unwrap_or_default();
    Ok(hits)
    }
    
    pub async fn get_recent_events(&self, limit: u64) -> anyhow::Result<Vec<RecentEvent>> {
        let events = self.client
            .query("SELECT timestamp, source, src_ip, dst_ip, proto, event_type, community_id FROM ndr_events ORDER BY timestamp DESC LIMIT ?")
            .bind(limit)
            .fetch_all::<RecentEvent>()
            .await
            .unwrap_or_default();
        Ok(events)
    }

    //top src ips
    pub async fn get_top_src_ips(&self, limit: u64) -> anyhow::Result<Vec<TopIp>> {
        let ips = self.client
            .query("SELECT src_ip as ip, count() as count FROM ndr_events WHERE src_ip != '' GROUP BY src_ip ORDER BY count DESC LIMIT ?")
            .bind(limit)
            .fetch_all::<TopIp>()
            .await
            .unwrap_or_default();
        Ok(ips)
    }

    //top dst ips
    pub async fn get_top_dst_ips(&self, limit: u64) -> anyhow::Result<Vec<TopIp>> {
        let ips = self.client
            .query("SELECT dst_ip as ip, count() as count FROM ndr_events WHERE dst_ip != '' GROUP BY dst_ip ORDER BY count DESC LIMIT ?")
            .bind(limit)
            .fetch_all::<TopIp>()
            .await
            .unwrap_or_default();
        Ok(ips)
    }

//network map
pub async fn get_network_map(&self) -> anyhow::Result<serde_json::Value> {
    // Get top communication pairs
    let pairs = self.client
        .query("
            SELECT 
                src_ip,
                dst_ip,
                count() as connections,
                groupArray(DISTINCT proto) as protocols
            FROM ndr_events 
            WHERE src_ip != '' 
              AND dst_ip != ''
              AND timestamp > now() - INTERVAL 1 HOUR
            GROUP BY src_ip, dst_ip
            ORDER BY connections DESC
            LIMIT 100
        ")
        .fetch_all::<NetworkPair>()
        .await
        .unwrap_or_default();

    // Build nodes and edges for graph
    let mut nodes: std::collections::HashMap<String, serde_json::Value> = 
        std::collections::HashMap::new();
    let mut edges: Vec<serde_json::Value> = Vec::new();

    for pair in &pairs {
        // Add source node
        nodes.entry(pair.src_ip.clone()).or_insert(json!({
            "id":    pair.src_ip,
            "label": pair.src_ip,
            "type":  if pair.src_ip.starts_with("10.") || 
                        pair.src_ip.starts_with("192.168.") || 
                        pair.src_ip.starts_with("172.") 
                     { "internal" } else { "external" }
        }));

        // Add destination node
        nodes.entry(pair.dst_ip.clone()).or_insert(json!({
            "id":    pair.dst_ip,
            "label": pair.dst_ip,
            "type":  if pair.dst_ip.starts_with("10.") || 
                        pair.dst_ip.starts_with("192.168.") || 
                        pair.dst_ip.starts_with("172.") 
                     { "internal" } else { "external" }
        }));

        // Add edge
        edges.push(json!({
            "source":      pair.src_ip,
            "target":      pair.dst_ip,
            "connections": pair.connections,
            "protocols":   pair.protocols,
            "weight":      pair.connections,
        }));
    }

    Ok(json!({
        "nodes": nodes.values().collect::<Vec<_>>(),
        "edges": edges,
        "total_nodes": nodes.len(),
        "total_edges": edges.len(),
    }))
}


    //severity breakdown
    pub async fn get_severity_breakdown(&self) -> anyhow::Result<serde_json::Value> {
        let critical: u64 = self.client
            .query("SELECT count() FROM ndr_hits WHERE lower(severity) = 'critical'")
            .fetch_one::<u64>().await.unwrap_or(0);
        let high: u64 = self.client
            .query("SELECT count() FROM ndr_hits WHERE lower(severity) = 'high'")
            .fetch_one::<u64>().await.unwrap_or(0);
        let medium: u64 = self.client
            .query("SELECT count() FROM ndr_hits WHERE lower(severity) = 'medium'")
            .fetch_one::<u64>().await.unwrap_or(0);
        let low: u64 = self.client
            .query("SELECT count() FROM ndr_hits WHERE lower(severity) = 'low'")
            .fetch_one::<u64>().await.unwrap_or(0);

        Ok(serde_json::json!({
            "critical": critical,
            "high":     high,
            "medium":   medium,
            "low":      low,
        }))
    }

    pub async fn get_stats_by_tenant(
        &self, tenant_id: &str
    ) -> anyhow::Result<serde_json::Value> {
        let db_name = tenant_db(tenant_id);
        let et: u64 = self.client.query(&format!(
            "SELECT count() FROM {}.ndr_events", db_name))
            .fetch_one::<u64>().await.unwrap_or(0);
        let ht: u64 = self.client.query(&format!(
            "SELECT count() FROM {}.ndr_hits", db_name))
            .fetch_one::<u64>().await.unwrap_or(0);
        let e1h: u64 = self.client.query(&format!(
            "SELECT count() FROM {}.ndr_events WHERE timestamp > now() - INTERVAL 1 HOUR", db_name))
            .fetch_one::<u64>().await.unwrap_or(0);
        let h1h: u64 = self.client.query(&format!(
            "SELECT count() FROM {}.ndr_hits WHERE timestamp > now() - INTERVAL 1 HOUR", db_name))
            .fetch_one::<u64>().await.unwrap_or(0);
        let zeek: u64 = self.client.query(&format!(
            "SELECT count() FROM {}.ndr_events WHERE source='zeek'", db_name))
            .fetch_one::<u64>().await.unwrap_or(0);
        let suri: u64 = self.client.query(&format!(
            "SELECT count() FROM {}.ndr_events WHERE source='suricata'", db_name))
            .fetch_one::<u64>().await.unwrap_or(0);
        Ok(serde_json::json!({
            "events_total": et, "hits_total": ht,
            "events_1h": e1h, "hits_1h": h1h,
            "zeek_events": zeek, "suricata_events": suri
        }))
    }

    pub async fn get_recent_events_by_tenant(
        &self, limit: u64, tenant_id: &str
    ) -> anyhow::Result<Vec<serde_json::Value>> {
        let db_name = tenant_db(tenant_id);
        let rows = self.client.query(&format!(
            "SELECT src_ip, dst_ip, proto, source, event_type, toUInt32(timestamp) \
             FROM {}.ndr_events \
             ORDER BY timestamp DESC LIMIT {}", db_name, limit))
            .fetch_all::<(String, String, String, String, String, u32)>()
            .await.unwrap_or_default();
        Ok(rows.iter().map(|r| serde_json::json!({
            "src_ip":     r.0,
            "dst_ip":     r.1,
            "proto":      r.2,
            "source":     r.3,
            "event_type": r.4,
            "timestamp":  r.5
        })).collect())
    }

    pub async fn get_top_src_ips_by_tenant(
        &self, limit: u64, tenant_id: &str
    ) -> anyhow::Result<Vec<serde_json::Value>> {
        let db_name = tenant_db(tenant_id);
        let rows = self.client.query(&format!(
            "SELECT src_ip, count() as cnt \
             FROM {}.ndr_events \
             GROUP BY src_ip ORDER BY cnt DESC LIMIT {}", db_name, limit))
            .fetch_all::<(String,u64)>()
            .await.unwrap_or_default();
        Ok(rows.iter().map(|r| serde_json::json!({
            "ip":r.0,"count":r.1
        })).collect())
    }

    pub async fn get_top_dst_ips_by_tenant(
        &self, limit: u64, tenant_id: &str
    ) -> anyhow::Result<Vec<serde_json::Value>> {
        let db_name = tenant_db(tenant_id);
        let rows = self.client.query(&format!(
            "SELECT dst_ip, count() as cnt \
             FROM {}.ndr_events \
             GROUP BY dst_ip ORDER BY cnt DESC LIMIT {}", db_name, limit))
            .fetch_all::<(String,u64)>()
            .await.unwrap_or_default();
        Ok(rows.iter().map(|r| serde_json::json!({
            "ip":r.0,"count":r.1
        })).collect())
    }

    pub async fn get_recent_hits_by_tenant(
        &self, limit: u64, tenant_id: &str
    ) -> anyhow::Result<Vec<serde_json::Value>> {
        let db_name = tenant_db(tenant_id);
        let rows = self.client.query(&format!(
            "SELECT src_ip,dst_ip,score,severity,toString(timestamp) \
             FROM {}.ndr_hits \
             ORDER BY timestamp DESC LIMIT {}", db_name, limit))
            .fetch_all::<(String,String,f32,String,String)>()
            .await.unwrap_or_default();
        Ok(rows.iter().map(|r| serde_json::json!({
            "src_ip":r.0,"dst_ip":r.1,"score":r.2,
            "severity":r.3,"timestamp":r.4
        })).collect())
    }

    pub async fn get_severity_by_tenant(
        &self, tenant_id: &str
    ) -> anyhow::Result<serde_json::Value> {
        let db_name = tenant_db(tenant_id);
        let critical: u64 = self.client.query(&format!(
            "SELECT count() FROM {}.ndr_hits WHERE severity='CRITICAL' OR severity='critical'", db_name))
            .fetch_one::<u64>().await.unwrap_or(0);
        let high: u64 = self.client.query(&format!(
            "SELECT count() FROM {}.ndr_hits WHERE severity='HIGH' OR severity='high'", db_name))
            .fetch_one::<u64>().await.unwrap_or(0);
        let medium: u64 = self.client.query(&format!(
            "SELECT count() FROM {}.ndr_hits WHERE severity='MEDIUM' OR severity='medium'", db_name))
            .fetch_one::<u64>().await.unwrap_or(0);
        let low: u64 = self.client.query(&format!(
            "SELECT count() FROM {}.ndr_hits WHERE severity='LOW' OR severity='low'", db_name))
            .fetch_one::<u64>().await.unwrap_or(0);
        Ok(serde_json::json!({
            "critical":critical,"high":high,
            "medium":medium,"low":low
        }))
    }

    pub async fn get_network_map_by_tenant(
        &self, tenant_id: &str
    ) -> anyhow::Result<serde_json::Value> {
        let db_name = tenant_db(tenant_id);
        let recent_query = format!("
            SELECT src_ip, dst_ip,
                count() as connections,
                groupArray(DISTINCT proto) as protocols
            FROM {}.ndr_events 
            WHERE src_ip != '' AND dst_ip != ''
              AND timestamp > now() - INTERVAL 1 HOUR
            GROUP BY src_ip, dst_ip
            ORDER BY connections DESC
            LIMIT 100", db_name);
        let fallback_query = format!("
            SELECT src_ip, dst_ip,
                count() as connections,
                groupArray(DISTINCT proto) as protocols
            FROM {}.ndr_events
            WHERE src_ip != '' AND dst_ip != ''
            GROUP BY src_ip, dst_ip
            ORDER BY connections DESC
            LIMIT 100", db_name);

        let mut pairs = self.client.query(&recent_query)
            .fetch_all::<NetworkPair>()
            .await.unwrap_or_default();
        if pairs.is_empty() {
            pairs = self.client.query(&fallback_query)
                .fetch_all::<NetworkPair>()
                .await.unwrap_or_default();
        }
        let mut nodes: std::collections::HashMap<String, serde_json::Value> = 
            std::collections::HashMap::new();
        let mut edges: Vec<serde_json::Value> = Vec::new();
        for pair in &pairs {
            nodes.entry(pair.src_ip.clone()).or_insert(serde_json::json!({
                "id": pair.src_ip, "label": pair.src_ip,
                "type": if pair.src_ip.starts_with("10.") || 
                    pair.src_ip.starts_with("192.168.") ||
                    pair.src_ip.starts_with("172.")
                    { "internal" } else { "external" }
            }));
            nodes.entry(pair.dst_ip.clone()).or_insert(serde_json::json!({
                "id": pair.dst_ip, "label": pair.dst_ip,
                "type": if pair.dst_ip.starts_with("10.") ||
                    pair.dst_ip.starts_with("192.168.") ||
                    pair.dst_ip.starts_with("172.")
                    { "internal" } else { "external" }
            }));
            edges.push(serde_json::json!({
                "source": pair.src_ip, "target": pair.dst_ip,
                "connections": pair.connections,
                "protocols": pair.protocols
            }));
        }
        let total_nodes = nodes.len();
        let total_edges = edges.len();
        Ok(serde_json::json!({
            "nodes": nodes.values().collect::<Vec<_>>(),
            "edges": edges,
            "total_nodes": total_nodes,
            "total_edges": total_edges
        }))
    }

pub async fn create_sensor_key(
    &self,
    tenant_id: &str,
    name: &str,
    key_hash: &str,
    key_prefix: &str,
) -> anyhow::Result<String> {
    let id = uuid::Uuid::new_v4().to_string();
    let query = format!(
        "INSERT INTO ndr.sensor_keys \
         (id, key_hash, key_prefix, tenant_id, name) \
         VALUES ('{}','{}','{}','{}','{}')",
        id, key_hash, key_prefix, tenant_id, name
    );
    self.client.query(&query).execute().await?;
    Ok(id)
}

pub async fn validate_sensor_key(
    &self,
    key: &str,
) -> anyhow::Result<Option<String>> {
    // Extract prefix (first 16 chars)
    if key.len() < 16 { return Ok(None); }
    let prefix = &key[..16];
    
    let result = self.client
        .query(&format!(
            "SELECT key_hash, tenant_id, active \
             FROM ndr.sensor_keys FINAL \
             WHERE key_prefix = '{}' \
             AND active = 1 \
             LIMIT 1", prefix
        ))
        .fetch_all::<(String, String, u8)>()
        .await?;
    
    if let Some((hash, tenant_id, _)) = result.first() {
        if bcrypt::verify(key, hash).unwrap_or(false) {
            // Update last_seen
            let _ = self.client
                .query(&format!(
                    "ALTER TABLE ndr.sensor_keys \
                     UPDATE last_seen = now() \
                     WHERE key_prefix = '{}'",
                    prefix
                ))
                .execute().await;
            return Ok(Some(tenant_id.clone()));
        }
    }
    Ok(None)
}

pub async fn get_sensor_keys(
    &self,
    tenant_id: &str,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let filter = if tenant_id == "default" {
        "1=1".to_string()
    } else {
        format!("tenant_id='{}'", tenant_id)
    };
    
    let result = self.client
        .query(&format!(
            "SELECT id, key_prefix, tenant_id, \
                    name, active, toString(created_at), \
                    toString(last_seen) \
             FROM ndr.sensor_keys FINAL \
             WHERE {} \
             ORDER BY created_at DESC", filter
        ))
        .fetch_all::<(String,String,String,String,u8,String,String)>()
        .await?;
    
    Ok(result.iter().map(|r| serde_json::json!({
        "id": r.0,
        "key_prefix": r.1,
        "tenant_id": r.2,
        "name": r.3,
        "active": r.4 == 1,
        "created_at": r.5,
        "last_seen": r.6
    })).collect())
}

pub async fn revoke_sensor_key(
    &self,
    id: &str,
) -> anyhow::Result<()> {
    self.client
        .query(&format!(
            "ALTER TABLE ndr.sensor_keys \
             UPDATE active = 0 \
             WHERE id = '{}'", id
        ))
        .execute().await?;
    Ok(())
}

pub async fn set_sensor_command(
    &self,
    tenant_id: &str,
    command: &str,
) -> anyhow::Result<()> {
    let id = uuid::Uuid::new_v4().to_string();
    let query = format!(
        "INSERT INTO ndr.sensor_commands \
         (id, tenant_id, command, status) \
         VALUES ('{}', '{}', '{}', 'pending')",
        id, tenant_id, command
    );
    self.client.query(&query).execute().await?;
    Ok(())
}

pub async fn get_sensor_command(
    &self,
    tenant_id: &str,
) -> anyhow::Result<String> {
    let result = self.client
        .query(&format!(
            "SELECT command, status FROM ndr.sensor_commands FINAL \
             WHERE tenant_id = '{}' \
             AND status = 'pending' \
             ORDER BY created_at DESC \
             LIMIT 1",
            tenant_id
        ))
        .fetch_all::<(String, String)>()
        .await?;
    
    Ok(result.first()
        .map(|r| r.0.clone())
        .unwrap_or_default())
}

pub async fn clear_sensor_command(
    &self,
    tenant_id: &str,
) -> anyhow::Result<()> {
    self.client
        .query(&format!(
            "ALTER TABLE ndr.sensor_commands \
             UPDATE status = 'done' \
             WHERE tenant_id = '{}' \
             AND status = 'pending'",
            tenant_id
        ))
        .execute().await?;
    Ok(())
}

}
