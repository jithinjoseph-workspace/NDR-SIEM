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
#[allow(dead_code)]
pub struct RecentHitDetail {
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
}

#[derive(Debug, Serialize, Deserialize, clickhouse::Row)]
pub struct ThreatIntelHit {
    pub src_ip:    String,
    pub dst_ip:    String,
    pub hits:      u64,
    pub last_seen: u32,
}

#[derive(Debug, Serialize, Deserialize, clickhouse::Row)]
pub struct PcapSessionRow {
    pub session_id:   String,
    pub community_id: String,
    pub src_ip:       String,
    pub dst_ip:       String,
    pub src_port:     u16,
    pub dst_port:     u16,
    pub proto:        String,
    pub start_time:   String,
    pub end_time:     String,
    pub bytes:        u64,
    pub packets:      u64,
    pub arkime_url:   String,
    pub sensor_host:  String,
    pub file_path:    String,
}

#[derive(Debug, Serialize, Deserialize, clickhouse::Row)]
pub struct SensorKeyRow {
    pub id: String,
    pub key_prefix: String,
    pub tenant_id: String,
    pub name: String,
    pub hostname: String,
    pub interface_name: String,
    pub os_name: String,
    pub zeek_status: String,
    pub suricata_status: String,
    pub vector_status: String,
    pub arkime_status: String,
    pub arkime_url: String,
    pub arkime_pass: String,
    pub active: u8,
    pub created_at: String,
    pub last_seen: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, clickhouse::Row)]
pub struct AssetRow {
    pub ip: String,
    pub mac: String,
    pub hostname: String,
    pub vendor: String,
    pub os_guess: String,
    pub device_type: String,
    pub custom_name: String,
    pub tenant_id: String,
    pub first_seen: u32,
    pub last_seen: u32,
    pub ip_history: String,
}

#[derive(Debug, Serialize, Deserialize, clickhouse::Row)]
pub struct AnnouncementRow {
    pub id: String,
    pub title: String,
    pub message: String,
    pub announcement_type: String,
    pub audience: String,
    pub status: String,
    pub target_roles: Vec<String>,
    pub target_tenants: Vec<String>,
    pub starts_at: String,
    pub ends_at: String,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize, Deserialize, clickhouse::Row)]
pub struct AnnouncementReadRow {
    pub announcement_id: String,
}

#[derive(clickhouse::Row, serde::Deserialize)]
pub struct SupportMessageRow {
    pub id: String,
    pub tenant_id: String,
    pub sender_username: String,
    pub sender_role: String,
    pub subject: String,
    pub category: String,
    pub message: String,
    pub status: String,
    pub admin_reply: String,
    pub replied_by: String,
    pub forwarded: u8,
    pub forwarded_by: String,
    pub deleted: u8,
    pub created_at: String,
    pub updated_at: String,
    pub replied_at: String,
    pub forwarded_at: String,
}

fn support_message_to_json(row: SupportMessageRow) -> serde_json::Value {
    json!({
        "id": row.id,
        "tenant_id": row.tenant_id,
        "sender_username": row.sender_username,
        "sender_role": row.sender_role,
        "subject": row.subject,
        "category": row.category,
        "message": row.message,
        "status": row.status,
        "admin_reply": row.admin_reply,
        "replied_by": row.replied_by,
        "forwarded": row.forwarded,
        "forwarded_by": row.forwarded_by,
        "deleted": row.deleted,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
        "replied_at": row.replied_at,
        "forwarded_at": row.forwarded_at,
    })
}

pub struct ClickhouseStorage {
    pub(crate) client: Client,
}

pub(crate) fn sql_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\'', "\\'")
}

fn sql_array_literal(values: &[String]) -> String {
    if values.is_empty() {
        return "CAST([], 'Array(String)')".to_string();
    }

    let items = values
        .iter()
        .map(|value| format!("'{}'", sql_escape(value)))
        .collect::<Vec<_>>()
        .join(",");
    format!("[{}]", items)
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

pub fn tenant_db_pub(tenant_id: &str) -> String {
    tenant_db(tenant_id)
}

fn get_base_domain(domain: &str) -> String {
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() <= 2 {
        return domain.to_string();
    }
    let second_to_last = parts[parts.len() - 2];
    let short_tlds = ["co", "com", "org", "net", "gov", "ac", "edu"];
    if second_to_last.len() <= 3 && short_tlds.contains(&second_to_last) {
        if parts.len() >= 3 {
            return format!("{}.{}.{}", parts[parts.len()-3], parts[parts.len()-2], parts[parts.len()-1]);
        }
    }
    format!("{}.{}", parts[parts.len()-2], parts[parts.len()-1])
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

/// Check whether a specific user account is enabled.
/// Returns `true` (allow) if the user is not found (fail-open for unknown users;
/// the JWT would already be invalid in that case).
/// Returns `false` only when the row exists AND `active = 0`.
pub async fn is_user_active(
    &self,
    username: &str,
) -> anyhow::Result<bool> {
    let esc = sql_escape(username);
    let rows = self.client
        .query(&format!(
            "SELECT active FROM ndr.users FINAL \
             WHERE username = '{}' LIMIT 1",
            esc
        ))
        .fetch_all::<u8>()
        .await?;

    // No row → user not in DB; JWT verification already failed earlier, so allow
    Ok(rows.first().map(|active| *active == 1).unwrap_or(true))
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

pub async fn get_all_tenants(
    &self,
) -> anyhow::Result<Vec<String>> {
    let result = self.client
        .query("SELECT id FROM ndr.tenants FINAL WHERE active = 1")
        .fetch_all::<String>()
        .await?;
    Ok(result)
}

pub async fn is_tenant_active(
    &self,
    id: &str,
) -> anyhow::Result<bool> {
    let id = sql_escape(id);
    let rows = self.client
        .query(&format!(
            "SELECT active FROM ndr.tenants FINAL WHERE id = '{}' LIMIT 1",
            id
        ))
        .fetch_all::<u8>()
        .await?;

    Ok(rows.first().map(|active| *active == 1).unwrap_or(true))
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

    // 2. Create dedicated database for tenant on all cluster nodes
    let db_name = format!("ndr_{}", id.replace("-", "_"));
    self.client.query(&format!(
        "CREATE DATABASE IF NOT EXISTS {} ON CLUSTER ndr_cluster", db_name
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

            // Skip global-only tables not needed inside individual tenant databases
            if stmt.contains("CREATE DATABASE IF NOT EXISTS ndr")
                || stmt.contains("ndr.users")
                || stmt.contains("ndr.tenants")
                || stmt.contains("ndr.announcements")
                || stmt.contains("ndr.announcement_reads")
                || stmt.contains("ndr.rules_state")
                || stmt.contains("ndr.shared_iocs")
            {
                continue;
            }

            // Replace database namespace with tenant DB and set its default tenant_id
            let mut tenant_stmt = stmt.replace("ndr.", &format!("{}.", db_name));
            // Fix ZooKeeper path: /clickhouse/tables/{shard}/ndr/ → /clickhouse/tables/{shard}/<tenant_db>/
            // The dot-replace above only fixes the SQL table prefix, not the ZooKeeper path inside ENGINE=
            tenant_stmt = tenant_stmt.replace(
                "/clickhouse/tables/{shard}/ndr/",
                &format!("/clickhouse/tables/{{shard}}/{}/", db_name),
            );
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

pub async fn create_announcement(
    &self,
    id: &str,
    title: &str,
    message: &str,
    announcement_type: &str,
    audience: &str,
    status: &str,
    target_roles: &[String],
    target_tenants: &[String],
    start_at: Option<&str>,
    end_at: Option<&str>,
    created_by: &str,
) -> anyhow::Result<()> {
    let start_expr = start_at
        .filter(|value| !value.trim().is_empty())
        .map(|value| format!("parseDateTimeBestEffort('{}')", sql_escape(value)))
        .unwrap_or_else(|| "now()".to_string());
    let end_expr = end_at
        .filter(|value| !value.trim().is_empty())
        .map(|value| format!("parseDateTimeBestEffort('{}')", sql_escape(value)))
        .unwrap_or_else(|| "CAST(NULL, 'Nullable(DateTime)')".to_string());
    let query = format!(
        "INSERT INTO ndr.announcements \
         (id, title, message, announcement_type, audience, status, target_roles, target_tenants, start_at, end_at, created_by, updated_at) \
         VALUES ('{}','{}','{}','{}','{}','{}',{},{},{},{},'{}',now())",
        sql_escape(id),
        sql_escape(title),
        sql_escape(message),
        sql_escape(announcement_type),
        sql_escape(audience),
        sql_escape(status),
        sql_array_literal(target_roles),
        sql_array_literal(target_tenants),
        start_expr,
        end_expr,
        sql_escape(created_by),
    );
    self.client.query(&query).execute().await?;
    Ok(())
}

pub async fn get_announcements(
    &self,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let result = self.client
        .query(
            "SELECT id, title, message, announcement_type, audience, status, target_roles, target_tenants, \
             toString(start_at) AS starts_at, ifNull(toString(end_at), '') AS ends_at, created_by, \
             toString(created_at) AS created_at, toString(updated_at) AS updated_at \
             FROM ndr.announcements FINAL \
             ORDER BY updated_at DESC"
        )
        .fetch_all::<AnnouncementRow>()
        .await?;

    Ok(result.iter().map(|r| json!({
        "id": r.id,
        "title": r.title,
        "message": r.message,
        "type": r.announcement_type,
        "audience": r.audience,
        "status": r.status,
        "active": r.status == "active",
        "target_roles": r.target_roles,
        "target_tenants": r.target_tenants,
        "start_at": r.starts_at,
        "starts_at": r.starts_at,
        "end_at": r.ends_at,
        "ends_at": r.ends_at,
        "created_by": r.created_by,
        "created_at": r.created_at,
        "updated_at": r.updated_at
    })).collect())
}

pub async fn get_active_announcements(
    &self,
    role: &str,
    tenant_id: &str,
    username: &str,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let role = sql_escape(role);
    let role_alias = if role == "tenant_admin" {
        "tenant_admins".to_string()
    } else {
        role.clone()
    };
    let tenant_id = sql_escape(tenant_id);
    let username = sql_escape(username);
    let query = format!(
        "SELECT id, title, message, announcement_type, audience, status, target_roles, target_tenants, \
         toString(start_at) AS starts_at, ifNull(toString(end_at), '') AS ends_at, created_by, \
         toString(created_at) AS created_at, toString(updated_at) AS updated_at \
         FROM ndr.announcements FINAL \
         WHERE status = 'active' \
           AND start_at <= now() \
           AND (isNull(end_at) OR end_at >= now()) \
           AND (length(target_roles) = 0 OR has(target_roles, 'all') OR has(target_roles, '{}') OR has(target_roles, '{}')) \
           AND (length(target_tenants) = 0 OR has(target_tenants, 'all') OR has(target_tenants, '{}')) \
         ORDER BY start_at DESC, updated_at DESC",
        role,
        role_alias,
        tenant_id,
    );
    let result = self.client
        .query(&query)
        .fetch_all::<AnnouncementRow>()
        .await?;
    let read_query = format!(
        "SELECT announcement_id FROM ndr.announcement_reads FINAL WHERE username = '{}'",
        username
    );
    let read_ids = self.client
        .query(&read_query)
        .fetch_all::<AnnouncementReadRow>()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|row| row.announcement_id)
        .collect::<std::collections::HashSet<_>>();

    Ok(result.iter().map(|r| json!({
        "id": r.id,
        "title": r.title,
        "message": r.message,
        "type": r.announcement_type,
        "audience": r.audience,
        "status": r.status,
        "active": r.status == "active",
        "read": read_ids.contains(&r.id),
        "target_roles": r.target_roles,
        "target_tenants": r.target_tenants,
        "start_at": r.starts_at,
        "starts_at": r.starts_at,
        "end_at": r.ends_at,
        "ends_at": r.ends_at,
        "created_by": r.created_by,
        "created_at": r.created_at,
        "updated_at": r.updated_at
    })).collect())
}

pub async fn mark_announcement_read(
    &self,
    announcement_id: &str,
    username: &str,
) -> anyhow::Result<()> {
    let announcement_id = sql_escape(announcement_id);
    let username = sql_escape(username);
    let query = format!(
        "INSERT INTO ndr.announcement_reads (announcement_id, username, read_at) \
         VALUES ('{}','{}',now())",
        announcement_id,
        username
    );
    self.client.query(&query).execute().await?;
    Ok(())
}

pub async fn update_announcement(
    &self,
    id: &str,
    title: &str,
    message: &str,
    announcement_type: &str,
    audience: &str,
    status: &str,
    target_roles: &[String],
    target_tenants: &[String],
    start_at: Option<&str>,
    end_at: Option<&str>,
) -> anyhow::Result<()> {
    let start_expr = start_at
        .filter(|value| !value.trim().is_empty())
        .map(|value| format!("parseDateTimeBestEffort('{}')", sql_escape(value)))
        .unwrap_or_else(|| "now()".to_string());
    let end_expr = end_at
        .filter(|value| !value.trim().is_empty())
        .map(|value| format!("parseDateTimeBestEffort('{}')", sql_escape(value)))
        .unwrap_or_else(|| "CAST(NULL, 'Nullable(DateTime)')".to_string());
    let query = format!(
        "ALTER TABLE ndr.announcements UPDATE \
         title = '{}', message = '{}', announcement_type = '{}', audience = '{}', status = '{}', target_roles = {}, \
         target_tenants = {}, start_at = {}, end_at = {} \
         WHERE id = '{}' SETTINGS mutations_sync=1",
        sql_escape(title),
        sql_escape(message),
        sql_escape(announcement_type),
        sql_escape(audience),
        sql_escape(status),
        sql_array_literal(target_roles),
        sql_array_literal(target_tenants),
        start_expr,
        end_expr,
        sql_escape(id),
    );
    self.client.query(&query).execute().await?;
    Ok(())
}

pub async fn delete_announcement(
    &self,
    id: &str,
) -> anyhow::Result<()> {
    let query = format!(
        "ALTER TABLE ndr.announcements DELETE WHERE id = '{}' SETTINGS mutations_sync=1",
        sql_escape(id)
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

    pub async fn health_check(&self) -> bool {
        self.client
            .query("SELECT 1")
            .fetch_one::<u8>()
            .await
            .is_ok()
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
    if stmt.is_empty() { continue; }
    // Skip INSERT statements — initial data is seeded by install.sh.
    // Running INSERTs here would create duplicate rows on every engine restart.
    if stmt.trim_start().to_uppercase().starts_with("INSERT") { continue; }
    if let Err(e) = self.client
        .query(&stmt)
        .execute()
        .await {
        tracing::debug!(
            "SQL init stmt skipped: {}", e
        );
    }
}
            tracing::info!(
                "✅ ClickHouse tables initialized from {}", 
                sql_path
            );
            
            let announcements_table = "
                CREATE TABLE IF NOT EXISTS ndr.announcements
                (
                    id             String,
                    title          String,
                    message        String,
                    announcement_type String DEFAULT 'info',
                    audience       String DEFAULT 'all',
                    status         String DEFAULT 'draft',
                    target_roles   Array(String),
                    target_tenants Array(String),
                    start_at       DateTime DEFAULT now(),
                    end_at         Nullable(DateTime),
                    created_by     String,
                    created_at     DateTime DEFAULT now(),
                    updated_at     DateTime DEFAULT now()
                )
                ENGINE = ReplacingMergeTree(updated_at)
                ORDER BY id
            ";
            if let Err(e) = self.client
                .query(announcements_table)
                .execute()
                .await {
                tracing::debug!("Announcements table init skipped: {}", e);
            }

            let announcement_reads_table = "
                CREATE TABLE IF NOT EXISTS ndr.announcement_reads
                (
                    announcement_id String,
                    username        String,
                    read_at         DateTime DEFAULT now()
                )
                ENGINE = ReplacingMergeTree(read_at)
                ORDER BY (announcement_id, username)
            ";
            if let Err(e) = self.client
                .query(announcement_reads_table)
                .execute()
                .await {
                tracing::debug!("Announcement reads table init skipped: {}", e);
            }

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
                "ALTER TABLE ndr.sensor_keys ADD COLUMN IF NOT EXISTS hostname String DEFAULT ''",
                "ALTER TABLE ndr.sensor_keys ADD COLUMN IF NOT EXISTS interface_name String DEFAULT ''",
                "ALTER TABLE ndr.sensor_keys ADD COLUMN IF NOT EXISTS os_name String DEFAULT ''",
                "ALTER TABLE ndr.sensor_keys ADD COLUMN IF NOT EXISTS zeek_status String DEFAULT 'unknown'",
                "ALTER TABLE ndr.sensor_keys ADD COLUMN IF NOT EXISTS suricata_status String DEFAULT 'unknown'",
                "ALTER TABLE ndr.sensor_keys ADD COLUMN IF NOT EXISTS vector_status String DEFAULT 'unknown'",
                "ALTER TABLE ndr.sensor_commands ADD COLUMN IF NOT EXISTS sensor_id String DEFAULT ''",
                "ALTER TABLE ndr.announcements ADD COLUMN IF NOT EXISTS announcement_type String DEFAULT 'info'",
                "ALTER TABLE ndr.announcements ADD COLUMN IF NOT EXISTS audience String DEFAULT 'all'",
                "ALTER TABLE ndr.announcements ADD COLUMN IF NOT EXISTS target_tenants Array(String) DEFAULT []",
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

    pub async fn batch_insert_events_for_tenant(&self, events: Vec<NdrEvent>, tenant_id: &str) -> anyhow::Result<()> {
        if events.is_empty() { return Ok(()); }
        let db_name = tenant_db(tenant_id);
        let table_name = format!("{}.ndr_events", db_name);
        let mut insert = self.client.insert(&table_name)?;
        for event in &events {
            insert.write(event).await?;
        }
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

    /// Returns (id, content, tenant_id) for all enabled rules across all active tenants.
    pub async fn get_all_enabled_sigma_rules(&self) -> anyhow::Result<Vec<(String, String, String)>> {
        let mut all: Vec<(String, String, String)> = Vec::new();

        // Always include default tenant
        let tenants_to_query: Vec<String> = {
            let mut ids: Vec<String> = self.client
                .query("SELECT id FROM ndr.tenants FINAL WHERE active = 1")
                .fetch_all::<String>()
                .await
                .unwrap_or_default();
            ids.insert(0, "default".to_string());
            ids.dedup();
            ids
        };

        for tid in &tenants_to_query {
            let db = tenant_db(tid);
            let rows: Vec<(String, String)> = self.client
                .query(&format!(
                    "SELECT id, content FROM {}.sigma_rules FINAL WHERE enabled = 1",
                    db
                ))
                .fetch_all::<(String, String)>()
                .await
                .unwrap_or_default();
            for (id, content) in rows {
                all.push((id, content, tid.clone()));
            }
        }

        Ok(all)
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

pub async fn update_integration(
    &self,
    id: &str,
    name: &str,
    int_type: &str,
    config: &str,
    tenant_id: &str,
) -> anyhow::Result<()> {
    let db = tenant_db(tenant_id);
    // Re-INSERT with same id — ReplacingMergeTree will deduplicate on next merge.
    // We preserve the existing enabled flag by SELECTing it from the current row.
    let query = format!(
        "INSERT INTO {}.soar_integrations \
         (id, name, type, config, enabled, tenant_id) \
         SELECT '{}', '{}', '{}', '{}', enabled, '{}' \
         FROM {}.soar_integrations \
         WHERE id = '{}' \
         LIMIT 1",
        db,
        id,
        name.replace('\'', "\\'"),
        int_type.replace('\'', "\\'"),
        config.replace('\'', "\\'"),
        tenant_id,
        db,
        id
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
        } else {
            map.insert(key, serde_json::json!(val));
        }
    }
    Ok(serde_json::Value::Object(map))
}

pub async fn get_settings(&self) -> anyhow::Result<serde_json::Value> {
    self.get_settings_by_tenant("default").await
}

/// Returns full AiConfig built from tenant settings.
pub async fn get_ai_config_full(&self, tenant_id: &str) -> crate::ai::AiConfig {
    let settings = self.get_settings_by_tenant(tenant_id).await
        .unwrap_or_default();
    crate::ai::AiConfig::from_settings(&settings)
}

pub async fn save_setting_by_tenant(
    &self, key: &str, value: &str, tenant_id: &str
) -> anyhow::Result<()> {
    let db = tenant_db(tenant_id);
    let query = format!(
        "INSERT INTO {}.settings (key, value) \
         VALUES ('{}', '{}')",
        db, key, value.replace('\'', "\\'")
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

    pub async fn get_top_protocols_by_tenant(
        &self, limit: u64, tenant_id: &str
    ) -> anyhow::Result<Vec<serde_json::Value>> {
        let db_name = tenant_db(tenant_id);
        let rows = self.client.query(&format!(
            "SELECT proto, count() as cnt \
             FROM {}.ndr_events \
             WHERE proto != '' \
             GROUP BY proto ORDER BY cnt DESC LIMIT {}", db_name, limit))
            .fetch_all::<(String, u64)>()
            .await.unwrap_or_default();
        Ok(rows.iter().map(|r| serde_json::json!({
            "proto": r.0, "count": r.1
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
            "SELECT \
                toUInt32(timestamp) AS timestamp, \
                community_id, src_ip, dst_ip, score, severity, \
                tags, sigma_hits, threat_intel, src_country, dst_country \
             FROM {}.ndr_hits \
             ORDER BY timestamp DESC LIMIT {}", db_name, limit))
            .fetch_all::<RecentHitDetail>()
            .await.unwrap_or_default();
        Ok(rows.iter().map(|r| serde_json::json!({
            "timestamp": r.timestamp,
            "community_id": r.community_id,
            "src_ip": r.src_ip,
            "dst_ip": r.dst_ip,
            "score": r.score,
            "severity": r.severity,
            "tags": r.tags,
            "sigma_hits": r.sigma_hits,
            "threat_intel": r.threat_intel != 0,
            "src_country": r.src_country,
            "dst_country": r.dst_country
        })).collect())
    }

    pub async fn get_events_by_community_id(
        &self, community_id: &str, tenant_id: &str
    ) -> anyhow::Result<serde_json::Value> {
        let db_name = tenant_db(tenant_id);
        let cid = sql_escape(community_id);
        let rows = self.client
            .query(&format!(
                "SELECT source, event_type, src_ip, dst_ip, \
                        src_port, dst_port, proto, \
                        toUnixTimestamp(toDateTime(timestamp)) AS ts \
                 FROM {}.ndr_events \
                 WHERE community_id = '{}' \
                 ORDER BY timestamp DESC LIMIT 50",
                db_name, cid
            ))
            .fetch_all::<(String, String, String, String, u16, u16, String, u32)>()
            .await
            .unwrap_or_default();

        Ok(serde_json::json!(rows.iter().map(|r| serde_json::json!({
            "source":     r.0,
            "event_type": r.1,
            "src_ip":     r.2,
            "dst_ip":     r.3,
            "src_port":   r.4,
            "dst_port":   r.5,
            "proto":      r.6,
            "ts":         r.7,
        })).collect::<Vec<_>>()))
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

    pub async fn insert_passive_dns(&self, ip: &str, domain: &str) -> anyhow::Result<()> {
        if ip.is_empty() || domain.is_empty() { return Ok(()); }
        let query = format!(
            "INSERT INTO ndr.passive_dns (ip, domain, hit_count, first_seen, last_seen) VALUES ('{}', '{}', 1, now(), now())",
            sql_escape(ip), sql_escape(domain)
        );
        self.client.query(&query).execute().await?;
        Ok(())
    }

    pub async fn get_network_map_by_tenant(
        &self, tenant_id: &str, mode: Option<&str>, limit: Option<usize>
    ) -> anyhow::Result<serde_json::Value> {
        let db_name = tenant_db(tenant_id);
        let recent_query = format!("
            SELECT src_ip, dst_ip,
                count() as connections,
                groupArray(DISTINCT proto) as protocols
            FROM {db_name}.ndr_events
            WHERE tenant_id = '{tenant_escaped}' AND src_ip != '' AND dst_ip != ''
              AND timestamp >= (SELECT subtractHours(max(timestamp), 1) FROM {db_name}.ndr_events WHERE tenant_id = '{tenant_escaped}')
            GROUP BY src_ip, dst_ip
            ORDER BY connections DESC
            LIMIT 1000", db_name=db_name, tenant_escaped=sql_escape(tenant_id));
        let fallback_query = format!("
            SELECT src_ip, dst_ip,
                count() as connections,
                groupArray(DISTINCT proto) as protocols
            FROM {db_name}.ndr_events
            WHERE tenant_id = '{tenant_escaped}' AND src_ip != '' AND dst_ip != ''
            GROUP BY src_ip, dst_ip
            ORDER BY connections DESC
            LIMIT 1000", db_name=db_name, tenant_escaped=sql_escape(tenant_id));

        let mut pairs = self.client.query(&recent_query).fetch_all::<NetworkPair>().await.unwrap_or_default();
        if pairs.is_empty() {
            pairs = self.client.query(&fallback_query).fetch_all::<NetworkPair>().await.unwrap_or_default();
        }

        let mut asset_map: std::collections::HashMap<String, AssetRow> = std::collections::HashMap::new();
        let mut historical_to_active: std::collections::HashMap<String, String> = std::collections::HashMap::new();

        if let Ok(assets) = self.get_assets_by_tenant(tenant_id).await {
            for asset in assets {
                asset_map.insert(asset.ip.clone(), asset.clone());
                if !asset.ip_history.is_empty() && asset.ip_history != "[]" {
                    if let Ok(history) = serde_json::from_str::<Vec<serde_json::Value>>(&asset.ip_history) {
                        for h in history {
                            if let Some(old_ip) = h.get("ip").and_then(|v| v.as_str()) {
                                historical_to_active.insert(old_ip.to_string(), asset.ip.clone());
                            }
                        }
                    }
                }
            }
        }

        let resolve_ip = |raw_ip: &String| -> String {
            historical_to_active.get(raw_ip).cloned().unwrap_or_else(|| raw_ip.clone())
        };

        let mut pair_map: std::collections::HashMap<(String, String), NetworkPair> = std::collections::HashMap::new();
        for p in pairs {
            let src = resolve_ip(&p.src_ip);
            let dst = resolve_ip(&p.dst_ip);
            if src == dst { continue; }
            let entry = pair_map.entry((src.clone(), dst.clone())).or_insert_with(|| NetworkPair {
                src_ip: src, dst_ip: dst, connections: 0, protocols: Vec::new()
            });
            entry.connections += p.connections;
            for proto in p.protocols {
                if !entry.protocols.contains(&proto) { entry.protocols.push(proto); }
            }
        }
        let pairs: Vec<NetworkPair> = pair_map.into_values().collect();

        let is_internal_fn = |ip: &str| -> bool {
            if ip.starts_with("10.") || ip.starts_with("192.168.") { return true; }
            if ip.starts_with("172.") {
                let parts: Vec<&str> = ip.split('.').collect();
                if parts.len() >= 2 {
                    if let Ok(second) = parts[1].parse::<u8>() {
                        return second >= 16 && second <= 31;
                    }
                }
            }
            false
        };

        let is_top_mode = mode.unwrap_or("") == "top";
        let mut top_ips = std::collections::HashSet::new();

        if is_top_mode {
            let limit_n = limit.unwrap_or(25);
            let mut ip_counts: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
            for p in &pairs {
                *ip_counts.entry(p.src_ip.clone()).or_insert(0) += p.connections;
                *ip_counts.entry(p.dst_ip.clone()).or_insert(0) += p.connections;
            }
            let mut ip_list: Vec<_> = ip_counts.into_iter().collect();
            ip_list.sort_by(|a, b| b.1.cmp(&a.1));
            top_ips = ip_list.into_iter().take(limit_n).map(|(ip, _)| ip).collect();
        }

        let mut internal_members = std::collections::HashSet::new();
        let mut external_members = std::collections::HashSet::new();

        let mut external_ips: Vec<String> = Vec::new();
        for pair in &pairs {
            if !is_internal_fn(&pair.src_ip) { external_ips.push(pair.src_ip.clone()); }
            if !is_internal_fn(&pair.dst_ip) { external_ips.push(pair.dst_ip.clone()); }
        }

        #[derive(clickhouse::Row, serde::Deserialize)]
        struct PassiveDnsRow {
            ip: String,
            primary_domain: String,
            all_domains: Vec<String>,
        }
        let mut passive_dns_map: std::collections::HashMap<String, PassiveDnsRow> = std::collections::HashMap::new();

        if !external_ips.is_empty() {
            let items = external_ips.iter().map(|v| format!("'{}'", sql_escape(v))).collect::<Vec<_>>().join(",");
            let dns_query = format!("
                SELECT ip,
                    argMax(domain, total_hits) AS primary_domain,
                    groupUniqArray(domain) AS all_domains
                FROM (
                    SELECT ip, domain, sum(hit_count) AS total_hits
                    FROM ndr.passive_dns
                    WHERE ip IN ({}) AND last_seen > now() - INTERVAL 30 DAY
                    GROUP BY ip, domain
                )
                GROUP BY ip
            ", items);
            if let Ok(dns_rows) = self.client.query(&dns_query).fetch_all::<PassiveDnsRow>().await {
                for r in dns_rows {
                    passive_dns_map.insert(r.ip.clone(), r);
                }
            }
        }

        struct DomainGroup {
            base_domain: String,
            observed_domains: std::collections::HashSet<String>,
            member_ips: std::collections::HashSet<String>,
        }
        let mut domain_groups: std::collections::HashMap<String, DomainGroup> = std::collections::HashMap::new();

        let mut remap_ip = |ip: &String| -> String {
            if is_internal_fn(ip) {
                if is_top_mode && !top_ips.contains(ip) {
                    internal_members.insert(ip.clone());
                    return "cluster:internal".to_string();
                }
                return ip.clone();
            } else {
                let group_id = if let Some(dns) = passive_dns_map.get(ip) {
                    let base = get_base_domain(&dns.primary_domain);
                    let gid = format!("domain:{}", base);
                    let group = domain_groups.entry(gid.clone()).or_insert_with(|| DomainGroup {
                        base_domain: base.clone(),
                        observed_domains: std::collections::HashSet::new(),
                        member_ips: std::collections::HashSet::new(),
                    });
                    group.member_ips.insert(ip.clone());
                    group.observed_domains.insert(dns.primary_domain.clone());
                    for d in &dns.all_domains { group.observed_domains.insert(d.clone()); }
                    gid
                } else {
                    ip.clone()
                };
                if is_top_mode && !top_ips.contains(ip) {
                    external_members.insert(group_id.clone());
                    return "cluster:external".to_string();
                }
                return group_id;
            }
        };

        let mut clustered_pairs: std::collections::HashMap<(String, String), (u64, std::collections::HashSet<String>)> = std::collections::HashMap::new();
        for pair in &pairs {
            let src = remap_ip(&pair.src_ip);
            let dst = remap_ip(&pair.dst_ip);
            if src == dst { continue; }
            let entry = clustered_pairs.entry((src.clone(), dst.clone())).or_insert_with(|| (0, std::collections::HashSet::new()));
            entry.0 += pair.connections;
            for p in &pair.protocols { entry.1.insert(p.clone()); }
        }

        let mut nodes: std::collections::HashMap<String, serde_json::Value> = std::collections::HashMap::new();
        let mut edges: Vec<serde_json::Value> = Vec::new();

        let enrich_node = |id: &str| -> serde_json::Value {
            let is_internal = is_internal_fn(id);
            if id == "cluster:internal" {
                return serde_json::json!({"id": id, "label": format!("{} more internal hosts", internal_members.len()), "type": "cluster", "is_internal": true, "member_ips": internal_members.iter().collect::<Vec<_>>()});
            } else if id == "cluster:external" {
                return serde_json::json!({"id": id, "label": format!("{} more external hosts", external_members.len()), "type": "cluster", "is_internal": false, "member_ips": external_members.iter().collect::<Vec<_>>()});
            }
            if id.starts_with("domain:") {
                if let Some(group) = domain_groups.get(id) {
                    return serde_json::json!({"id": id, "label": group.base_domain, "type": "domain", "is_internal": false, "primary_domain": group.base_domain, "all_domains": group.observed_domains.iter().collect::<Vec<_>>(), "member_ips": group.member_ips.iter().collect::<Vec<_>>()});
                }
            }
            if let Some(asset) = asset_map.get(id) {
                let label = if !asset.custom_name.is_empty() { asset.custom_name.clone() } else if !asset.hostname.is_empty() { asset.hostname.clone() } else { id.to_string() };
                serde_json::json!({"id": id, "label": label, "active_ip": id, "ip_history": asset.ip_history, "mac": asset.mac, "type": asset.device_type, "vendor": asset.vendor, "os_guess": asset.os_guess, "is_internal": is_internal})
            } else {
                serde_json::json!({"id": id, "label": id, "active_ip": id, "ip_history": "[]", "type": if is_internal { "unknown" } else { "external" }, "is_internal": is_internal, "primary_domain": null, "all_domains": []})
            }
        };

        for ((src, dst), (conn, protos)) in clustered_pairs {
            nodes.entry(src.clone()).or_insert_with(|| enrich_node(&src));
            nodes.entry(dst.clone()).or_insert_with(|| enrich_node(&dst));
            edges.push(serde_json::json!({"source": src, "target": dst, "connections": conn, "protocols": protos.into_iter().collect::<Vec<_>>()}));
        }

        let total_nodes = nodes.len();
        let total_edges = edges.len();
        Ok(serde_json::json!({"nodes": nodes.values().collect::<Vec<_>>(), "edges": edges, "total_nodes": total_nodes, "total_edges": total_edges}))
    }

    pub async fn get_network_map_node(
        &self, tenant_id: &str, target_ip: &str
    ) -> anyhow::Result<serde_json::Value> {
        let db_name = tenant_db(tenant_id);
        let safe_ip = sql_escape(target_ip);
        let query = format!("
            SELECT src_ip, dst_ip,
                count() as connections,
                groupArray(DISTINCT proto) as protocols
            FROM {}.ndr_events
            WHERE tenant_id = '{}' AND (src_ip = '{}' OR dst_ip = '{}')
              AND src_ip != '' AND dst_ip != ''
            GROUP BY src_ip, dst_ip
            ORDER BY connections DESC
            LIMIT 500", db_name, sql_escape(tenant_id), safe_ip, safe_ip);

        let pairs = self.client.query(&query).fetch_all::<NetworkPair>().await.unwrap_or_default();

        let mut asset_map: std::collections::HashMap<String, AssetRow> = std::collections::HashMap::new();
        let mut historical_to_active: std::collections::HashMap<String, String> = std::collections::HashMap::new();

        if let Ok(assets) = self.get_assets_by_tenant(tenant_id).await {
            for asset in assets {
                asset_map.insert(asset.ip.clone(), asset.clone());
                if !asset.ip_history.is_empty() && asset.ip_history != "[]" {
                    if let Ok(history) = serde_json::from_str::<Vec<serde_json::Value>>(&asset.ip_history) {
                        for h in history {
                            if let Some(old_ip) = h.get("ip").and_then(|v| v.as_str()) {
                                historical_to_active.insert(old_ip.to_string(), asset.ip.clone());
                            }
                        }
                    }
                }
            }
        }

        let resolve_ip = |raw_ip: &String| -> String {
            historical_to_active.get(raw_ip).cloned().unwrap_or_else(|| raw_ip.clone())
        };

        let mut pair_map: std::collections::HashMap<(String, String), NetworkPair> = std::collections::HashMap::new();
        for p in pairs {
            let src = resolve_ip(&p.src_ip);
            let dst = resolve_ip(&p.dst_ip);
            if src == dst { continue; }
            let entry = pair_map.entry((src.clone(), dst.clone())).or_insert_with(|| NetworkPair {
                src_ip: src, dst_ip: dst, connections: 0, protocols: Vec::new()
            });
            entry.connections += p.connections;
            for proto in p.protocols {
                if !entry.protocols.contains(&proto) { entry.protocols.push(proto); }
            }
        }
        let pairs: Vec<NetworkPair> = pair_map.into_values().collect();

        let is_internal_fn = |ip: &str| -> bool {
            if ip.starts_with("10.") || ip.starts_with("192.168.") { return true; }
            if ip.starts_with("172.") {
                let parts: Vec<&str> = ip.split('.').collect();
                if parts.len() >= 2 {
                    if let Ok(second) = parts[1].parse::<u8>() {
                        return second >= 16 && second <= 31;
                    }
                }
            }
            false
        };

        let mut nodes: std::collections::HashMap<String, serde_json::Value> = std::collections::HashMap::new();
        let mut edges: Vec<serde_json::Value> = Vec::new();

        let enrich_node = |ip: &str| -> serde_json::Value {
            let is_internal = is_internal_fn(ip);
            if let Some(asset) = asset_map.get(ip) {
                let label = if !asset.custom_name.is_empty() { asset.custom_name.clone() } else if !asset.hostname.is_empty() { asset.hostname.clone() } else { ip.to_string() };
                serde_json::json!({"id": ip, "label": label, "active_ip": ip, "ip_history": asset.ip_history, "mac": asset.mac, "type": asset.device_type, "vendor": asset.vendor, "os_guess": asset.os_guess, "is_internal": is_internal})
            } else {
                serde_json::json!({"id": ip, "label": ip, "active_ip": ip, "ip_history": "[]", "type": if is_internal { "unknown" } else { "external" }, "is_internal": is_internal})
            }
        };

        for pair in pairs {
            nodes.entry(pair.src_ip.clone()).or_insert_with(|| enrich_node(&pair.src_ip));
            nodes.entry(pair.dst_ip.clone()).or_insert_with(|| enrich_node(&pair.dst_ip));
            edges.push(serde_json::json!({"source": pair.src_ip, "target": pair.dst_ip, "connections": pair.connections, "protocols": pair.protocols}));
        }

        Ok(serde_json::json!({"nodes": nodes.values().collect::<Vec<_>>(), "edges": edges, "total_nodes": nodes.len(), "total_edges": edges.len()}))
    }

    pub async fn search_network_map(
        &self, tenant_id: &str, q: &str
    ) -> anyhow::Result<Vec<String>> {
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct SearchRow { ip: String }

        let db_name = tenant_db(tenant_id);
        let safe_q = sql_escape(q);
        let query = format!("
            SELECT ip FROM (
                SELECT DISTINCT ip FROM {}.assets
                WHERE ip ILIKE '%{}%' OR hostname ILIKE '%{}%' OR custom_name ILIKE '%{}%' OR ip_history ILIKE '%{}%'
                UNION ALL
                SELECT DISTINCT ip FROM ndr.passive_dns
                WHERE domain ILIKE '%{}%'
            ) LIMIT 50", db_name, safe_q, safe_q, safe_q, safe_q, safe_q);

        let rows = self.client.query(&query).fetch_all::<SearchRow>().await.unwrap_or_default();
        Ok(rows.into_iter().map(|r| r.ip).collect())
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
                    name, hostname, interface_name, \
                    os_name, zeek_status, suricata_status, \
                    vector_status, arkime_status, arkime_url, arkime_pass, \
                    active, toString(created_at), \
                    toString(last_seen) \
             FROM ndr.sensor_keys FINAL \
             WHERE {} \
             ORDER BY created_at DESC", filter
        ))
        .fetch_all::<SensorKeyRow>()
        .await?;
    
    Ok(result.iter().map(|r| serde_json::json!({
        "id": r.id,
        "key_prefix": r.key_prefix,
        "tenant_id": r.tenant_id,
        "name": r.name,
        "hostname": r.hostname,
        "interface": r.interface_name,
        "os": r.os_name,
        "zeek": r.zeek_status,
        "suricata": r.suricata_status,
        "vector": r.vector_status,
        "arkime": r.arkime_status,
        "arkime_url": r.arkime_url,
        "active": r.active == 1,
        "created_at": r.created_at,
        "last_seen": r.last_seen
    })).collect())
}

pub async fn update_sensor_registration(
    &self,
    key_prefix: &str,
    hostname: &str,
    interface_name: &str,
    os_name: &str,
) -> anyhow::Result<()> {
    let key_prefix = sql_escape(key_prefix);
    let hostname = sql_escape(hostname);
    let interface_name = sql_escape(interface_name);
    let os_name = sql_escape(os_name);
    let query = format!(
        "INSERT INTO ndr.sensor_keys \
         (id, key_hash, key_prefix, tenant_id, name, hostname, interface_name, \
          os_name, zeek_status, suricata_status, vector_status, active, created_at, last_seen) \
         SELECT id, key_hash, key_prefix, tenant_id, name, '{}', '{}', '{}', \
                zeek_status, suricata_status, vector_status, active, created_at, now() \
         FROM ndr.sensor_keys FINAL \
         WHERE key_prefix = '{}' AND active = 1",
        hostname, interface_name, os_name, key_prefix
    );
    self.client.query(&query).execute().await?;
    Ok(())
}

pub async fn update_sensor_heartbeat(
    &self,
    key_prefix: &str,
    zeek_status: &str,
    suricata_status: &str,
    vector_status: &str,
    arkime_status: &str,
    arkime_url: &str,
    arkime_pass: &str,
) -> anyhow::Result<()> {
    let key_prefix = sql_escape(key_prefix);
    let zeek_status = sql_escape(zeek_status);
    let suricata_status = sql_escape(suricata_status);
    let vector_status = sql_escape(vector_status);
    let arkime_status = sql_escape(arkime_status);
    let arkime_url = sql_escape(arkime_url);
    let arkime_pass_esc = sql_escape(arkime_pass);
    let update_pass = if arkime_pass.is_empty() {
        "arkime_pass".to_string()
    } else {
        format!("'{}'", arkime_pass_esc)
    };
    let query = format!(
        "INSERT INTO ndr.sensor_keys \
         (id, key_hash, key_prefix, tenant_id, name, hostname, interface_name, \
          os_name, zeek_status, suricata_status, vector_status, \
          arkime_status, arkime_url, arkime_pass, active, created_at, last_seen) \
         SELECT id, key_hash, key_prefix, tenant_id, name, hostname, interface_name, \
                os_name, '{}', '{}', '{}', '{}', '{}', {}, active, created_at, now() \
         FROM ndr.sensor_keys FINAL \
         WHERE key_prefix = '{}' AND active = 1",
        zeek_status, suricata_status, vector_status,
        arkime_status, arkime_url, update_pass, key_prefix
    );
    self.client.query(&query).execute().await?;
    Ok(())
}

pub async fn get_arkime_creds(
    &self,
    tenant_id: &str,
) -> anyhow::Result<(String, String)> {
    let tenant_id_esc = sql_escape(tenant_id);

    // Query sensor_keys — ignore errors (e.g. arkime_pass column not yet migrated)
    // so the env var fallback below is always reachable
    let db_creds = self.client
        .query(&format!(
            "SELECT arkime_url, arkime_pass FROM ndr.sensor_keys FINAL \
             WHERE tenant_id = '{}' AND active = 1 AND arkime_url != '' \
             ORDER BY last_seen DESC LIMIT 1",
            tenant_id_esc
        ))
        .fetch_all::<(String, String)>()
        .await
        .unwrap_or_default();

    if let Some(creds) = db_creds.into_iter().next() {
        if !creds.0.is_empty() {
            return Ok(creds);
        }
    }

    // On-premise fallback: read from environment (set by install.sh for default tenant)
    if tenant_id == "default" {
        let url  = std::env::var("ARKIME_URL").unwrap_or_default();
        let pass = std::env::var("ARKIME_PASS").unwrap_or_default();
        if !url.is_empty() {
            return Ok((url, pass));
        }
    }

    Ok((String::new(), String::new()))
}

pub async fn get_arkime_url(
    &self,
    tenant_id: &str,
) -> anyhow::Result<String> {
    let tenant_id = sql_escape(tenant_id);
    let result = self.client
        .query(&format!(
            "SELECT arkime_url FROM ndr.sensor_keys FINAL \
             WHERE tenant_id = '{}' AND active = 1 AND arkime_url != '' \
             ORDER BY last_seen DESC LIMIT 1",
            tenant_id
        ))
        .fetch_all::<String>()
        .await?;
    Ok(result.into_iter().next().unwrap_or_default())
}

pub async fn save_arkime_url(
    &self,
    tenant_id: &str,
    arkime_url: &str,
) -> anyhow::Result<()> {
    let tenant_id = sql_escape(tenant_id);
    let arkime_url = sql_escape(arkime_url);
    self.client
        .query(&format!(
            "ALTER TABLE ndr.sensor_keys \
             UPDATE arkime_url = '{}' \
             WHERE tenant_id = '{}' AND active = 1",
            arkime_url, tenant_id
        ))
        .execute()
        .await?;
    Ok(())
}

pub async fn get_pcap_sessions(
    &self,
    tenant_id: &str,
    community_id: Option<&str>,
    src_ip: Option<&str>,
    limit: u32,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let db = tenant_db(tenant_id);
    let tenant_id_esc = sql_escape(tenant_id);
    let mut conditions = format!("tenant_id = '{}'", tenant_id_esc);
    if let Some(cid) = community_id {
        conditions.push_str(&format!(" AND community_id = '{}'", sql_escape(cid)));
    }
    if let Some(ip) = src_ip {
        let ip = sql_escape(ip);
        conditions.push_str(&format!(" AND (src_ip = '{}' OR dst_ip = '{}')", ip, ip));
    }
    let query = format!(
        "SELECT session_id, any(community_id), any(src_ip), any(dst_ip), \
                any(src_port), any(dst_port), any(proto), \
                toString(any(start_time)), toString(any(end_time)), \
                any(bytes), any(packets), any(arkime_url), any(sensor_host), any(file_path) \
         FROM {}.pcap_sessions \
         WHERE {} \
         GROUP BY session_id \
         ORDER BY any(start_time) DESC \
         LIMIT {}",
        db, conditions, limit
    );
    let rows = self.client
        .query(&query)
        .fetch_all::<PcapSessionRow>()
        .await?;
    Ok(rows.iter().map(|r| json!({
        "session_id":   r.session_id,
        "community_id": r.community_id,
        "src_ip":       r.src_ip,
        "dst_ip":       r.dst_ip,
        "src_port":     r.src_port,
        "dst_port":     r.dst_port,
        "proto":        r.proto,
        "start_time":   r.start_time,
        "end_time":     r.end_time,
        "bytes":        r.bytes,
        "packets":      r.packets,
        "arkime_url":   r.arkime_url,
        "sensor_host":  r.sensor_host,
        "file_path":    r.file_path
    })).collect())
}

pub async fn save_pcap_session(
    &self,
    tenant_id: &str,
    session_id: &str,
    community_id: &str,
    src_ip: &str,
    dst_ip: &str,
    src_port: u16,
    dst_port: u16,
    proto: &str,
    bytes: u64,
    arkime_url: &str,
    file_path: &str,
    sensor_host: &str,
) -> anyhow::Result<()> {
    let db = tenant_db(tenant_id);
    // Skip insert if this session_id is already stored (prevents duplicate rows
    // from repeated Arkime live-queries on the same sessions)
    let exists_query = format!(
        "SELECT count() FROM {}.pcap_sessions \
         WHERE session_id = '{}' AND tenant_id = '{}'",
        db, sql_escape(session_id), sql_escape(tenant_id)
    );
    let count: Vec<u64> = self.client.query(&exists_query).fetch_all().await?;
    if count.into_iter().next().unwrap_or(0) > 0 {
        return Ok(());
    }

    let query = format!(
        "INSERT INTO {}.pcap_sessions \
         (session_id, community_id, src_ip, dst_ip, src_port, dst_port, \
          proto, start_time, end_time, bytes, packets, arkime_url, \
          tenant_id, sensor_host, file_path) \
         VALUES ('{}', '{}', '{}', '{}', {}, {}, '{}', now(), now(), \
                 {}, 0, '{}', '{}', '{}', '{}')",
        db,
        sql_escape(session_id), sql_escape(community_id),
        sql_escape(src_ip), sql_escape(dst_ip),
        src_port, dst_port, sql_escape(proto),
        bytes, sql_escape(arkime_url), sql_escape(tenant_id),
        sql_escape(sensor_host), sql_escape(file_path)
    );
    self.client.query(&query).execute().await?;
    Ok(())
}

pub async fn get_pcap_file_path(
    &self,
    tenant_id: &str,
    session_id: &str,
) -> anyhow::Result<String> {
    let db = tenant_db(tenant_id);
    let result = self.client
        .query(&format!(
            "SELECT file_path FROM {}.pcap_sessions \
             WHERE session_id = '{}' AND tenant_id = '{}' \
             LIMIT 1",
            db, sql_escape(session_id), sql_escape(tenant_id)
        ))
        .fetch_all::<String>()
        .await?;
    Ok(result.into_iter().next().unwrap_or_default())
}

pub async fn queue_pcap_request(
    &self,
    tenant_id: &str,
    community_id: &str,
) -> anyhow::Result<()> {
    let db = tenant_db(tenant_id);
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct CntRow { cnt: u64 }
    let rows = self.client.query(&format!(
        "SELECT count() as cnt FROM {}.pcap_pending \
         WHERE community_id = '{}' AND tenant_id = '{}' \
         AND requested_at > now() - INTERVAL 24 HOUR",
        db, sql_escape(community_id), sql_escape(tenant_id)
    )).fetch_all::<CntRow>().await.unwrap_or_default();
    if rows.first().map(|r| r.cnt).unwrap_or(0) > 0 {
        return Ok(()); // already queued — skip duplicate
    }

    self.client
        .query(&format!(
            "INSERT INTO {}.pcap_pending \
             (community_id, tenant_id, fulfilled) VALUES \
             ('{}', '{}', 0)",
            db, sql_escape(community_id), sql_escape(tenant_id)
        ))
        .execute()
        .await?;
    Ok(())
}

pub async fn get_pending_pcap_requests(
    &self,
    tenant_id: &str,
) -> anyhow::Result<Vec<String>> {
    let db = tenant_db(tenant_id);
    let rows = self.client
        .query(&format!(
            "SELECT community_id FROM {}.pcap_pending FINAL \
             WHERE tenant_id = '{}' AND fulfilled = 0 \
             AND requested_at > now() - INTERVAL 1 DAY",
            db, sql_escape(tenant_id)
        ))
        .fetch_all::<String>()
        .await
        .unwrap_or_default();
    Ok(rows)
}

pub async fn mark_pcap_fulfilled(
    &self,
    tenant_id: &str,
    community_id: &str,
) -> anyhow::Result<()> {
    let db = tenant_db(tenant_id);
    self.client
        .query(&format!(
            "ALTER TABLE {}.pcap_pending \
             UPDATE fulfilled = 1, fulfilled_at = now() \
             WHERE tenant_id = '{}' AND community_id = '{}'",
            db, sql_escape(tenant_id), sql_escape(community_id)
        ))
        .execute()
        .await?;
    Ok(())
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

/// Fetch the key_prefix for a sensor key by its UUID id.
/// Used to invalidate the Redis cache immediately on revocation,
/// since plain api_keys are never stored (only bcrypt hashes).
pub async fn get_sensor_key_prefix_by_id(
    &self,
    id: &str,
) -> anyhow::Result<Option<String>> {
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct Row { key_prefix: String }

    let rows = self.client
        .query(&format!(
            "SELECT key_prefix FROM ndr.sensor_keys FINAL \
             WHERE id = '{}' LIMIT 1",
            id.replace('\'', "\\'")
        ))
        .fetch_all::<Row>()
        .await?;

    Ok(rows.into_iter().next().map(|r| r.key_prefix))
}

pub async fn reactivate_sensor_key(
    &self,
    id: &str,
) -> anyhow::Result<()> {
    self.client
        .query(&format!(
            "ALTER TABLE ndr.sensor_keys \
             UPDATE active = 1 \
             WHERE id = '{}'", id
        ))
        .execute().await?;
    Ok(())
}

pub async fn active_sensor_exists(
    &self,
    tenant_id: &str,
    sensor_id: &str,
) -> anyhow::Result<bool> {
    let tenant_id = sql_escape(tenant_id);
    let sensor_id = sql_escape(sensor_id);
    let result = self.client
        .query(&format!(
            "SELECT id FROM ndr.sensor_keys FINAL \
             WHERE tenant_id = '{}' \
             AND key_prefix = '{}' \
             AND active = 1 \
             LIMIT 1",
            tenant_id, sensor_id
        ))
        .fetch_all::<String>()
        .await?;

    Ok(!result.is_empty())
}

pub async fn set_sensor_command(
    &self,
    tenant_id: &str,
    sensor_id: &str,
    command: &str,
) -> anyhow::Result<()> {
    let db = tenant_db(tenant_id);
    let id = uuid::Uuid::new_v4().to_string();
    let tenant_id = sql_escape(tenant_id);
    let sensor_id = sql_escape(sensor_id);
    let command = sql_escape(command);
    let query = format!(
        "INSERT INTO {}.sensor_commands \
         (id, tenant_id, sensor_id, command, status) \
         VALUES ('{}', '{}', '{}', '{}', 'pending')",
        db, id, tenant_id, sensor_id, command
    );
    self.client.query(&query).execute().await?;
    Ok(())
}

pub async fn get_sensor_command(
    &self,
    tenant_id: &str,
    sensor_id: &str,
) -> anyhow::Result<(String, String)> {
    let db = tenant_db(tenant_id);
    let tenant_id = sql_escape(tenant_id);
    let sensor_id = sql_escape(sensor_id);
    let result = self.client
        .query(&format!(
            "SELECT command, sensor_id FROM {}.sensor_commands FINAL \
             WHERE tenant_id = '{}' \
             AND (sensor_id = '{}' OR sensor_id = '') \
             AND status = 'pending' \
             ORDER BY if(sensor_id = '{}', 0, 1), created_at DESC \
             LIMIT 1",
            db, tenant_id, sensor_id, sensor_id
        ))
        .fetch_all::<(String, String)>()
        .await?;

    Ok(result.first()
        .map(|r| (r.0.clone(), r.1.clone()))
        .unwrap_or_default())
}

pub async fn clear_sensor_command(
    &self,
    tenant_id: &str,
    sensor_id: &str,
) -> anyhow::Result<()> {
    let db = tenant_db(tenant_id);
    let tenant_id = sql_escape(tenant_id);
    let sensor_id = sql_escape(sensor_id);
    self.client
        .query(&format!(
            "ALTER TABLE {}.sensor_commands \
             UPDATE status = 'done' \
             WHERE tenant_id = '{}' \
             AND sensor_id = '{}' \
             AND status = 'pending'",
            db, tenant_id, sensor_id
        ))
        .execute().await?;
    Ok(())
}

    // ── AI suppressions ──────────────────────────────────────────────────

    pub async fn save_ai_suppression(
        &self,
        tenant_id:      &str,
        sig_id:         u64,
        sig_name:       &str,
        suppress_type:  &str,   // "by_dst" | "by_src" | "by_sid"
        suppress_ip:    &str,
        src_ip:         &str,
        dst_ip:         &str,
        community_id:   &str,
        ai_reason:      &str,
        ai_confidence:  u8,
        sensor_id:      &str,
    ) -> anyhow::Result<()> {
        let db = tenant_db(tenant_id);
        self.client.query(&format!(
            "INSERT INTO {}.ai_suppressions \
             (id, tenant_id, signature_id, signature_name, suppress_type, suppress_ip, \
              src_ip, dst_ip, community_id, ai_reason, ai_confidence, sensor_id, active) \
             VALUES ('{}','{}',{},  '{}','{}','{}','{}','{}','{}','{}',{}, '{}', 1)",
            db,
            uuid::Uuid::new_v4(),
            sql_escape(tenant_id),
            sig_id,
            sql_escape(sig_name),
            sql_escape(suppress_type),
            sql_escape(suppress_ip),
            sql_escape(src_ip),
            sql_escape(dst_ip),
            sql_escape(community_id),
            sql_escape(ai_reason),
            ai_confidence,
            sql_escape(sensor_id),
        )).execute().await?;
        Ok(())
    }

    pub async fn is_ai_suppressed(
        &self,
        tenant_id: &str,
        sig_id:    u64,
        src_ip:    &str,
        dst_ip:    &str,
    ) -> bool {
        let db = tenant_db(tenant_id);
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct Cnt { cnt: u64 }
        let r = self.client.query(&format!(
            "SELECT count() as cnt FROM {}.ai_suppressions FINAL \
             WHERE tenant_id = '{}' AND active = 1 \
             AND signature_id = {} \
             AND (suppress_type = 'by_sid' \
               OR (suppress_type = 'by_dst' AND suppress_ip = '{}') \
               OR (suppress_type = 'by_src' AND suppress_ip = '{}'))",
            db, sql_escape(tenant_id), sig_id,
            sql_escape(dst_ip), sql_escape(src_ip)
        )).fetch_all::<Cnt>().await.unwrap_or_default();
        r.first().map(|x| x.cnt > 0).unwrap_or(false)
    }

    pub async fn list_ai_suppressions(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<Vec<serde_json::Value>> {
        let db = tenant_db(tenant_id);
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct Row {
            id: String, sig_id: u64, sig_name: String,
            suppress_type: String, suppress_ip: String,
            src_ip: String, dst_ip: String,
            ai_reason: String, ai_confidence: u8,
            active: u8, created_at: String,
        }
        let rows = self.client.query(&format!(
            "SELECT id, signature_id as sig_id, signature_name as sig_name, \
             suppress_type, suppress_ip, src_ip, dst_ip, \
             ai_reason, ai_confidence, active, toString(created_at) as created_at \
             FROM {}.ai_suppressions FINAL \
             WHERE tenant_id = '{}' \
             ORDER BY created_at DESC LIMIT 100",
            db, sql_escape(tenant_id)
        )).fetch_all::<Row>().await.unwrap_or_default();
        Ok(rows.iter().map(|r| json!({
            "id": r.id, "signature_id": r.sig_id, "signature_name": r.sig_name,
            "suppress_type": r.suppress_type, "suppress_ip": r.suppress_ip,
            "src_ip": r.src_ip, "dst_ip": r.dst_ip,
            "ai_reason": r.ai_reason, "ai_confidence": r.ai_confidence,
            "active": r.active == 1, "created_at": r.created_at
        })).collect())
    }

    //support messages
    pub async fn create_support_message(
        &self,
        tenant_id: &str,
        sender_username: &str,
        sender_role: &str,
        subject: &str,
        category: &str,
        message: &str,
    ) -> anyhow::Result<String> {
        let id = uuid::Uuid::new_v4().to_string();
        self.client
            .query(
                "INSERT INTO ndr.support_messages
                 (id, tenant_id, sender_username, sender_role, subject, category, message)
                 VALUES (?, ?, ?, ?, ?, ?, ?)"
            )
            .bind(&id)
            .bind(tenant_id)
            .bind(sender_username)
            .bind(sender_role)
            .bind(subject)
            .bind(category)
            .bind(message)
            .execute()
            .await?;
        Ok(id)
    }

    pub async fn get_support_messages_for_user(
        &self,
        tenant_id: &str,
        sender_username: &str,
    ) -> anyhow::Result<Vec<serde_json::Value>> {
        let rows = self.client
            .query(
                "SELECT
                    id, tenant_id, sender_username, sender_role, subject, category, message,
                    status, admin_reply, replied_by, forwarded, forwarded_by, deleted,
                    toString(created_at) AS created_at,
                    toString(updated_at) AS updated_at,
                    if(isNull(replied_at), '', toString(assumeNotNull(replied_at))) AS replied_at,
                    if(isNull(forwarded_at), '', toString(assumeNotNull(forwarded_at))) AS forwarded_at
                 FROM ndr.support_messages FINAL
                 WHERE tenant_id = ? AND sender_username = ? AND deleted = 0
                 ORDER BY updated_at DESC"
            )
            .bind(tenant_id)
            .bind(sender_username)
            .fetch_all::<SupportMessageRow>()
            .await?;
        Ok(rows.into_iter().map(support_message_to_json).collect())
    }

    pub async fn get_support_messages_for_tenant(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<Vec<serde_json::Value>> {
        let rows = self.client
            .query(
                "SELECT
                    id, tenant_id, sender_username, sender_role, subject, category, message,
                    status, admin_reply, replied_by, forwarded, forwarded_by, deleted,
                    toString(created_at) AS created_at,
                    toString(updated_at) AS updated_at,
                    if(isNull(replied_at), '', toString(assumeNotNull(replied_at))) AS replied_at,
                    if(isNull(forwarded_at), '', toString(assumeNotNull(forwarded_at))) AS forwarded_at
                 FROM ndr.support_messages FINAL
                 WHERE tenant_id = ? AND deleted = 0
                 ORDER BY updated_at DESC"
            )
            .bind(tenant_id)
            .fetch_all::<SupportMessageRow>()
            .await?;
        Ok(rows.into_iter().map(support_message_to_json).collect())
    }

    pub async fn get_support_messages_for_super_admin(&self) -> anyhow::Result<Vec<serde_json::Value>> {
        let rows = self.client
            .query(
                "SELECT
                    id, tenant_id, sender_username, sender_role, subject, category, message,
                    status, admin_reply, replied_by, forwarded, forwarded_by, deleted,
                    toString(created_at) AS created_at,
                    toString(updated_at) AS updated_at,
                    if(isNull(replied_at), '', toString(assumeNotNull(replied_at))) AS replied_at,
                    if(isNull(forwarded_at), '', toString(assumeNotNull(forwarded_at))) AS forwarded_at
                 FROM ndr.support_messages FINAL
                 WHERE deleted = 0 AND (forwarded = 1 OR tenant_id = 'default')
                 ORDER BY updated_at DESC"
            )
            .fetch_all::<SupportMessageRow>()
            .await?;
        Ok(rows.into_iter().map(support_message_to_json).collect())
    }

    pub async fn get_support_message_scope(
        &self,
        id: &str,
    ) -> anyhow::Result<Option<(String, String, u8)>> {
        let rows = self.client
            .query(
                "SELECT tenant_id, sender_username, forwarded
                 FROM ndr.support_messages FINAL
                 WHERE id = ? AND deleted = 0
                 LIMIT 1"
            )
            .bind(id)
            .fetch_all::<(String, String, u8)>()
            .await?;
        Ok(rows.into_iter().next())
    }

    pub async fn update_support_status(&self, id: &str, status: &str) -> anyhow::Result<()> {
        self.client
            .query(
                "ALTER TABLE ndr.support_messages
                 UPDATE status = ?
                 WHERE id = ?
                 SETTINGS mutations_sync=1"
            )
            .bind(status)
            .bind(id)
            .execute()
            .await?;
        Ok(())
    }

    pub async fn reply_support_message(
        &self,
        id: &str,
        reply: &str,
        replied_by: &str,
        status: &str,
    ) -> anyhow::Result<()> {
        self.client
            .query(
                "ALTER TABLE ndr.support_messages
                 UPDATE admin_reply = ?, replied_by = ?, replied_at = now(),
                        status = ?
                 WHERE id = ?
                 SETTINGS mutations_sync=1"
            )
            .bind(reply)
            .bind(replied_by)
            .bind(status)
            .bind(id)
            .execute()
            .await?;
        Ok(())
    }

    pub async fn forward_support_message(&self, id: &str, forwarded_by: &str) -> anyhow::Result<()> {
        self.client
            .query(
                "ALTER TABLE ndr.support_messages
                 UPDATE forwarded = 1, forwarded_by = ?, forwarded_at = now(),
                        status = 'forwarded'
                 WHERE id = ?
                 SETTINGS mutations_sync=1"
            )
            .bind(forwarded_by)
            .bind(id)
            .execute()
            .await?;
        Ok(())
    }

    pub async fn delete_support_message(&self, id: &str) -> anyhow::Result<()> {
        self.client
            .query(
                "ALTER TABLE ndr.support_messages
                 UPDATE deleted = 1, status = 'deleted'
                 WHERE id = ?
                 SETTINGS mutations_sync=1"
            )
            .bind(id)
            .execute()
            .await?;
        Ok(())
    }

    pub async fn get_native_playbooks(&self, tenant_id: &str) -> anyhow::Result<Vec<crate::soar::SoarNativePlaybook>> {
        let db = tenant_db(tenant_id);
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct PlaybookRow {
            id: String,
            name: String,
            description: String,
            enabled: u8,
            cond_field: String,
            cond_op: String,
            cond_value: String,
            action_type: String,
            action_config: String,
            run_count: u64,
            last_run_ts: Option<u32>,
            created_at_ts: u32,
            updated_at_ts: u32,
        }
        let result = self.client
            .query(&format!("SELECT id, name, description, enabled, cond_field, cond_op, cond_value, action_type, action_config, run_count, toUnixTimestamp(last_run) as last_run_ts, toUnixTimestamp(created_at) as created_at_ts, toUnixTimestamp(updated_at) as updated_at_ts FROM {}.soar_native_playbooks FINAL", db))
            .fetch_all::<PlaybookRow>()
            .await?;
        let tid = tenant_id.to_string();
        Ok(result.into_iter().map(|r| crate::soar::SoarNativePlaybook {
            id: r.id,
            name: r.name,
            description: r.description,
            enabled: r.enabled,
            cond_field: r.cond_field,
            cond_op: r.cond_op,
            cond_value: r.cond_value,
            action_type: r.action_type,
            action_config: r.action_config,
            run_count: r.run_count,
            last_run: r.last_run_ts.map(|t| t.to_string()),
            created_at: r.created_at_ts.to_string(),
            updated_at: r.updated_at_ts.to_string(),
            tenant_id: tid.clone(),
        }).collect())
    }

    pub async fn insert_soar_case(
        &self,
        id: &str,
        title: &str,
        description: &str,
        severity: &str,
        status: &str,
        src_ip: &str,
        dst_ip: &str,
        community_id: &str,
        tags: &[String],
        tenant_id: &str,
    ) -> anyhow::Result<()> {
        let db = tenant_db(tenant_id);
        let tags_str = sql_array_literal(tags);
        let query = format!(
            "INSERT INTO {}.soar_cases \
             (id, title, description, severity, status, src_ip, dst_ip, community_id, tags, tenant_id) \
             VALUES ('{}','{}','{}','{}','{}','{}','{}','{}',{},'{}')",
            db,
            sql_escape(id), sql_escape(title), sql_escape(description), sql_escape(severity),
            sql_escape(status), sql_escape(src_ip), sql_escape(dst_ip), sql_escape(community_id),
            tags_str, sql_escape(tenant_id)
        );
        self.client.query(&query).execute().await?;
        Ok(())
    }

    pub async fn insert_soar_playbook_run(
        &self,
        run: &crate::soar::SoarPlaybookRun,
    ) -> anyhow::Result<()> {
        let db = tenant_db(&run.tenant_id);
        let query = format!(
            "INSERT INTO {}.soar_playbook_runs \
             (id, playbook_id, playbook_name, hit_id, status, detail, tenant_id) \
             VALUES ('{}','{}','{}','{}','{}','{}','{}')",
            db,
            sql_escape(&run.id), sql_escape(&run.playbook_id), sql_escape(&run.playbook_name),
            sql_escape(&run.hit_id), sql_escape(&run.status), sql_escape(&run.detail),
            sql_escape(&run.tenant_id)
        );
        self.client.query(&query).execute().await?;

        let update = format!(
            "ALTER TABLE {}.soar_native_playbooks \
             UPDATE run_count = run_count + 1, last_run = now() \
             WHERE id = '{}'",
            db, sql_escape(&run.playbook_id)
        );
        let _ = self.client.query(&update).execute().await;
        Ok(())
    }

    pub async fn get_soar_cases(&self, tenant_id: &str) -> anyhow::Result<Vec<serde_json::Value>> {
        let db = tenant_db(tenant_id);
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct CaseRow {
            id: String,
            title: String,
            description: String,
            severity: String,
            status: String,
            assigned_to: String,
            src_ip: String,
            dst_ip: String,
            community_id: String,
            tags: Vec<String>,
            created_at_ts: u32,
            updated_at_ts: u32,
            closed_at_ts: Option<u32>,
        }
        let result = self.client
            .query(&format!("SELECT id, title, description, severity, status, assigned_to, src_ip, dst_ip, community_id, tags, toUnixTimestamp(created_at) as created_at_ts, toUnixTimestamp(updated_at) as updated_at_ts, toUnixTimestamp(closed_at) as closed_at_ts FROM {}.soar_cases FINAL ORDER BY created_at DESC", db))
            .fetch_all::<CaseRow>()
            .await?;
        Ok(result.into_iter().map(|r| json!({
            "id": r.id, "title": r.title, "description": r.description, "severity": r.severity,
            "status": r.status, "assigned_to": r.assigned_to, "src_ip": r.src_ip, "dst_ip": r.dst_ip,
            "community_id": r.community_id, "tags": r.tags, "created_at": r.created_at_ts,
            "updated_at": r.updated_at_ts, "closed_at": r.closed_at_ts
        })).collect())
    }

    pub async fn update_soar_case_status(&self, id: &str, status: &str, tenant_id: &str) -> anyhow::Result<()> {
        let db = tenant_db(tenant_id);
        let closed_at = if status == "Resolved" || status == "False Positive" { "now()" } else { "NULL" };
        let query = format!(
            "ALTER TABLE {}.soar_cases UPDATE status = '{}', updated_at = now(), closed_at = {} WHERE id = '{}' SETTINGS mutations_sync=1",
            db, sql_escape(status), closed_at, sql_escape(id)
        );
        self.client.query(&query).execute().await?;
        Ok(())
    }

    pub async fn get_soar_case_comments(&self, case_id: &str, tenant_id: &str) -> anyhow::Result<Vec<serde_json::Value>> {
        let db = tenant_db(tenant_id);
        let result = self.client
            .query(&format!("SELECT id, case_id, author, comment, toUnixTimestamp(created_at) FROM {}.soar_case_comments WHERE case_id = ? ORDER BY created_at ASC", db))
            .bind(case_id)
            .fetch_all::<(String, String, String, String, u32)>()
            .await?;
        Ok(result.into_iter().map(|r| json!({
            "id": r.0, "case_id": r.1, "author": r.2, "comment": r.3, "created_at": r.4
        })).collect())
    }

    pub async fn insert_soar_case_comment(&self, case_id: &str, author: &str, comment: &str, tenant_id: &str) -> anyhow::Result<()> {
        let db = tenant_db(tenant_id);
        let id = uuid::Uuid::new_v4().to_string();
        let query = format!(
            "INSERT INTO {}.soar_case_comments (id, case_id, author, comment, tenant_id) VALUES ('{}','{}','{}','{}','{}')",
            db, sql_escape(&id), sql_escape(case_id), sql_escape(author), sql_escape(comment), sql_escape(tenant_id)
        );
        self.client.query(&query).execute().await?;
        Ok(())
    }

    pub async fn insert_native_playbook(&self, pb: &crate::soar::SoarNativePlaybook) -> anyhow::Result<()> {
        let db = tenant_db(&pb.tenant_id);
        let query = format!(
            "INSERT INTO {}.soar_native_playbooks (id, name, description, enabled, cond_field, cond_op, cond_value, action_type, action_config, tenant_id) VALUES ('{}','{}','{}',{},'{}','{}','{}','{}','{}','{}')",
            db,
            sql_escape(&pb.id), sql_escape(&pb.name), sql_escape(&pb.description), pb.enabled,
            sql_escape(&pb.cond_field), sql_escape(&pb.cond_op), sql_escape(&pb.cond_value),
            sql_escape(&pb.action_type), sql_escape(&pb.action_config), sql_escape(&pb.tenant_id)
        );
        self.client.query(&query).execute().await?;
        Ok(())
    }

    pub async fn update_native_playbook(&self, id: &str, name: &str, description: &str, enabled: u8, cond_field: &str, cond_op: &str, cond_value: &str, action_type: &str, action_config: &str, tenant_id: &str) -> anyhow::Result<()> {
        let db = tenant_db(tenant_id);
        // INSERT SELECT preserves run_count/last_run/created_at and sets updated_at = now().
        // ReplacingMergeTree deduplicates on next merge keeping the latest updated_at row.
        // This avoids "Cannot UPDATE key column `updated_at`" from ALTER TABLE UPDATE.
        let query = format!(
            "INSERT INTO {db}.soar_native_playbooks \
             (id, name, description, enabled, cond_field, cond_op, cond_value, \
              action_type, action_config, run_count, last_run, created_at, updated_at, tenant_id) \
             SELECT id, '{name}', '{desc}', {enabled}, '{cf}', '{co}', '{cv}', '{at}', '{ac}', \
                    run_count, last_run, created_at, now(), tenant_id \
             FROM {db}.soar_native_playbooks FINAL \
             WHERE id = '{id}' AND tenant_id = '{tid}'",
            db  = db,
            name = sql_escape(name),
            desc = sql_escape(description),
            enabled = enabled,
            cf  = sql_escape(cond_field),
            co  = sql_escape(cond_op),
            cv  = sql_escape(cond_value),
            at  = sql_escape(action_type),
            ac  = sql_escape(action_config),
            id  = sql_escape(id),
            tid = sql_escape(tenant_id),
        );
        self.client.query(&query).execute().await?;
        Ok(())
    }

    pub async fn delete_native_playbook(&self, id: &str, tenant_id: &str) -> anyhow::Result<()> {
        let db = tenant_db(tenant_id);
        let query = format!(
            "ALTER TABLE {}.soar_native_playbooks DELETE WHERE id = '{}' SETTINGS mutations_sync=1",
            db, sql_escape(id)
        );
        self.client.query(&query).execute().await?;
        Ok(())
    }

    pub async fn get_soar_playbook_runs(&self, tenant_id: &str) -> anyhow::Result<Vec<serde_json::Value>> {
        let db = tenant_db(tenant_id);
        let result = self.client
            .query(&format!("SELECT id, playbook_id, playbook_name, hit_id, status, detail, toUnixTimestamp(created_at) FROM {}.soar_playbook_runs ORDER BY created_at DESC LIMIT 100", db))
            .fetch_all::<(String, String, String, String, String, String, u32)>()
            .await?;
        Ok(result.into_iter().map(|r| json!({
            "id": r.0, "playbook_id": r.1, "playbook_name": r.2, "hit_id": r.3,
            "status": r.4, "detail": r.5, "created_at": r.6
        })).collect())
    }





// ---- EVIDENCE LOG ----

pub async fn log_evidence_action(
    &self,
    tenant_id: &str,
    community_id: &str,
    bundle_id: &str,
    action: &str,
    performed_by: &str,
    severity: &str,
    src_ip: &str,
    dst_ip: &str,
    notes: &str,
    requester_ip: &str,
) -> anyhow::Result<()> {
    let db = tenant_db(tenant_id);
    self.client.query(&format!(
        "INSERT INTO {}.evidence_log
         (community_id,bundle_id,action,performed_by,
          severity,src_ip,dst_ip,notes,ip_address)
         VALUES ('{}','{}','{}','{}','{}','{}','{}','{}','{}')",
        db, community_id, bundle_id, action,
        performed_by, severity, src_ip, dst_ip,
        notes, requester_ip
    )).execute().await?;
    Ok(())
}

pub async fn get_evidence_log(
    &self,
    tenant_id: &str,
    community_id: &str,
) -> anyhow::Result<Vec<serde_json::Value>> {
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct EvidenceLogRow {
        id:           String,
        community_id: String,
        bundle_id:    String,
        action:       String,
        performed_by: String,
        performed_at: String,
        severity:     String,
        src_ip:       String,
        dst_ip:       String,
        notes:        String,
        ip_address:   String,
    }
    let db = tenant_db(tenant_id);
    let rows = self.client.query(&format!(
        "SELECT id, community_id, bundle_id, action,
         performed_by, toString(performed_at) as performed_at,
         severity, src_ip, dst_ip, notes, ip_address
         FROM {}.evidence_log
         WHERE community_id = '{}'
         ORDER BY performed_at DESC",
        db, community_id
    )).fetch_all::<EvidenceLogRow>().await?;
    Ok(rows.iter().map(|r| serde_json::json!({
        "id": r.id, "community_id": r.community_id, "bundle_id": r.bundle_id,
        "action": r.action, "performed_by": r.performed_by,
        "performed_at": r.performed_at, "severity": r.severity,
        "src_ip": r.src_ip, "dst_ip": r.dst_ip,
        "notes": r.notes, "ip_address": r.ip_address
    })).collect())
}

// ---- EVIDENCE BUNDLES ----

pub async fn save_evidence_bundle(
    &self,
    tenant_id: &str,
    id: &str,
    community_id: &str,
    file_path: &str,
    sha256: &str,
    size_bytes: u64,
    auto_captured: u8,
    expires_days: u32,
    src_ip: &str,
    dst_ip: &str,
    severity: &str,
    alert_id: &str,
) -> anyhow::Result<()> {
    let db = tenant_db(tenant_id);

    // Skip insert if a bundle already exists for this community_id — prevents
    // duplicate entries when the same alert is downloaded more than once.
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct Count { n: u64 }
    let existing: Vec<Count> = self.client
        .query(&format!(
            "SELECT count() as n FROM {}.evidence_bundles FINAL \
             WHERE community_id = '{}'",
            db, community_id
        ))
        .fetch_all::<Count>()
        .await
        .unwrap_or_default();
    if existing.first().map(|r| r.n).unwrap_or(0) > 0 {
        return Ok(());
    }

    self.client.query(&format!(
        "INSERT INTO {}.evidence_bundles
         (id,community_id,file_path,sha256,size_bytes,
          auto_captured,expires_at,src_ip,dst_ip,
          severity,alert_id)
         VALUES ('{}','{}','{}','{}',{},
          {},now() + INTERVAL {} DAY,'{}','{}','{}','{}')",
        db, id, community_id, file_path, sha256,
        size_bytes, auto_captured, expires_days,
        src_ip, dst_ip, severity, alert_id
    )).execute().await?;
    Ok(())
}

pub async fn get_evidence_bundle(
    &self,
    tenant_id: &str,
    bundle_id: &str,
) -> anyhow::Result<Option<serde_json::Value>> {
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct EvidenceBundleRow {
        id:             String,
        community_id:   String,
        file_path:      String,
        sha256:         String,
        size_bytes:     u64,
        auto_captured:  u8,
        captured_at:    String,
        expires_at:     String,
        status:         String,
        legal_hold:     u8,
        hold_reason:    String,
        src_ip:         String,
        dst_ip:         String,
        severity:       String,
    }
    let db = tenant_db(tenant_id);
    let rows = self.client.query(&format!(
        "SELECT id, community_id, file_path, sha256,
         size_bytes, auto_captured,
         formatDateTime(captured_at, '%Y-%m-%dT%H:%i:%SZ') as captured_at,
         formatDateTime(expires_at, '%Y-%m-%dT%H:%i:%SZ') as expires_at,
         status, legal_hold, hold_reason,
         src_ip, dst_ip, severity
         FROM {}.evidence_bundles FINAL
         WHERE id = '{}' LIMIT 1",
        db, bundle_id
    )).fetch_all::<EvidenceBundleRow>().await?;
    Ok(rows.first().map(|r| serde_json::json!({
        "id": r.id, "community_id": r.community_id, "file_path": r.file_path,
        "sha256": r.sha256, "size_bytes": r.size_bytes,
        "auto_captured": r.auto_captured == 1,
        "captured_at": r.captured_at, "expires_at": r.expires_at,
        "status": r.status, "legal_hold": r.legal_hold == 1,
        "hold_reason": r.hold_reason,
        "src_ip": r.src_ip, "dst_ip": r.dst_ip, "severity": r.severity
    })))
}

pub async fn list_evidence_bundles(
    &self,
    tenant_id: &str,
    limit: u32,
) -> anyhow::Result<Vec<serde_json::Value>> {
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct EvidenceBundleListRow {
        id:            String,
        community_id:  String,
        sha256:        String,
        size_bytes:    u64,
        auto_captured: u8,
        captured_at:   String,
        expires_at:    String,
        status:        String,
        legal_hold:    u8,
        src_ip:        String,
        dst_ip:        String,
        severity:      String,
    }
    let db = tenant_db(tenant_id);
    let rows = self.client.query(&format!(
        "SELECT id, community_id, sha256, size_bytes,
         auto_captured,
         formatDateTime(captured_at, '%Y-%m-%dT%H:%i:%SZ') as captured_at,
         formatDateTime(expires_at, '%Y-%m-%dT%H:%i:%SZ') as expires_at,
         status, legal_hold, src_ip, dst_ip, severity
         FROM {}.evidence_bundles FINAL
         ORDER BY captured_at DESC LIMIT {}",
        db, limit
    )).fetch_all::<EvidenceBundleListRow>().await?;
    Ok(rows.iter().map(|r| serde_json::json!({
        "id": r.id, "community_id": r.community_id, "sha256": r.sha256,
        "size_bytes": r.size_bytes, "auto_captured": r.auto_captured == 1,
        "captured_at": r.captured_at, "expires_at": r.expires_at,
        "status": r.status, "legal_hold": r.legal_hold == 1,
        "src_ip": r.src_ip, "dst_ip": r.dst_ip, "severity": r.severity
    })).collect())
}

pub async fn set_legal_hold(
    &self,
    tenant_id: &str,
    bundle_id: &str,
    hold: u8,
    reason: &str,
    set_by: &str,
) -> anyhow::Result<()> {
    let db = tenant_db(tenant_id);
    self.client.query(&format!(
        "ALTER TABLE {}.evidence_bundles
         UPDATE legal_hold={}, hold_reason='{}',
         hold_set_by='{}'
         WHERE id='{}'",
        db, hold, reason, set_by, bundle_id
    )).execute().await?;
    Ok(())
}

pub async fn add_evidence_annotation(
    &self,
    tenant_id: &str,
    bundle_id: &str,
    community_id: &str,
    author: &str,
    note: &str,
    tag: &str,
) -> anyhow::Result<()> {
    let db = tenant_db(tenant_id);
    self.client.query(&format!(
        "INSERT INTO {}.evidence_annotations
         (bundle_id,community_id,author,note,tag)
         VALUES ('{}','{}','{}','{}','{}')",
        db, bundle_id, community_id, author, note, tag
    )).execute().await?;
    Ok(())
}

pub async fn get_annotations(
    &self,
    tenant_id: &str,
    bundle_id: &str,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let db = tenant_db(tenant_id);
    let rows = self.client.query(&format!(
        "SELECT id, author, note, tag,
         toString(created_at) as created_at
         FROM {}.evidence_annotations
         WHERE bundle_id='{}'
         ORDER BY created_at DESC",
        db, bundle_id
    )).fetch_all::<(String,String,String,String,String)>().await?;
    Ok(rows.iter().map(|r| serde_json::json!({
        "id": r.0, "author": r.1, "note": r.2,
        "tag": r.3, "created_at": r.4
    })).collect())
}

pub async fn get_all_ai_annotations(
    &self,
    tenant_id: &str,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let db = tenant_db(tenant_id);
    let rows = self.client.query(&format!(
        "SELECT ea.id, ea.bundle_id, ea.community_id, ea.author, ea.note,
         toString(ea.created_at) as created_at,
         eb.severity, eb.src_ip, eb.dst_ip
         FROM {db}.evidence_annotations ea
         LEFT JOIN {db}.evidence_bundles eb ON ea.bundle_id = eb.id
         WHERE ea.tag = 'ai_analysis'
         ORDER BY ea.created_at DESC LIMIT 200",
        db = db
    )).fetch_all::<(String,String,String,String,String,String,String,String,String)>().await.unwrap_or_default();
    Ok(rows.iter().map(|r| serde_json::json!({
        "id": r.0, "bundle_id": r.1, "community_id": r.2,
        "author": r.3, "analysis": r.4, "created_at": r.5,
        "severity": r.6, "src_ip": r.7, "dst_ip": r.8
    })).collect())
}

// ---- SHARED IOCs ----

pub async fn upsert_shared_ioc(
    &self,
    ioc_value: &str,
    ioc_type: &str,
    confidence: u8,
    tenant_hash: &str,
    tags: &str,
    description: &str,
) -> anyhow::Result<()> {
    self.client.query(&format!(
        "INSERT INTO ndr.shared_iocs
         (ioc_value,ioc_type,confidence,
          tenant_hash,tags,description)
         VALUES ('{}','{}',{},'{}','{}','{}')",
        ioc_value, ioc_type, confidence,
        tenant_hash, tags, description
    )).execute().await?;
    Ok(())
}

pub async fn check_shared_ioc(
    &self,
    ioc_value: &str,
) -> anyhow::Result<Option<serde_json::Value>> {
    let rows = self.client.query(&format!(
        "SELECT ioc_value, ioc_type, confidence,
         toString(first_seen) as first_seen,
         toString(last_seen) as last_seen,
         tags, description
         FROM ndr.shared_iocs FINAL
         WHERE ioc_value='{}' LIMIT 1",
        ioc_value
    )).fetch_all::<(String,String,u8,String,
        String,String,String)>().await?;
    Ok(rows.first().map(|r| serde_json::json!({
        "ioc_value": r.0, "ioc_type": r.1,
        "confidence": r.2, "first_seen": r.3,
        "last_seen": r.4, "tags": r.5,
        "description": r.6
    })))
}



pub async fn get_hit_by_community_id(
    &self,
    tenant_id: &str,
    community_id: &str,
) -> anyhow::Result<Option<serde_json::Value>> {
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct HitRow {
        community_id: String,
        src_ip:       String,
        dst_ip:       String,
        timestamp:    String,
        severity:     String,
    }
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct EventRow {
        src_port: u16,
        dst_port: u16,
        proto:    String,
    }
    let db = tenant_db(tenant_id);
    let hits = self.client.query(&format!(
        "SELECT community_id, src_ip, dst_ip,
         formatDateTime(toDateTime(timestamp), '%Y-%m-%dT%H:%i:%SZ') as timestamp, severity
         FROM {}.ndr_hits
         WHERE community_id = '{}'
         ORDER BY timestamp DESC LIMIT 1",
        db, community_id
    )).fetch_all::<HitRow>().await?;

    let Some(hit) = hits.first() else { return Ok(None); };

    // Pull ports and proto from ndr_events (ndr_hits doesn't store them)
    let events = self.client.query(&format!(
        "SELECT src_port, dst_port, proto
         FROM {}.ndr_events
         WHERE community_id = '{}' AND src_port > 0
         ORDER BY timestamp DESC LIMIT 1",
        db, community_id
    )).fetch_all::<EventRow>().await.unwrap_or_default();
    let (src_port, dst_port, proto) = events.first()
        .map(|e| (e.src_port, e.dst_port, e.proto.clone()))
        .unwrap_or((0, 0, "tcp".to_string()));

    Ok(Some(serde_json::json!({
        "community_id": hit.community_id,
        "src_ip":       hit.src_ip,
        "dst_ip":       hit.dst_ip,
        "src_port":     src_port,
        "dst_port":     dst_port,
        "proto":        proto,
        "timestamp":    hit.timestamp,
        "severity":     hit.severity,
    })))
}

pub async fn get_related_hits_by_ip(
    &self,
    tenant_id: &str,
    src_ip: &str,
    around_time: &str,
    window_minutes: i64,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let db = tenant_db(tenant_id);
    let rows = self.client.query(&format!(
        "SELECT community_id, src_ip, dst_ip,
         formatDateTime(toDateTime(timestamp), '%Y-%m-%dT%H:%i:%SZ') as timestamp,
         severity, rule_name
         FROM {}.ndr_hits
         WHERE src_ip = '{}'
         AND timestamp BETWEEN
             toDateTime('{}') - INTERVAL {} MINUTE
             AND toDateTime('{}') + INTERVAL {} MINUTE
         ORDER BY timestamp ASC
         LIMIT 20",
        db, src_ip, around_time, window_minutes,
        around_time, window_minutes
    )).fetch_all::<(String,String,String,String,String,String)>()
    .await?;
    Ok(rows.iter().map(|r| serde_json::json!({
        "community_id": r.0, "src_ip": r.1, "dst_ip": r.2,
        "timestamp": r.3, "severity": r.4, "rule_name": r.5
    })).collect())
}

pub async fn get_pcap_file_path_by_community_id(
    &self,
    tenant_id: &str,
    community_id: &str,
) -> anyhow::Result<Option<String>> {
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct PcapPathRow {
        file_path: String,
    }
    let db = tenant_db(tenant_id);
    let rows = self.client.query(&format!(
        "SELECT file_path FROM {}.pcap_sessions
         WHERE community_id = '{}'
         AND file_path != ''
         ORDER BY start_time DESC LIMIT 1",
        db, community_id
    )).fetch_all::<PcapPathRow>().await?;
    Ok(rows.first().map(|r| r.file_path.clone()).filter(|s| !s.is_empty()))
}


/// Get recent hits for ARIA context
pub async fn get_recent_hits_for_aria(
    &self,
    tenant_id: &str,
    limit: u32,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let db = tenant_db(tenant_id);
    // Use a struct to avoid tuple field limit
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct HitRow {
        community_id: String,
        src_ip: String,
        dst_ip: String,
        severity: String,
        score: f64,
        tags: String,
        timestamp: String,
    }
    let rows = self.client.query(&format!(
        "SELECT community_id, src_ip, dst_ip,
         severity, score, tags,
         formatDateTime(toDateTime(timestamp), '%Y-%m-%dT%H:%i:%SZ') as timestamp
         FROM {}.ndr_hits
         ORDER BY timestamp DESC LIMIT {}",
        db, limit
    )).fetch_all::<HitRow>().await?;

    Ok(rows.iter().map(|r| serde_json::json!({
        "community_id": r.community_id,
        "src_ip": r.src_ip,
        "dst_ip": r.dst_ip,
        "severity": r.severity,
        "score": r.score,
        "tags": r.tags,
        "timestamp": r.timestamp
    })).collect())
}

/// Count hits by severity last 24h
pub async fn count_hits_by_severity_aria(
    &self,
    tenant_id: &str,
    severity: &str,
) -> anyhow::Result<u64> {
    let db = tenant_db(tenant_id);
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct CountRow { cnt: u64 }
    let rows = self.client.query(&format!(
        "SELECT count() as cnt
         FROM {}.ndr_hits
         WHERE severity = '{}'
         AND timestamp >= now() - INTERVAL 24 HOUR",
        db, severity
    )).fetch_all::<CountRow>().await?;
    Ok(rows.first().map(|r| r.cnt).unwrap_or(0))
}

/// Count evidence bundles for tenant
pub async fn count_evidence_bundles_aria(
    &self,
    tenant_id: &str,
) -> anyhow::Result<u64> {
    let db = tenant_db(tenant_id);
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct CountRow { cnt: u64 }
    let rows = self.client.query(&format!(
        "SELECT count() as cnt
         FROM {}.evidence_bundles",
        db
    )).fetch_all::<CountRow>().await?;
    Ok(rows.first().map(|r| r.cnt).unwrap_or(0))
}

/// Write a permanent IOC hit record — immutable, never updated or deleted.
/// Called at detection time so the match is preserved even if the feed changes later.
pub async fn write_ioc_hit(
    &self,
    tenant_id: &str,
    community_id: &str,
    src_ip: &str,
    dst_ip: &str,
    matched_ip: &str,
    feed_source: &str,
) -> anyhow::Result<()> {
    let db = tenant_db(tenant_id);
    self.client.query(&format!(
        "INSERT INTO {}.ioc_hits \
         (timestamp, community_id, src_ip, dst_ip, matched_ip, ioc_type, feed_source) \
         VALUES (now(), '{}', '{}', '{}', '{}', 'ip', '{}')",
        db,
        community_id.replace('\'', "\\'"),
        src_ip.replace('\'', "\\'"),
        dst_ip.replace('\'', "\\'"),
        matched_ip.replace('\'', "\\'"),
        feed_source.replace('\'', "\\'"),
    )).execute().await?;
    Ok(())
}

/// Query permanent IOC hits for a community_id (for evidence investigation).
pub async fn get_ioc_hits(
    &self,
    tenant_id: &str,
    community_id: &str,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let db = tenant_db(tenant_id);
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct IocHitRow {
        timestamp:    String,
        community_id: String,
        src_ip:       String,
        dst_ip:       String,
        matched_ip:   String,
        ioc_type:     String,
        feed_source:  String,
    }
    let rows = self.client.query(&format!(
        "SELECT formatDateTime(toDateTime(timestamp), '%Y-%m-%dT%H:%i:%SZ') as timestamp, community_id, \
         src_ip, dst_ip, matched_ip, ioc_type, feed_source \
         FROM {}.ioc_hits \
         WHERE community_id = '{}' \
         ORDER BY timestamp ASC",
        db,
        community_id.replace('\'', "\\'"),
    ))
    .fetch_all::<IocHitRow>().await.unwrap_or_default();

    Ok(rows.into_iter().map(|r| serde_json::json!({
        "timestamp":    r.timestamp,
        "community_id": r.community_id,
        "src_ip":       r.src_ip,
        "dst_ip":       r.dst_ip,
        "matched_ip":   r.matched_ip,
        "ioc_type":     r.ioc_type,
        "feed_source":  r.feed_source,
    })).collect())
}

    // ── Asset Management ──────────────────────────────────────────────────────

    pub async fn upsert_asset(&self, asset: &AssetRow) -> anyhow::Result<()> {
        let db = tenant_db(&asset.tenant_id);
        let safe_history = sql_escape(&asset.ip_history);
        let query = format!(
            "INSERT INTO {}.assets (ip, mac, hostname, vendor, os_guess, device_type, custom_name, tenant_id, first_seen, last_seen, ip_history) \
             VALUES ('{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', toDateTime({}), toDateTime({}), '{}')",
            db,
            sql_escape(&asset.ip), sql_escape(&asset.mac), sql_escape(&asset.hostname),
            sql_escape(&asset.vendor), sql_escape(&asset.os_guess), sql_escape(&asset.device_type),
            sql_escape(&asset.custom_name), sql_escape(&asset.tenant_id),
            asset.first_seen, asset.last_seen,
            safe_history
        );
        self.client.query(&query).execute().await?;
        Ok(())
    }

    pub async fn update_asset_os(&self, ip: &str, os_name: &str, tenant_id: &str) -> anyhow::Result<()> {
        let db = tenant_db(tenant_id);
        let query = format!(
            "ALTER TABLE {}.assets UPDATE os_guess = '{}' WHERE tenant_id = '{}' AND ip = '{}'",
            db, sql_escape(os_name), sql_escape(tenant_id), sql_escape(ip)
        );
        self.client.query(&query).execute().await?;
        Ok(())
    }

    pub async fn get_assets_by_tenant(&self, tenant_id: &str) -> anyhow::Result<Vec<AssetRow>> {
        let db = tenant_db(tenant_id);
        let query = format!(
            "SELECT ip, mac, hostname, vendor, os_guess, device_type, custom_name, tenant_id, \
             toUnixTimestamp(first_seen) as first_seen, toUnixTimestamp(last_seen) as last_seen, ip_history \
             FROM {}.assets FINAL WHERE tenant_id = '{}' ORDER BY ip",
            db, sql_escape(tenant_id)
        );
        let rows = self.client.query(&query).fetch_all::<AssetRow>().await?;
        Ok(rows)
    }

    pub async fn get_asset_by_mac(&self, tenant_id: &str, mac: &str) -> anyhow::Result<Option<AssetRow>> {
        if mac.is_empty() { return Ok(None); }
        let db = tenant_db(tenant_id);
        let query = format!(
            "SELECT ip, mac, hostname, vendor, os_guess, device_type, custom_name, tenant_id, \
             toUnixTimestamp(first_seen) as first_seen, toUnixTimestamp(last_seen) as last_seen, ip_history \
             FROM {}.assets FINAL WHERE tenant_id = '{}' AND mac = '{}' ORDER BY last_seen DESC LIMIT 1",
            db, sql_escape(tenant_id), sql_escape(mac)
        );
        let result = self.client.query(&query).fetch_optional::<AssetRow>().await?;
        Ok(result)
    }

    pub async fn get_assets_with_counts_by_tenant(&self, tenant_id: &str) -> anyhow::Result<Vec<serde_json::Value>> {
        let db = tenant_db(tenant_id);
        let assets = self.get_assets_by_tenant(tenant_id).await?;

        let q_conns = format!(
            "SELECT arrayJoin([src_ip, dst_ip]) as ip, count() as c \
             FROM {}.ndr_events WHERE tenant_id = '{}' AND timestamp > now() - INTERVAL 1 DAY GROUP BY ip",
            db, sql_escape(tenant_id)
        );
        let conns: Vec<(String, u64)> = self.client.query(&q_conns).fetch_all().await.unwrap_or_default();
        let mut conn_map = std::collections::HashMap::new();
        for (ip, c) in conns { conn_map.insert(ip, c); }

        let q_hits = format!(
            "SELECT arrayJoin([src_ip, dst_ip]) as ip, count() as c \
             FROM {}.ndr_hits WHERE tenant_id = '{}' AND timestamp > now() - INTERVAL 1 DAY GROUP BY ip",
            db, sql_escape(tenant_id)
        );
        let hits: Vec<(String, u64)> = self.client.query(&q_hits).fetch_all().await.unwrap_or_default();
        let mut hit_map = std::collections::HashMap::new();
        for (ip, c) in hits { hit_map.insert(ip, c); }

        let mut result = Vec::new();
        for a in assets {
            let mut val = serde_json::to_value(&a).unwrap();
            if let Some(obj) = val.as_object_mut() {
                obj.insert("connections_24h".into(), serde_json::json!(conn_map.get(&a.ip).unwrap_or(&0)));
                obj.insert("alerts_24h".into(),      serde_json::json!(hit_map.get(&a.ip).unwrap_or(&0)));
            }
            result.push(val);
        }
        Ok(result)
    }

    pub async fn get_asset_by_ip(&self, tenant_id: &str, ip: &str) -> anyhow::Result<Option<AssetRow>> {
        let db = tenant_db(tenant_id);
        let query = format!(
            "SELECT ip, mac, hostname, vendor, os_guess, device_type, custom_name, tenant_id, \
             toUnixTimestamp(first_seen) as first_seen, toUnixTimestamp(last_seen) as last_seen, ip_history \
             FROM {}.assets FINAL WHERE tenant_id = '{}' AND ip = '{}'",
            db, sql_escape(tenant_id), sql_escape(ip)
        );
        let asset = self.client.query(&query).fetch_optional::<AssetRow>().await?;
        Ok(asset)
    }

    pub async fn update_asset_name(&self, tenant_id: &str, ip: &str, custom_name: &str) -> anyhow::Result<()> {
        let db = tenant_db(tenant_id);
        let query = format!(
            "ALTER TABLE {}.assets UPDATE custom_name = '{}', last_seen = now() \
             WHERE tenant_id = '{}' AND ip = '{}' SETTINGS mutations_sync=1",
            db, sql_escape(custom_name), sql_escape(tenant_id), sql_escape(ip)
        );
        self.client.query(&query).execute().await?;
        Ok(())
    }

}
