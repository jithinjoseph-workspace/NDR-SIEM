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

pub fn default_permissions(role: &str) -> String {
  match role {
    "admin" | "super_admin" =>
      "dashboard,alerts,logs,live,rules,soar,network-map,intel,settings,health,users,setup",
    "tenant_admin" =>
      "dashboard,alerts,logs,live,rules,soar,network-map,intel,health,users",
    "analyst" =>
      "dashboard,alerts,logs,live,network-map,intel,health",
    _ => "dashboard,alerts,health",
  }.to_string()
}

#[allow(dead_code)]
impl ClickhouseStorage {


// ── User auth ─────────────────────────────────
pub async fn verify_user(
    &self,
    username: &str,
    password: &str,
) -> anyhow::Result<Option<serde_json::Value>> {
    let query = format!(
        "SELECT id, username, password_hash, role, tenant_id, permissions
         FROM ndr.users FINAL
         WHERE username = '{}'
         LIMIT 1",
        username
    );
    let result = self.client
        .query(&query)
        .fetch_all::<(String, String, String, String, String, String)>()
        .await?;

    if let Some(user) = result.first() {
        let hash = &user.2;
        if bcrypt::verify(password, hash)
            .unwrap_or(false) {
            return Ok(Some(serde_json::json!({
                "id":          user.0,
                "username":    user.1,
                "role":        user.3,
                "tenant_id":   user.4,
                "permissions": user.5
            })));
        }
    }
    Ok(None)
}

pub async fn create_default_admin(&self) -> anyhow::Result<()> {
    // Check if admin exists
    let count: u64 = self.client
        .query("SELECT count() FROM ndr.users WHERE username = 'admin'")
        .fetch_one::<u64>()
        .await
        .unwrap_or(0);

    if count == 0 {
        let hash = bcrypt::hash("ndr@admin123", 12)
            .unwrap_or_default();
        let perms = default_permissions("admin");
        let query = format!(
            "INSERT INTO ndr.users \
             (username, password_hash, role, tenant_id, permissions) \
             VALUES ('admin', '{}', 'admin', 'default', '{}')",
            hash, perms
        );
        self.client.query(&query).execute().await?;
        tracing::info!("✅ Default admin user created");
    }
    Ok(())
}


pub async fn get_users(
    &self
) -> anyhow::Result<Vec<serde_json::Value>> {
    let result = self.client
        .query("SELECT id, username, role, tenant_id, permissions, toString(created_at) FROM ndr.users FINAL ORDER BY created_at")
        .fetch_all::<(String,String,String,String,String,String)>()
        .await?;
    Ok(result.iter().map(|r| json!({
        "id": r.0,
        "username": r.1,
        "role": r.2,
        "tenant_id": r.3,
        "permissions": r.4,
        "created_at": r.5
    })).collect())
}

pub async fn create_user(
    &self,
    username: &str,
    password_hash: &str,
    role: &str,
    tenant_id: &str,
    permissions: &str,
) -> anyhow::Result<()> {
    let query = format!(
        "INSERT INTO ndr.users \
         (username, password_hash, role, tenant_id, permissions) \
         VALUES ('{}','{}','{}','{}','{}')",
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
    let query = format!(
        "SELECT id, username, password_hash, role, tenant_id
         FROM ndr.users FINAL
         WHERE id = '{}'
         LIMIT 1",
        id
    );
    let result = self.client
        .query(&query)
        .fetch_all::<(String, String, String, String, String)>()
        .await?;

    if let Some(user) = result.first() {
        let insert_query = format!(
            "INSERT INTO ndr.users \
             (id, username, password_hash, role, tenant_id, permissions, created_at) \
             VALUES ('{}', '{}', '{}', '{}', '{}', '{}', now() + 1)",
            user.0, user.1, user.2, user.3, user.4, permissions
        );
        self.client.query(&insert_query).execute().await?;
    }
    Ok(())
}

pub async fn delete_user(
    &self, id: &str
) -> anyhow::Result<()> {
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
    // 1. Insert into main tenants table
    let query = format!(
        "INSERT INTO ndr.tenants (id, name, active) \
         VALUES ('{}','{}',1)",
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





//threat intel hits
    pub async fn get_threat_intel_hits_by_tenant(&self, tenant_id: &str) -> anyhow::Result<Vec<serde_json::Value>> {
    let filter = format!("tenant_id='{}'", tenant_id);
    let query = format!("
        SELECT
            src_ip,
            dst_ip,
            count() as hits,
            max(timestamp) as last_seen
        FROM ndr_hits
        WHERE threat_intel = 1 AND {}
        GROUP BY src_ip, dst_ip
        ORDER BY hits DESC
        LIMIT 50
    ", filter);
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

    pub async fn insert_hit(&self, hit: NdrHit) -> anyhow::Result<()> {
        let mut insert = self.client.insert("ndr_hits")?;
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
        let result = self.client
            .query("SELECT id, content FROM ndr.sigma_rules FINAL WHERE enabled = 1 AND (tenant_id = ? OR tenant_id = 'default')")
            .bind(tenant_id)
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
        self.client
            .query("INSERT INTO ndr.sigma_rules (id, name, content, tenant_id, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, 1, now(), now())")
            .bind(id)
            .bind(name)
            .bind(content)
            .bind(tenant_id)
            .execute()
            .await?;
        Ok(())
    }

    pub async fn delete_sigma_rule(&self, id: &str, tenant_id: &str) -> anyhow::Result<()> {
        self.client
            .query("ALTER TABLE ndr.sigma_rules DELETE WHERE id = ? AND tenant_id = ?")
            .bind(id)
            .bind(tenant_id)
            .execute()
            .await?;
        Ok(())
    }

    pub async fn toggle_sigma_rule(&self, id: &str, enabled: bool, tenant_id: &str) -> anyhow::Result<()> {
        let query = if tenant_id == "default" {
            "INSERT INTO ndr.sigma_rules (id, name, content, tenant_id, enabled, updated_at) SELECT id, name, content, tenant_id, ?, now() FROM ndr.sigma_rules FINAL WHERE id = ?"
        } else {
            "INSERT INTO ndr.sigma_rules (id, name, content, tenant_id, enabled, updated_at) SELECT id, name, content, tenant_id, ?, now() FROM ndr.sigma_rules FINAL WHERE id = ? AND tenant_id = ?"
        };
        let mut q = self.client.query(query).bind(enabled as u8).bind(id);
        if tenant_id != "default" {
            q = q.bind(tenant_id);
        }
        q.execute().await?;
        Ok(())
    }

    pub async fn get_sigma_rule_by_id(&self, id: &str, tenant_id: &str) -> anyhow::Result<Option<(String, String, String, String, u8)>> {
        let result = self.client
            .query("SELECT id, name, content, tenant_id, enabled FROM ndr.sigma_rules FINAL WHERE id = ? AND (tenant_id = ? OR tenant_id = 'default') LIMIT 1")
            .bind(id)
            .bind(tenant_id)
            .fetch_all::<(String, String, String, String, u8)>()
            .await?;
        Ok(result.first().cloned())
    }

    pub async fn get_all_sigma_rules(&self, tenant_id: &str) -> anyhow::Result<Vec<(String, String, String, String, u8)>> {
        let result = self.client
            .query("SELECT id, name, content, tenant_id, enabled FROM ndr.sigma_rules FINAL WHERE tenant_id = ? OR tenant_id = 'default'")
            .bind(tenant_id)
            .fetch_all::<(String, String, String, String, u8)>()
            .await?;
        Ok(result)
    }

//soar integrations

pub async fn get_integrations_by_tenant(
    &self, tenant_id: &str
) -> anyhow::Result<Vec<serde_json::Value>> {
    let filter = format!("tenant_id='{}'", tenant_id);
    let query = format!("
        SELECT id, name, type, config, enabled
        FROM ndr.soar_integrations
        FINAL
        WHERE {}
        ORDER BY created_at
    ", filter);
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
    let query = format!(
        "INSERT INTO ndr.soar_integrations \
         (id, name, type, config, enabled, tenant_id) \
         VALUES ('{}','{}','{}','{}',1,'{}')",
        id, name, int_type,
        config.replace("'", "\\'"), tenant_id
    );
    self.client.query(&query).execute().await?;
    Ok(())
}

pub async fn toggle_integration(
    &self, id: &str, enabled: bool, tenant_id: &str
) -> anyhow::Result<()> {
    let filter = format!("tenant_id='{}'", tenant_id);
    let query = format!(
        "INSERT INTO ndr.soar_integrations \
         (id, name, type, config, enabled, tenant_id) \
         SELECT id, name, type, config, {}, tenant_id \
         FROM ndr.soar_integrations \
         WHERE id = '{}' AND {}",
        if enabled { 1 } else { 0 }, id, filter
    );
    self.client.query(&query).execute().await?;
    Ok(())
}

pub async fn delete_integration(
    &self, id: &str, tenant_id: &str
) -> anyhow::Result<()> {
    let filter = format!("tenant_id='{}'", tenant_id);
    let query = format!(
        "ALTER TABLE ndr.soar_integrations \
         DELETE WHERE id = '{}' AND {}",
        id, filter
    );
    self.client.query(&query).execute().await?;
    Ok(())
}


//save soar config
pub async fn save_soar_config_by_tenant(
    &self, key: &str, value: &str, tenant_id: &str
) -> anyhow::Result<()> {
    let query = format!(
        "INSERT INTO ndr.soar_config (key, value, tenant_id) \
         VALUES ('{}', '{}', '{}')",
        key, value, tenant_id
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
    let filter = format!("tenant_id='{}'", tenant_id);
    let query = format!("
        SELECT key, value
        FROM ndr.soar_config
        FINAL
        WHERE {}
        ORDER BY key
    ", filter);
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
    let filter = format!("tenant_id='{}'", tenant_id);
    let query = format!("
        SELECT id, name, description,
               trigger, action_type,
               config, enabled, runs
        FROM ndr.soar_playbooks
        FINAL
        WHERE {}
        ORDER BY created_at
    ", filter);
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
    let filter = format!("tenant_id='{}'", tenant_id);
    let query = format!(
        "INSERT INTO ndr.soar_playbooks \
         (id, name, description, trigger, \
          action_type, enabled, tenant_id) \
         SELECT id, name, description, trigger, \
                action_type, {}, tenant_id \
         FROM ndr.soar_playbooks \
         WHERE id = '{}' AND {}",
        if enabled { 1 } else { 0 }, id, filter
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
    let query = format!(
        "INSERT INTO ndr.soar_playbooks \
         (id, name, description, trigger, \
          action_type, config, enabled, tenant_id) \
         VALUES ('{}','{}','{}','{}','{}','{}',1,'{}')",
        id, name, description,
        trigger, action_type, config, tenant_id
    );
    self.client.query(&query).execute().await?;
    Ok(())
}


//get settings

pub async fn get_settings(&self) -> anyhow::Result<serde_json::Value> {
    let query = "
        SELECT key, value
        FROM ndr.settings
        FINAL
        ORDER BY key
    ";
    let result = self.client
        .query(query)
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

pub async fn save_setting(
    &self, key: &str, value: &str
) -> anyhow::Result<()> {
    let query = format!(
        "INSERT INTO ndr.settings (key, value) \
         VALUES ('{}', '{}')",
        key, value
    );
    self.client.query(&query).execute().await?;
    Ok(())
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
        let f = format!("tenant_id='{}'", tenant_id);
        let et: u64 = self.client.query(&format!(
            "SELECT count() FROM ndr.ndr_events WHERE {}", f))
            .fetch_one::<u64>().await.unwrap_or(0);
        let ht: u64 = self.client.query(&format!(
            "SELECT count() FROM ndr.ndr_hits WHERE {}", f))
            .fetch_one::<u64>().await.unwrap_or(0);
        let e1h: u64 = self.client.query(&format!(
            "SELECT count() FROM ndr.ndr_events WHERE {} AND timestamp > now() - INTERVAL 1 HOUR", f))
            .fetch_one::<u64>().await.unwrap_or(0);
        let h1h: u64 = self.client.query(&format!(
            "SELECT count() FROM ndr.ndr_hits WHERE {} AND timestamp > now() - INTERVAL 1 HOUR", f))
            .fetch_one::<u64>().await.unwrap_or(0);
        let zeek: u64 = self.client.query(&format!(
            "SELECT count() FROM ndr.ndr_events WHERE {} AND source='zeek'", f))
            .fetch_one::<u64>().await.unwrap_or(0);
        let suri: u64 = self.client.query(&format!(
            "SELECT count() FROM ndr.ndr_events WHERE {} AND source='suricata'", f))
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
        let f = format!("tenant_id='{}'", tenant_id);
        let rows = self.client.query(&format!(
            "SELECT src_ip,dst_ip,proto,source,severity,toString(timestamp) \
             FROM ndr.ndr_events WHERE {} \
             ORDER BY timestamp DESC LIMIT {}", f, limit))
            .fetch_all::<(String,String,String,String,String,String)>()
            .await.unwrap_or_default();
        Ok(rows.iter().map(|r| serde_json::json!({
            "src_ip":r.0,"dst_ip":r.1,"proto":r.2,
            "source":r.3,"severity":r.4,"timestamp":r.5
        })).collect())
    }

    pub async fn get_top_src_ips_by_tenant(
        &self, limit: u64, tenant_id: &str
    ) -> anyhow::Result<Vec<serde_json::Value>> {
        let f = format!("tenant_id='{}'", tenant_id);
        let rows = self.client.query(&format!(
            "SELECT src_ip, count() as cnt \
             FROM ndr.ndr_events WHERE {} \
             GROUP BY src_ip ORDER BY cnt DESC LIMIT {}", f, limit))
            .fetch_all::<(String,u64)>()
            .await.unwrap_or_default();
        Ok(rows.iter().map(|r| serde_json::json!({
            "ip":r.0,"count":r.1
        })).collect())
    }

    pub async fn get_top_dst_ips_by_tenant(
        &self, limit: u64, tenant_id: &str
    ) -> anyhow::Result<Vec<serde_json::Value>> {
        let f = format!("tenant_id='{}'", tenant_id);
        let rows = self.client.query(&format!(
            "SELECT dst_ip, count() as cnt \
             FROM ndr.ndr_events WHERE {} \
             GROUP BY dst_ip ORDER BY cnt DESC LIMIT {}", f, limit))
            .fetch_all::<(String,u64)>()
            .await.unwrap_or_default();
        Ok(rows.iter().map(|r| serde_json::json!({
            "ip":r.0,"count":r.1
        })).collect())
    }

    pub async fn get_recent_hits_by_tenant(
        &self, limit: u64, tenant_id: &str
    ) -> anyhow::Result<Vec<serde_json::Value>> {
        let f = format!("tenant_id='{}'", tenant_id);
        let rows = self.client.query(&format!(
            "SELECT src_ip,dst_ip,score,severity,toString(timestamp) \
             FROM ndr.ndr_hits WHERE {} \
             ORDER BY timestamp DESC LIMIT {}", f, limit))
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
        let f = format!("tenant_id='{}'", tenant_id);
        let critical: u64 = self.client.query(&format!(
            "SELECT count() FROM ndr.ndr_hits WHERE {} AND severity='CRITICAL'", f))
            .fetch_one::<u64>().await.unwrap_or(0);
        let high: u64 = self.client.query(&format!(
            "SELECT count() FROM ndr.ndr_hits WHERE {} AND severity='HIGH'", f))
            .fetch_one::<u64>().await.unwrap_or(0);
        let medium: u64 = self.client.query(&format!(
            "SELECT count() FROM ndr.ndr_hits WHERE {} AND severity='MEDIUM'", f))
            .fetch_one::<u64>().await.unwrap_or(0);
        let low: u64 = self.client.query(&format!(
            "SELECT count() FROM ndr.ndr_hits WHERE {} AND severity='LOW'", f))
            .fetch_one::<u64>().await.unwrap_or(0);
        Ok(serde_json::json!({
            "critical":critical,"high":high,
            "medium":medium,"low":low
        }))
    }

    pub async fn get_network_map_by_tenant(
        &self, tenant_id: &str
    ) -> anyhow::Result<serde_json::Value> {
        let f = format!("tenant_id='{}'", tenant_id);
        let pairs = self.client.query(&format!("
            SELECT src_ip, dst_ip,
                count() as connections,
                groupArray(DISTINCT proto) as protocols
            FROM ndr.ndr_events 
            WHERE {} AND src_ip != '' AND dst_ip != ''
              AND timestamp > now() - INTERVAL 1 HOUR
            GROUP BY src_ip, dst_ip
            ORDER BY connections DESC
            LIMIT 100", f))
            .fetch_all::<NetworkPair>()
            .await.unwrap_or_default();
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
        Ok(serde_json::json!({
            "nodes": nodes.values().collect::<Vec<_>>(),
            "edges": edges
        }))
    }

}