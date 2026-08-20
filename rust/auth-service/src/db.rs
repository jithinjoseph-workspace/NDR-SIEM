use anyhow::Result;
use clickhouse::Client;
use serde::Deserialize;

/// Row from the users table — column names match the real ClickHouse schema.
#[derive(Debug, Clone, Deserialize, clickhouse::Row)]
pub struct UserRow {
    pub id:            String,   // primary key
    pub username:      String,
    pub password_hash: String,
    pub role:          String,
    pub tenant_id:     String,
    pub permissions:   String,   // comma-separated page permissions
    pub active:        u8,
    pub gmail:         String,
    pub secret_code:   String,
}

pub struct AuthDb {
    client: Client,
}

impl AuthDb {
    pub async fn new(url: &str) -> Result<Self> {
        let db   = std::env::var("CLICKHOUSE_DB").unwrap_or_else(|_| "ndr".into());
        let user = std::env::var("CLICKHOUSE_USER").unwrap_or_else(|_| "ndr".into());
        let pass = std::env::var("CLICKHOUSE_PASSWORD").unwrap_or_default();
        let client = Client::default()
            .with_url(url)
            .with_database(db)
            .with_user(user)
            .with_password(pass);
        Ok(Self { client })
    }

    /// Fetch a user by username within a tenant.
    pub async fn get_user(&self, username: &str, tenant_id: &str) -> Result<Option<UserRow>> {
        let tenant_clause = if tenant_id.is_empty() {
            String::new()
        } else {
            format!("AND tenant_id = '{}'", escape(tenant_id))
        };
        let q = format!(
            "SELECT id, username, password_hash, role, tenant_id, permissions,
                    active, coalesce(gmail,'') AS gmail, coalesce(secret_code,'') AS secret_code
             FROM users
             WHERE username = '{u}'
             {tenant_clause}
             LIMIT 1",
            u = escape(username),
        );
        let mut cur = self.client.query(&q).fetch::<UserRow>()?;
        Ok(cur.next().await?)
    }

    /// Fetch a user by internal id (used in MFA second step).
    pub async fn get_user_by_id(&self, id: &str) -> Result<Option<UserRow>> {
        let q = format!(
            "SELECT id, username, password_hash, role, tenant_id, permissions,
                    active, coalesce(gmail,'') AS gmail, coalesce(secret_code,'') AS secret_code
             FROM users
             WHERE id = '{}'
             LIMIT 1",
            escape(id)
        );
        let mut cur = self.client.query(&q).fetch::<UserRow>()?;
        Ok(cur.next().await?)
    }

    /// Check whether a tenant is active.
    pub async fn is_tenant_active(&self, tenant_id: &str) -> Result<bool> {
        #[derive(Deserialize, clickhouse::Row)]
        struct Row { active: u8 }
        let q = format!(
            "SELECT active FROM tenants WHERE id = '{}' LIMIT 1",
            escape(tenant_id)
        );
        let mut cur = self.client.query(&q).fetch::<Row>()?;
        match cur.next().await? {
            Some(r) => Ok(r.active == 1),
            None    => Ok(false),
        }
    }

    /// Feature flags for a tenant — stored as JSON array in tenants.features column.
    pub async fn get_tenant_features(&self, tenant_id: &str) -> Result<Vec<String>> {
        #[derive(Deserialize, clickhouse::Row)]
        struct Row { features: String }
        let q = format!(
            "SELECT coalesce(features, '[\"ndr\"]') AS features
             FROM tenants WHERE id = '{}' LIMIT 1",
            escape(tenant_id)
        );
        let mut cur = self.client.query(&q).fetch::<Row>()?;
        if let Some(r) = cur.next().await? {
            let feats: Vec<String> = serde_json::from_str(&r.features)
                .unwrap_or_else(|_| vec!["ndr".into()]);
            return Ok(feats);
        }
        Ok(vec!["ndr".into()])
    }

    /// AI-analysis feature toggle for a tenant.
    pub async fn get_tenant_ai_enabled(&self, tenant_id: &str) -> bool {
        #[derive(Deserialize, clickhouse::Row)]
        struct Row { ai_enabled: u8 }
        let q = format!(
            "SELECT ai_enabled FROM tenants WHERE id = '{}' LIMIT 1",
            escape(tenant_id)
        );
        let Ok(mut cur) = self.client.query(&q).fetch::<Row>() else { return false };
        cur.next().await.ok().flatten().map(|r| r.ai_enabled == 1).unwrap_or(false)
    }

    /// Sensor IDs scoped to a user (empty = all sensors for the tenant).
    pub async fn get_sensor_ids(&self, user_id: &str) -> Result<Vec<String>> {
        #[derive(Deserialize, clickhouse::Row)]
        struct Row { sensor_id: String }
        let q = format!(
            "SELECT sensor_id FROM user_sensor_assignments WHERE user_id = '{}'",
            escape(user_id)
        );
        let mut cur = self.client.query(&q).fetch::<Row>()?;
        let mut ids = Vec::new();
        while let Some(r) = cur.next().await? { ids.push(r.sensor_id); }
        Ok(ids)
    }

    /// Tenant admin email for new-device notifications.
    pub async fn get_tenant_admin_email(&self, tenant_id: &str) -> Result<Option<String>> {
        #[derive(Deserialize, clickhouse::Row)]
        struct Row { gmail: String }
        let q = format!(
            "SELECT coalesce(gmail, '') AS gmail
             FROM users
             WHERE tenant_id = '{}' AND role IN ('tenant_admin','super_admin')
               AND gmail != ''
             LIMIT 1",
            escape(tenant_id)
        );
        let mut cur = self.client.query(&q).fetch::<Row>()?;
        Ok(cur.next().await?.map(|r| r.gmail).filter(|e| !e.is_empty()))
    }

    /// Update password hash (password reset).
    pub async fn set_password_hash(&self, user_id: &str, new_hash: &str) -> Result<()> {
        self.client
            .query(&format!(
                "ALTER TABLE users UPDATE password_hash = '{}' WHERE id = '{}'",
                escape(new_hash), escape(user_id)
            ))
            .execute()
            .await?;
        Ok(())
    }
}

/// Minimal SQL escape — single-quote sanitisation.
fn escape(s: &str) -> String {
    s.replace('\'', "\\'")
}
