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
    pub async fn new(_url: &str) -> Result<Self> {
        let cfg = provigil_common::clickhouse::ClickHouseConfig::from_env();
        Ok(Self { client: cfg.build_client() })
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
            "SELECT coalesce(features, 'ndr') AS features
             FROM tenants FINAL WHERE id = '{}' LIMIT 1",
            escape(tenant_id)
        );
        let mut cur = self.client.query(&q).fetch::<Row>()?;
        if let Some(r) = cur.next().await? {
            // features stored as comma-separated (e.g. "ndr,ai,soar")
            let feats: Vec<String> = r.features
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            return Ok(feats);
        }
        Ok(vec!["ndr".into()])
    }

    /// AI-analysis feature toggle for a tenant.
    pub async fn get_tenant_ai_enabled(&self, tenant_id: &str) -> bool {
        #[derive(Deserialize, clickhouse::Row)]
        struct Row { ai_enabled: u8 }
        let q = format!(
            "SELECT ai_enabled FROM tenants FINAL WHERE id = '{}' LIMIT 1",
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

    // ─────────────────────────────────────────────────────────────────────────
    // User management
    // ─────────────────────────────────────────────────────────────────────────

    pub async fn get_all_users(&self) -> Result<Vec<serde_json::Value>> {
        #[derive(Deserialize, clickhouse::Row)]
        struct Row {
            id: String, username: String, role: String,
            tenant_id: String, permissions: String, active: u8,
            gmail: String, created_at: String,
        }
        let q = "SELECT id, username, role, tenant_id, permissions, active, \
                        coalesce(gmail,'') AS gmail, toString(created_at) AS created_at \
                 FROM users ORDER BY created_at DESC";
        let mut cur = self.client.query(q).fetch::<Row>()?;
        let mut out = Vec::new();
        while let Some(r) = cur.next().await? {
            out.push(serde_json::json!({
                "id": r.id, "username": r.username, "role": r.role,
                "tenant_id": r.tenant_id, "permissions": r.permissions,
                "active": r.active, "gmail": r.gmail, "created_at": r.created_at,
            }));
        }
        Ok(out)
    }

    pub async fn get_users_by_tenant(&self, tenant_id: &str) -> Result<Vec<serde_json::Value>> {
        #[derive(Deserialize, clickhouse::Row)]
        struct Row {
            id: String, username: String, role: String,
            tenant_id: String, permissions: String, active: u8,
            gmail: String, created_at: String,
        }
        let q = format!(
            "SELECT id, username, role, tenant_id, permissions, active, \
                    coalesce(gmail,'') AS gmail, toString(created_at) AS created_at \
             FROM users WHERE tenant_id = '{}' AND role != 'super_admin' \
             ORDER BY created_at DESC",
            escape(tenant_id)
        );
        let mut cur = self.client.query(&q).fetch::<Row>()?;
        let mut out = Vec::new();
        while let Some(r) = cur.next().await? {
            out.push(serde_json::json!({
                "id": r.id, "username": r.username, "role": r.role,
                "tenant_id": r.tenant_id, "permissions": r.permissions,
                "active": r.active, "gmail": r.gmail, "created_at": r.created_at,
            }));
        }
        Ok(out)
    }

    pub async fn get_user_identity(&self, id: &str) -> Result<Option<(String, String, String)>> {
        #[derive(Deserialize, clickhouse::Row)]
        struct Row { username: String, role: String, tenant_id: String }
        let q = format!(
            "SELECT username, role, tenant_id FROM users WHERE id = '{}' LIMIT 1",
            escape(id)
        );
        let mut cur = self.client.query(&q).fetch::<Row>()?;
        Ok(cur.next().await?.map(|r| (r.username, r.role, r.tenant_id)))
    }

    pub async fn get_user_by_username_json(&self, username: &str) -> Result<Option<serde_json::Value>> {
        #[derive(Deserialize, clickhouse::Row)]
        struct Row {
            id: String, username: String, role: String, tenant_id: String,
            permissions: String, active: u8, gmail: String, secret_code: String,
        }
        let q = format!(
            "SELECT id, username, role, tenant_id, permissions, active, \
                    coalesce(gmail,'') AS gmail, coalesce(secret_code,'') AS secret_code \
             FROM users WHERE username = '{}' LIMIT 1",
            escape(username)
        );
        let mut cur = self.client.query(&q).fetch::<Row>()?;
        Ok(cur.next().await?.map(|r| serde_json::json!({
            "id": r.id, "username": r.username, "role": r.role,
            "tenant_id": r.tenant_id, "permissions": r.permissions,
            "active": r.active, "gmail": r.gmail, "secret_code": r.secret_code,
        })))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_user(
        &self, username: &str, hash: &str, role: &str,
        tenant_id: &str, permissions: &str, gmail: &str, secret_code: &str,
    ) -> Result<()> {
        let q = format!(
            "INSERT INTO users (id, username, password_hash, role, tenant_id, permissions, \
                                active, created_at, last_login, gmail, secret_code) \
             VALUES (generateUUIDv4(), '{}', '{}', '{}', '{}', '{}', 1, now(), now(), '{}', '{}')",
            escape(username), escape(hash), escape(role), escape(tenant_id),
            escape(permissions), escape(gmail), escape(secret_code)
        );
        self.client.query(&q).execute().await?;
        Ok(())
    }

    pub async fn update_user_full(
        &self, id: &str, role: &str, tenant_id: &str,
        permissions: &str, active: bool, hash: Option<&str>,
    ) -> Result<()> {
        let active_u8 = active as u8;
        let hash_clause = match hash {
            Some(h) => format!(", password_hash = '{}'", escape(h)),
            None    => String::new(),
        };
        let q = format!(
            "ALTER TABLE users UPDATE role = '{}', tenant_id = '{}', \
                    permissions = '{}', active = {}{} WHERE id = '{}'",
            escape(role), escape(tenant_id), escape(permissions),
            active_u8, hash_clause, escape(id)
        );
        self.client.query(&q).execute().await?;
        Ok(())
    }

    pub async fn set_user_active(&self, id: &str, active: bool) -> Result<()> {
        let q = format!(
            "ALTER TABLE users UPDATE active = {} WHERE id = '{}'",
            active as u8, escape(id)
        );
        self.client.query(&q).execute().await?;
        Ok(())
    }

    pub async fn update_user_permissions(&self, id: &str, permissions: &str) -> Result<()> {
        let q = format!(
            "ALTER TABLE users UPDATE permissions = '{}' WHERE id = '{}'",
            escape(permissions), escape(id)
        );
        self.client.query(&q).execute().await?;
        Ok(())
    }

    pub async fn update_user_password(&self, id: &str, hash: &str) -> Result<()> {
        let q = format!(
            "ALTER TABLE users UPDATE password_hash = '{}' WHERE id = '{}'",
            escape(hash), escape(id)
        );
        self.client.query(&q).execute().await?;
        Ok(())
    }

    pub async fn delete_user(&self, id: &str) -> Result<()> {
        let q = format!("ALTER TABLE users DELETE WHERE id = '{}'", escape(id));
        self.client.query(&q).execute().await?;
        Ok(())
    }

    pub async fn update_user_gmail(&self, id: &str, gmail: &str) -> Result<()> {
        let q = format!(
            "ALTER TABLE users UPDATE gmail = '{}' WHERE id = '{}'",
            escape(gmail), escape(id)
        );
        self.client.query(&q).execute().await?;
        Ok(())
    }

    pub async fn update_user_secret_code(&self, id: &str, code: &str) -> Result<()> {
        let q = format!(
            "ALTER TABLE users UPDATE secret_code = '{}' WHERE id = '{}'",
            escape(code), escape(id)
        );
        self.client.query(&q).execute().await?;
        Ok(())
    }

    pub async fn verify_tenant_admin_secret(
        &self, username: &str, secret_code: &str,
    ) -> Result<Option<String>> {
        #[derive(Deserialize, clickhouse::Row)]
        struct Row { gmail: String }
        let q = format!(
            "SELECT coalesce(gmail,'') AS gmail FROM users \
             WHERE username = '{}' AND secret_code = '{}' AND role = 'tenant_admin' LIMIT 1",
            escape(username), escape(secret_code)
        );
        let mut cur = self.client.query(&q).fetch::<Row>()?;
        Ok(cur.next().await?.map(|r| r.gmail))
    }

    pub async fn get_gmail_for_user(&self, username: &str) -> Result<Option<String>> {
        #[derive(Deserialize, clickhouse::Row)]
        struct Row { gmail: String }
        let q = format!(
            "SELECT coalesce(gmail,'') AS gmail FROM users WHERE username = '{}' LIMIT 1",
            escape(username)
        );
        let mut cur = self.client.query(&q).fetch::<Row>()?;
        Ok(cur.next().await?.map(|r| r.gmail))
    }

    pub async fn reset_password_by_username(&self, username: &str, hash: &str) -> Result<()> {
        let q = format!(
            "ALTER TABLE users UPDATE password_hash = '{}' WHERE username = '{}'",
            escape(hash), escape(username)
        );
        self.client.query(&q).execute().await?;
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Tenant management
    // ─────────────────────────────────────────────────────────────────────────

    pub async fn get_all_tenants(&self) -> Result<Vec<serde_json::Value>> {
        #[derive(Deserialize, clickhouse::Row)]
        struct Row {
            id: String, name: String, active: u8, ai_enabled: u8,
            features: String, created_at: String,
        }
        let q = "SELECT id, name, active, ai_enabled, \
                        coalesce(features,'[\"ndr\"]') AS features, \
                        toString(created_at) AS created_at \
                 FROM tenants ORDER BY created_at DESC";
        let mut cur = self.client.query(q).fetch::<Row>()?;
        let mut out = Vec::new();
        while let Some(r) = cur.next().await? {
            out.push(serde_json::json!({
                "id": r.id, "name": r.name, "active": r.active,
                "ai_enabled": r.ai_enabled, "features": r.features,
                "created_at": r.created_at,
            }));
        }
        Ok(out)
    }

    pub async fn create_tenant(&self, id: &str, name: &str) -> Result<()> {
        let q = format!(
            "INSERT INTO tenants (id, name, active, ai_enabled, updated_at, created_at, features) \
             VALUES ('{}', '{}', 1, 0, now(), now(), '[\"ndr\"]')",
            escape(id), escape(name)
        );
        self.client.query(&q).execute().await?;
        Ok(())
    }

    pub async fn update_tenant(&self, id: &str, name: &str, active: bool) -> Result<()> {
        let q = format!(
            "ALTER TABLE tenants UPDATE name = '{}', active = {}, updated_at = now() WHERE id = '{}'",
            escape(name), active as u8, escape(id)
        );
        self.client.query(&q).execute().await?;
        Ok(())
    }

    pub async fn set_tenant_active(&self, id: &str, active: bool) -> Result<()> {
        let q = format!(
            "ALTER TABLE tenants UPDATE active = {}, updated_at = now() WHERE id = '{}'",
            active as u8, escape(id)
        );
        self.client.query(&q).execute().await?;
        Ok(())
    }

    pub async fn set_tenant_ai_enabled(&self, id: &str, enabled: bool) -> Result<()> {
        let q = format!(
            "ALTER TABLE tenants UPDATE ai_enabled = {}, updated_at = now() WHERE id = '{}'",
            enabled as u8, escape(id)
        );
        self.client.query(&q).execute().await?;
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SMTP settings
    // ─────────────────────────────────────────────────────────────────────────

    pub async fn get_smtp_settings(&self) -> Result<(String, String, String, String)> {
        #[derive(Deserialize, clickhouse::Row)]
        struct Row { key: String, value: String }
        let mut cur = self.client.query(
            "SELECT key, value FROM ndr.settings FINAL \
             WHERE key IN ('global_smtp_host','global_smtp_port','global_smtp_user','global_smtp_password')"
        ).fetch::<Row>()?;
        let mut host = "smtp.gmail.com".to_string();
        let mut port = "587".to_string();
        let mut user = String::new();
        let mut pass = String::new();
        while let Some(r) = cur.next().await? {
            match r.key.as_str() {
                "global_smtp_host"     => host = r.value,
                "global_smtp_port"     => port = r.value,
                "global_smtp_user"     => user = r.value,
                "global_smtp_password" => pass = r.value,
                _                      => {}
            }
        }
        Ok((host, port, user, pass))
    }
}

/// Minimal SQL escape — single-quote sanitisation.
fn escape(s: &str) -> String {
    s.replace('\'', "\\'")
}
