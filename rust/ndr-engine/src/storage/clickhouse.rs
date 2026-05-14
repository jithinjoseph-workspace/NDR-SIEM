use clickhouse::Client;
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
}

#[derive(Debug, Serialize, Deserialize, clickhouse::Row)]
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

impl ClickhouseStorage {
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
            return;
        }
    }
    tracing::warn!("init.sql not found!");
}


//threat intel hits
    pub async fn get_threat_intel_hits(&self) -> anyhow::Result<Vec<serde_json::Value>> {
    let hits = self.client
        .query("
            SELECT
                src_ip,
                dst_ip,
                count() as hits,
                max(timestamp) as last_seen
            FROM ndr_hits
            WHERE threat_intel = 1
            GROUP BY src_ip, dst_ip
            ORDER BY hits DESC
            LIMIT 50
        ")
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
    
    pub async fn set_rule_enabled(&self,id: &str,enabled: bool) -> anyhow::Result<()> {
    self.client.query("INSERT INTO ndr.rules_state (id, enabled, updated) VALUES (?, ?, now())").bind(id).bind(enabled as u8).execute().await?;
    Ok(())
}

pub async fn get_disabled_rules(&self) -> anyhow::Result<Vec<String>> {
    let ids = self.client
        .query(
            "SELECT id FROM ndr.rules_state
             FINAL
             WHERE enabled = 0"
        )
        .fetch_all::<String>()
        .await
        .unwrap_or_default();
    Ok(ids)
}

pub async fn delete_rule_state(&self, id: &str) -> anyhow::Result<()> {
    self.client
        .query("ALTER TABLE ndr.rules_state DELETE WHERE id = ?")
        .bind(id)
        .execute()
        .await?;
    Ok(())
}


//save soar config
pub async fn save_soar_config(
    &self, key: &str, value: &str
) -> anyhow::Result<()> {
    let query = format!(
        "INSERT INTO ndr.soar_config (key, value) \
         VALUES ('{}', '{}')",
        key, value
    );
    self.client.query(&query).execute().await?;
    Ok(())
}


//get soar config
pub async fn get_soar_config(
    &self
) -> anyhow::Result<serde_json::Value> {
    let query = "
        SELECT key, value
        FROM ndr.soar_config
        FINAL
        ORDER BY key
    ";
    let result = self.client
        .query(query)
        .fetch_all::<(String, String)>()
        .await?;
    let mut map = serde_json::Map::new();
    for (key, val) in result {
        map.insert(key, serde_json::json!(val));
    }
    Ok(serde_json::Value::Object(map))
}


//soar playbooks
pub async fn get_soar_playbooks(
    &self
) -> anyhow::Result<Vec<serde_json::Value>> {
    let query = "
        SELECT id, name, description,
               trigger, action_type,
               config, enabled, runs
        FROM ndr.soar_playbooks
        FINAL
        ORDER BY created_at
    ";
    let result = self.client
        .query(query)
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

//enable/disable playbook
pub async fn update_playbook_enabled(
    &self, id: &str, enabled: bool
) -> anyhow::Result<()> {
    let query = format!(
        "INSERT INTO ndr.soar_playbooks \
         (id, name, description, trigger, \
          action_type, enabled) \
         SELECT id, name, description, trigger, \
                action_type, {}
         FROM ndr.soar_playbooks
         WHERE id = '{}'",
        if enabled { 1 } else { 0 }, id
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
            .query("SELECT count() FROM ndr_hits WHERE severity = 'critical'")
            .fetch_one::<u64>().await.unwrap_or(0);
        let high: u64 = self.client
            .query("SELECT count() FROM ndr_hits WHERE severity = 'high'")
            .fetch_one::<u64>().await.unwrap_or(0);
        let medium: u64 = self.client
            .query("SELECT count() FROM ndr_hits WHERE severity = 'medium'")
            .fetch_one::<u64>().await.unwrap_or(0);
        let low: u64 = self.client
            .query("SELECT count() FROM ndr_hits WHERE severity = 'low'")
            .fetch_one::<u64>().await.unwrap_or(0);

        Ok(serde_json::json!({
            "critical": critical,
            "high":     high,
            "medium":   medium,
            "low":      low,
        }))
    }



    
}
