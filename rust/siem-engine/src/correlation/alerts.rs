// SIEM Correlation Engine — ClickHouse Alert Write/Query Layer
// All writes target ndr.unified_alerts (schema: init.sql line 968).
// source = 'corroborated' for all SIEM correlation engine output.
// License: Apache-2.0

use anyhow::Result;
use clickhouse::Client;
use serde::{Deserialize, Serialize};
use chrono::Utc;

use crate::correlation::types::SiemAlert;

// ─────────────────────────────────────────────────────────────────────────────
// ClickHouse row struct for INSERT (matches init.sql schema exactly)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, clickhouse::Row)]
pub struct UnifiedAlertRow {
    pub alert_id:             String,
    pub tenant_id:            String,
    pub source:               String,
    pub severity:             String,
    pub rule_id:              String,
    pub rule_name:            String,
    pub title:                String,
    pub description:          String,
    pub affected_hosts:       Vec<String>,
    pub mitre_techniques:     Vec<String>,
    pub mitre_sources:        Vec<String>,
    pub mitre_confidences:    Vec<f32>,
    pub status:               String,
    pub linked_siem_log_ids:  Vec<String>,
    pub sla_started_at:       Option<u32>,  // ClickHouse Nullable(DateTime) as Unix epoch
    pub sla_breached_at:      Option<u32>,
    pub created_at:           u32,           // DateTime as Unix epoch for clickhouse crate
    pub updated_at:           u32,
}

impl From<&SiemAlert> for UnifiedAlertRow {
    fn from(a: &SiemAlert) -> Self {
        Self {
            alert_id:          a.alert_id.clone(),
            tenant_id:         a.tenant_id.clone(),
            source:            a.source.clone(),
            severity:          a.severity.clone(),
            rule_id:           a.rule_id.clone(),
            rule_name:         a.rule_name.clone(),
            title:             a.title.clone(),
            description:       a.description.clone(),
            affected_hosts:    a.affected_hosts.clone(),
            mitre_techniques:  a.mitre_techniques.clone(),
            mitre_sources:     a.mitre_sources.clone(),
            mitre_confidences: a.mitre_confidences.clone(),
            status:            a.status.clone(),
            linked_siem_log_ids: a.linked_siem_log_ids.clone(),
            sla_started_at:    a.sla_started_at.map(|dt| dt.timestamp() as u32),
            sla_breached_at:   a.sla_breached_at.map(|dt| dt.timestamp() as u32),
            created_at:        a.created_at.timestamp() as u32,
            updated_at:        a.updated_at.timestamp() as u32,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Write operations
// ─────────────────────────────────────────────────────────────────────────────

/// INSERT a new alert row into ndr.unified_alerts.
pub async fn write_alert(ch: &Client, alert: &SiemAlert) -> Result<()> {
    let row = UnifiedAlertRow::from(alert);
    let mut insert = ch.insert("ndr.unified_alerts")?;
    insert.write(&row).await?;
    insert.end().await?;
    tracing::info!(
        alert_id = %alert.alert_id,
        rule_id  = %alert.rule_id,
        severity = %alert.severity,
        tenant   = %alert.tenant_id,
        "New corroborated alert written to unified_alerts"
    );
    Ok(())
}

/// UPDATE an existing alert: bump updated_at.
/// ClickHouse ReplacingMergeTree deduplicates on (tenant_id, alert_id);
/// we re-INSERT (SELECT) with same alert_id but updated `updated_at` and optionally `status`.
pub async fn update_alert(
    ch:         &Client,
    alert_id:   &str,
    tenant_id:  &str,
    new_status: Option<&str>,
) -> Result<()> {
    let updated_at = chrono::Utc::now().timestamp() as u32;

    let status_expr = if let Some(s) = new_status {
        format!("'{}' AS status", escape(s))
    } else {
        "status".to_string()
    };

    let sql = format!(
        "INSERT INTO ndr.unified_alerts \
         (alert_id, tenant_id, source, severity, rule_id, rule_name, title, description, \
          affected_hosts, mitre_techniques, mitre_sources, mitre_confidences, \
          status, linked_siem_log_ids, sla_started_at, sla_breached_at, created_at, updated_at) \
         SELECT \
          alert_id, tenant_id, source, severity, rule_id, rule_name, title, description, \
          affected_hosts, mitre_techniques, mitre_sources, mitre_confidences, \
          {status}, linked_siem_log_ids, sla_started_at, sla_breached_at, \
          created_at, {ts} AS updated_at \
         FROM ndr.unified_alerts FINAL \
         WHERE tenant_id = '{tid}' AND alert_id = '{aid}'",
        status = status_expr,
        ts     = updated_at,
        tid    = escape(tenant_id),
        aid    = escape(alert_id),
    );

    ch.query(&sql).execute().await?;
    tracing::debug!(alert_id = %alert_id, "Alert updated (dedup hit)");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Query operations (for REST API)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, clickhouse::Row)]
pub struct AlertListRow {
    pub alert_id:         String,
    pub source:           String,
    pub severity:         String,
    pub rule_id:          String,
    pub rule_name:        String,
    pub title:            String,
    pub description:      String,
    pub affected_hosts:   Vec<String>,
    pub mitre_techniques: Vec<String>,
    pub status:           String,
    pub created_at:       u32,
    pub updated_at:       u32,
    pub sla_breached_at:  Option<u32>,
}

pub struct AlertQuery {
    pub tenant_id:  String,
    pub status:     Option<String>,
    pub severity:   Option<String>,
    pub source:     Option<String>,
    pub limit:      u32,
    pub offset:     u32,
}

/// Query unified_alerts with filters for the REST API.
pub async fn get_alerts(ch: &Client, q: &AlertQuery) -> Result<Vec<AlertListRow>> {
    let mut conditions = vec![
        format!("tenant_id = '{}'", escape(&q.tenant_id))
    ];
    if let Some(ref s) = q.status {
        conditions.push(format!("status = '{}'", escape(s)));
    }
    if let Some(ref s) = q.severity {
        conditions.push(format!("severity = '{}'", escape(s)));
    }
    if let Some(ref s) = q.source {
        conditions.push(format!("source = '{}'", escape(s)));
    }

    let where_clause = conditions.join(" AND ");
    let sql = format!(
        "SELECT alert_id, source, severity, rule_id, rule_name, title, description, \
                affected_hosts, mitre_techniques, status, \
                toUnixTimestamp(created_at) AS created_at, \
                toUnixTimestamp(updated_at) AS updated_at, \
                toUnixTimestamp(sla_breached_at) AS sla_breached_at \
         FROM ndr.unified_alerts FINAL \
         WHERE {} \
         ORDER BY created_at DESC \
         LIMIT {} OFFSET {}",
        where_clause, q.limit, q.offset
    );

    let rows = ch.query(&sql).fetch_all::<AlertListRow>().await?;
    Ok(rows)
}

/// Count total matching alerts (for pagination metadata).
pub async fn count_alerts(ch: &Client, q: &AlertQuery) -> Result<u64> {
    let mut conditions = vec![
        format!("tenant_id = '{}'", escape(&q.tenant_id))
    ];
    if let Some(ref s) = q.status   { conditions.push(format!("status = '{}'", escape(s))); }
    if let Some(ref s) = q.severity { conditions.push(format!("severity = '{}'", escape(s))); }
    if let Some(ref s) = q.source   { conditions.push(format!("source = '{}'", escape(s))); }

    let sql = format!(
        "SELECT count() FROM ndr.unified_alerts FINAL WHERE {}",
        conditions.join(" AND ")
    );
    let count: u64 = ch.query(&sql).fetch_one().await?;
    Ok(count)
}

/// Update sla_breached status on an alert (called by sla.rs checker).
pub async fn mark_sla_breached(ch: &Client, alert_id: &str, tenant_id: &str) -> Result<()> {
    let now = Utc::now().timestamp() as u32;
    let sql = format!(
        "INSERT INTO ndr.unified_alerts \
         (alert_id, tenant_id, source, severity, rule_id, rule_name, title, description, \
          affected_hosts, mitre_techniques, mitre_sources, mitre_confidences, status, \
          linked_siem_log_ids, sla_started_at, sla_breached_at, created_at, updated_at) \
         SELECT alert_id, tenant_id, source, severity, rule_id, rule_name, title, description, \
                affected_hosts, mitre_techniques, mitre_sources, mitre_confidences, \
                status, linked_siem_log_ids, sla_started_at, sla_breached_at, \
                created_at, {} AS updated_at \
         FROM ndr.unified_alerts FINAL \
         WHERE tenant_id = '{}' AND alert_id = '{}'",
        now, escape(tenant_id), escape(alert_id)
    );
    ch.query(&sql).execute().await?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Minimal SQL string escaping (single-quote doubling).
fn escape(s: &str) -> String {
    s.replace('\'', "''")
}
