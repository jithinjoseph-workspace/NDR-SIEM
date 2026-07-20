/// Entity Scorer — per-host accumulated risk scoring.
///
/// Every 5 minutes aggregates all ndr_hits from the last 24 hours per src_ip,
/// sums their scores, and upserts into ndr.entity_scores. The UI queries
/// GET /api/entity-scores to show a "Top Risky Hosts" panel.

use std::sync::Arc;
use tracing::{info, warn};

use crate::storage::ClickhouseStorage;

const REFRESH_SECS: u64 = 300; // 5 minutes
const WINDOW_HOURS: u32 = 24;

pub fn spawn_entity_scorer(
    ch:    Arc<ClickhouseStorage>,
    cache: Arc<dashmap::DashMap<String, f32>>,
) {
    tokio::spawn(async move {
        // Run immediately on startup so the in-memory cache is pre-populated.
        // Previously delayed 60s, leaving entity_score=0 for all new hits in that window.
        run_refresh(&ch, &cache).await;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(REFRESH_SECS)).await;
            run_refresh(&ch, &cache).await;
        }
    });
}

async fn run_refresh(ch: &Arc<ClickhouseStorage>, cache: &Arc<dashmap::DashMap<String, f32>>) {
    info!("entity_scorer: refreshing");
    let tenant_ids = ch.get_all_tenants().await
        .unwrap_or_else(|_| vec!["default".to_string()]);
    for tenant_id in &tenant_ids {
        if let Err(e) = refresh_tenant(ch, tenant_id, cache).await {
            warn!("entity_scorer: tenant {} failed — {}", tenant_id, e);
        }
    }
}

async fn refresh_tenant(
    ch:        &Arc<ClickhouseStorage>,
    tenant_id: &str,
    cache:     &Arc<dashmap::DashMap<String, f32>>,
) -> anyhow::Result<()> {
    use crate::storage::clickhouse::{tenant_db_pub, sql_escape_pub};

    let db  = tenant_db_pub(tenant_id);
    let tid = sql_escape_pub(tenant_id);

    // Subquery unnests tags array so groupUniqArray can collect distinct tags per host
    let select_q = format!(
        "SELECT
             src_ip,
             sum(score)               AS accumulated_score,
             count()                  AS alert_count,
             argMax(severity, score)  AS top_severity,
             groupUniqArray(tag)      AS top_tags,
             max(timestamp)           AS last_seen
         FROM (
             SELECT src_ip, score, severity, timestamp,
                    arrayJoin(tags) AS tag
             FROM {db}.ndr_hits FINAL
             WHERE tenant_id = '{tid}'
               AND timestamp  > now() - INTERVAL {hours} HOUR
               AND src_ip    != ''
         )
         GROUP BY src_ip
         HAVING accumulated_score > 0
         ORDER BY accumulated_score DESC
         LIMIT 100",
        db = db, tid = tid, hours = WINDOW_HOURS
    );

    #[derive(clickhouse::Row, serde::Deserialize)]
    struct Row {
        src_ip:            String,
        accumulated_score: f64,
        alert_count:       u64,
        top_severity:      String,
        top_tags:          Vec<String>,
        last_seen:         u32, // ClickHouse DateTime as unix timestamp
    }

    let rows = ch.client.query(&select_q).fetch_all::<Row>().await?;

    if rows.is_empty() {
        return Ok(());
    }

    info!("entity_scorer: {} hosts for tenant {}", rows.len(), tenant_id);

    for row in &rows {
        // Normalize accumulated_score → 0-100 for the scorer.
        // Dividing by 10 means a host needs ~800 accumulated points (≈12 HIGH
        // hits in 24 h) to hit the "compromised-host" threshold (entity_score ≥ 80).
        let normalized: f32 = (row.accumulated_score as f32 / 10.0).min(100.0);
        cache.insert(format!("{}:{}", tenant_id, row.src_ip), normalized);

        let tags_literal = format!(
            "[{}]",
            row.top_tags
                .iter()
                .map(|t| format!("'{}'", sql_escape_pub(t)))
                .collect::<Vec<_>>()
                .join(", ")
        );

        let q = format!(
            "INSERT INTO {db}.entity_scores \
             (src_ip, tenant_id, accumulated_score, alert_count, top_severity, top_tags, last_seen, updated_at) \
             VALUES \
             ('{src}', '{tid}', {score:.2}, {cnt}, '{sev}', {tags}, \
              toDateTime({ls}), now())",
            db    = db,
            src   = sql_escape_pub(&row.src_ip),
            tid   = sql_escape_pub(tenant_id),
            score = row.accumulated_score,
            cnt   = row.alert_count,
            sev   = sql_escape_pub(&row.top_severity),
            tags  = tags_literal,
            ls    = row.last_seen,
        );

        if let Err(e) = ch.client.query(&q).execute().await {
            warn!("entity_scorer: upsert failed for {}: {}", row.src_ip, e);
        }
    }

    Ok(())
}
