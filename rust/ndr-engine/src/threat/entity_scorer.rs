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

    // Refresh all tenants concurrently (bounded to 4 in-flight) so a slow scan
    // on one tenant doesn't push the total past the 5-minute refresh window.
    let sem = Arc::new(tokio::sync::Semaphore::new(4));
    let mut handles = Vec::with_capacity(tenant_ids.len());
    for tenant_id in tenant_ids {
        let ch2    = ch.clone();
        let cache2 = cache.clone();
        let sem2   = sem.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem2.acquire().await;
            if let Err(e) = refresh_tenant(&ch2, &tenant_id, &cache2).await {
                warn!("entity_scorer: tenant {} failed — {}", tenant_id, e);
            }
        }));
    }
    futures_util::future::join_all(handles).await;
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
               AND score     >= 20
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

    // Update in-memory cache and collect rows for a single batch INSERT.
    // Previously issued one INSERT per host (up to 100 round-trips per tenant).
    #[derive(clickhouse::Row, serde::Serialize)]
    struct EntityScoreRow {
        src_ip:            String,
        tenant_id:         String,
        accumulated_score: f64,
        alert_count:       u64,
        top_severity:      String,
        top_tags:          Vec<String>,
        last_seen:         u32,
        updated_at:        u32,
    }

    let now_ts = chrono::Utc::now().timestamp() as u32;
    let table  = format!("{}.entity_scores", db);
    match ch.client.insert(&table) {
        Err(e) => {
            warn!("entity_scorer: failed to open insert for tenant {}: {}", tenant_id, e);
        }
        Ok(mut inserter) => {
            for row in &rows {
                let normalized: f32 = (row.accumulated_score as f32 / 10.0).min(100.0);
                cache.insert(format!("{}:{}", tenant_id, row.src_ip), normalized);

                let r = EntityScoreRow {
                    src_ip:            row.src_ip.clone(),
                    tenant_id:         tenant_id.to_string(),
                    accumulated_score: row.accumulated_score,
                    alert_count:       row.alert_count,
                    top_severity:      row.top_severity.clone(),
                    top_tags:          row.top_tags.clone(),
                    last_seen:         row.last_seen,
                    updated_at:        now_ts,
                };
                if let Err(e) = inserter.write(&r).await {
                    warn!("entity_scorer: write failed for {}: {}", row.src_ip, e);
                }
            }
            if let Err(e) = inserter.end().await {
                warn!("entity_scorer: batch commit failed for tenant {}: {}", tenant_id, e);
            }
        }
    }

    Ok(())
}
