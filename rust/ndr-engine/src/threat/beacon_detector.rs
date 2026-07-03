/// Beacon Detector — detects C2 beaconing even to trusted cloud infrastructure.
///
/// C2 malware "phones home" on a regular schedule. Normal human traffic to
/// AWS/Cloudflare is random and varied; C2 beacons are mechanical and regular.
/// This runs independently of the trusted-cloud suppression system so that
/// beaconing tagged hits are NEVER suppressed by trusted-cloud scoring.

use std::sync::Arc;
use tracing::{info, warn};

use crate::storage::ClickhouseStorage;

// Beacon score thresholds (0–100)
const BEACON_SCORE_THRESHOLD: f64 = 70.0;
// Minimum connections in window to bother scoring
const MIN_CONNS: u64 = 10;
// Look-back window hours
const WINDOW_HOURS: u32 = 1;

pub fn spawn_beacon_detector(ch: Arc<ClickhouseStorage>) {
    tokio::spawn(async move {
        // Initial delay — let traffic accumulate before first scan
        tokio::time::sleep(std::time::Duration::from_secs(180)).await;
        loop {
            run_scan(&ch).await;
            tokio::time::sleep(std::time::Duration::from_secs(1800)).await; // every 30 min
        }
    });
}

async fn run_scan(ch: &Arc<ClickhouseStorage>) {
    info!("beacon_detector: starting scan");

    let tenant_ids = ch.get_all_tenants().await
        .unwrap_or_else(|_| vec!["default".to_string()]);

    for tenant_id in &tenant_ids {
        if let Err(e) = scan_tenant(ch, tenant_id).await {
            warn!("beacon_detector: tenant {} failed — {}", tenant_id, e);
        }
    }
}

async fn scan_tenant(ch: &Arc<ClickhouseStorage>, tenant_id: &str) -> anyhow::Result<()> {
    let candidates = ch.get_beacon_candidates(tenant_id, WINDOW_HOURS, MIN_CONNS).await?;

    if candidates.is_empty() {
        info!("beacon_detector: no candidates for tenant {}", tenant_id);
        return Ok(());
    }

    info!("beacon_detector: {} pairs to score for tenant {}", candidates.len(), tenant_id);

    // Load already-flagged pairs this hour to avoid duplicate hits
    let already_flagged = load_flagged_pairs(ch, tenant_id).await;

    for (src_ip, dst_ip, timestamps) in candidates {
        let pair_key = format!("{}→{}", src_ip, dst_ip);
        if already_flagged.contains(&pair_key) {
            continue;
        }

        let score = beacon_score(&timestamps);
        if score >= BEACON_SCORE_THRESHOLD {
            info!(
                "beacon_detector: BEACON detected tenant={} {}→{} score={:.1} conns={}",
                tenant_id, src_ip, dst_ip, score, timestamps.len()
            );
            store_beacon_hit(ch, tenant_id, &src_ip, &dst_ip, score, timestamps.len()).await;
        }
    }

    Ok(())
}

/// Calculate beacon score 0–100.
/// High score = regular intervals (low coefficient of variation of gaps).
fn beacon_score(timestamps: &[i64]) -> f64 {
    if timestamps.len() < 4 {
        return 0.0;
    }

    // Calculate inter-arrival gaps
    let gaps: Vec<f64> = timestamps.windows(2)
        .map(|w| (w[1] - w[0]) as f64)
        .filter(|&g| g > 0.0)
        .collect();

    if gaps.len() < 3 {
        return 0.0;
    }

    let mean = gaps.iter().sum::<f64>() / gaps.len() as f64;
    if mean < 1.0 {
        return 0.0; // sub-second gaps = noise, not beaconing
    }

    let variance = gaps.iter().map(|g| (g - mean).powi(2)).sum::<f64>() / gaps.len() as f64;
    let stddev = variance.sqrt();

    // Coefficient of Variation: low CV = very regular = high beacon suspicion
    let cv = stddev / mean;

    // CV=0 (perfect beacon) → score=100; CV=1 (random) → score~0
    // Score = 100 * max(0, 1 - cv)²  — penalise irregularity quadratically
    let regularity = (1.0_f64 - cv).max(0.0);
    let score = 100.0 * regularity * regularity;

    // Bonus for high connection count (more connections = more confidence)
    let count_bonus = ((timestamps.len() as f64 - MIN_CONNS as f64) / 40.0).min(0.15) * 100.0;

    (score + count_bonus).min(100.0)
}

async fn store_beacon_hit(
    ch:        &Arc<ClickhouseStorage>,
    tenant_id: &str,
    src_ip:    &str,
    dst_ip:    &str,
    score:     f64,
    conn_cnt:  usize,
) {
    let community_id = format!("beacon:{}:{}:{}", tenant_id, src_ip, dst_ip);
    let reason = format!(
        "Beaconing detected — {} connections in {}h with regular intervals (score={:.0}/100). \
         Bypasses trusted-cloud suppression. Investigate for C2 activity.",
        conn_cnt, WINDOW_HOURS, score
    );

    // Write directly as a scored hit — tags include "beaconing" which the API
    // checks to skip trusted-cloud score cap (see scoring/mod.rs rule 7)
    let q = format!(
        "INSERT INTO {db}.ndr_hits \
         (community_id, tenant_id, src_ip, dst_ip, score, severity, tags, \
          threat_intel, timestamp, correlation_status, zeek_details, suricata_details) \
         VALUES \
         ('{cid}', '{tid}', '{src}', '{dst}', {score:.1}, '{sev}', {tags}, \
          0, now(), 'beacon', '{details}', '{{}}')",
        db      = crate::storage::clickhouse::tenant_db_pub(tenant_id),
        cid     = crate::storage::clickhouse::sql_escape_pub(&community_id),
        tid     = crate::storage::clickhouse::sql_escape_pub(tenant_id),
        src     = crate::storage::clickhouse::sql_escape_pub(src_ip),
        dst     = crate::storage::clickhouse::sql_escape_pub(dst_ip),
        score   = score,
        sev     = if score >= 85.0 { "HIGH" } else { "MEDIUM" },
        tags    = format!("['beaconing', 'c2-suspect']"),
        details = crate::storage::clickhouse::sql_escape_pub(&reason),
    );

    if let Err(e) = ch.client.query(&q).execute().await {
        warn!("beacon_detector: failed to store hit for {}→{}: {}", src_ip, dst_ip, e);
    }
}

/// Load (src→dst) pairs already flagged as beaconing in the last hour
/// so we don't create duplicate hits every 30 min.
async fn load_flagged_pairs(ch: &Arc<ClickhouseStorage>, tenant_id: &str) -> Vec<String> {
    let db = crate::storage::clickhouse::tenant_db_pub(tenant_id);
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct Row { src_ip: String, dst_ip: String }

    let rows = ch.client.query(&format!(
        "SELECT src_ip, dst_ip FROM {db}.ndr_hits FINAL
         WHERE tenant_id = '{tid}'
           AND has(tags, 'beaconing')
           AND timestamp > now() - INTERVAL 2 HOUR",
        db  = db,
        tid = crate::storage::clickhouse::sql_escape_pub(tenant_id),
    )).fetch_all::<Row>().await.unwrap_or_default();

    rows.into_iter().map(|r| format!("{}→{}", r.src_ip, r.dst_ip)).collect()
}
