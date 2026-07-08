// Multi-flow correlator — detects attack patterns that span multiple network flows.
//
// Three background loops:
//   Tier 1/2 (every 60 s)  — short/medium window: port scan, cred stuffing, lateral movement,
//                             DNS beaconing, slow scan, internal recon, data staging
//   Tier 3a (every 24 h)   — baseline refresh: pre-aggregates per-IP daily stats into ndr_baselines
//   Tier 3b (every 5 min)  — anomaly detection: volume spike, new external contact

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use chrono::{Utc, Timelike};
use clickhouse::Row;
use serde::{Deserialize, Serialize};

use crate::leader::LeaderElection;
use crate::storage::ClickhouseStorage;
use crate::storage::clickhouse::{
    NdrHit,
    tenant_db_pub as db_for,
    sql_escape_pub as esc,
};

// Suppression windows — how long after an alert fires before the same
// (pattern, tenant, src_ip) is allowed to fire again.
const SUP_PORT_SCAN:   Duration = Duration::from_secs(1800); // 30 min
const SUP_CRED_STUFF:  Duration = Duration::from_secs(1800);
const SUP_LATERAL:     Duration = Duration::from_secs(1800);
const SUP_DNS_BEACON:  Duration = Duration::from_secs(3600); // 60 min
const SUP_SLOW_SCAN:   Duration = Duration::from_secs(3600);
const SUP_RECON:       Duration = Duration::from_secs(1800);
const SUP_STAGING:     Duration = Duration::from_secs(3600);
const SUP_VOL_ANOMALY:    Duration = Duration::from_secs(3600);
const SUP_NEW_CONTACT:    Duration = Duration::from_secs(86400); // 24 h — new contact once per day per pair
const SUP_ICMP_FLOOD:     Duration = Duration::from_secs(1800);
const SUP_ABNORMAL_HOURS: Duration = Duration::from_secs(3600);

// In-memory suppression cache: key = (pattern, tenant, identifier), value = Instant of last emit.
// Shared across all Tier 1/2 and Tier 3 runs inside the same tokio task via passed &mut.
type SuppressMap = HashMap<(String, String, String), Instant>;

fn is_suppressed(map: &mut SuppressMap, pattern: &str, tenant: &str, key: &str, window: Duration) -> bool {
    let k = (pattern.to_string(), tenant.to_string(), key.to_string());
    if let Some(last) = map.get(&k) {
        if last.elapsed() < window {
            return true;
        }
    }
    map.insert(k, Instant::now());
    false
}

// Evict entries older than 24 h to prevent unbounded memory growth.
fn evict_old(map: &mut SuppressMap) {
    map.retain(|_, v| v.elapsed() < Duration::from_secs(86400));
}

// ── Query result row types ────────────────────────────────────────────────────

#[derive(Row, Serialize, Deserialize)]
struct TwoCount {
    src_ip: String,
    cnt_a:  u64,
    cnt_b:  u64,
}

#[derive(Row, Serialize, Deserialize)]
struct OneCount {
    src_ip: String,
    cnt:    u64,
}

#[derive(Row, Serialize, Deserialize)]
struct PairCount {
    src_ip: String,
    dst_ip: String,
    cnt:    u64,
    span:   i64,
}

#[derive(Row, Serialize, Deserialize)]
struct BRow {
    src_ip:  String,
    value_f: f64,
    value_s: String,
}

#[derive(Row, Serialize, Deserialize)]
struct NewContact {
    src_ip: String,
    dst_ip: String,
}

#[derive(Row, Serialize, Deserialize)]
struct VolAnomaly {
    src_ip:      String,
    today_cnt:   u64,
    avg_hourly:  f64,
}

#[derive(Row, Serialize)]
struct NdrBaseline {
    tenant_id:  String,
    src_ip:     String,
    metric:     String,
    value_f:    f64,
    value_s:    String,
    window_ts:  u32,
    updated_at: u32,
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub fn spawn(ch: Arc<ClickhouseStorage>, election: Arc<LeaderElection>) {
    // Tier 1+2 — every 60 s, only on elected leader
    {
        let ch  = ch.clone();
        let el  = election.clone();
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
            let mut sup: SuppressMap = HashMap::new();
            let mut evict_tick = 0u32;
            loop {
                if el.is_leader() {
                    run_tier12(&ch, &mut sup).await;
                    evict_tick += 1;
                    if evict_tick % 60 == 0 { evict_old(&mut sup); }
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
            }
        });
    }
    // Tier 3a — baseline refresh every 24 h, only on elected leader
    {
        let ch = ch.clone();
        let el = election.clone();
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_secs(120)).await;
            loop {
                if el.is_leader() {
                    run_baseline_refresh(&ch).await;
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(86400)).await;
            }
        });
    }
    // Tier 3b — anomaly detection every 5 min, only on elected leader
    {
        let ch = ch.clone();
        let el = election.clone();
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_secs(300)).await;
            let mut sup: SuppressMap = HashMap::new();
            loop {
                if el.is_leader() {
                    run_tier3(&ch, &mut sup).await;
                    evict_old(&mut sup);
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(300)).await;
            }
        });
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn now_ts() -> u32 {
    Utc::now().timestamp() as u32
}

fn severity_label(score: f32) -> &'static str {
    match score as u32 {
        0..=49  => "low",
        50..=69 => "medium",
        70..=84 => "high",
        _       => "critical",
    }
}

// Unique community_id for a new alert row — includes timestamp so each
// suppression-allowed emit is a distinct row (not an update of the previous one).
fn make_cid(pattern: &str, tenant: &str, key: &str) -> String {
    format!("mf:{}:{}:{}:{}", pattern, tenant, key, now_ts())
}

// Look up the sensor that most recently saw src_ip for this tenant.
// Returns empty string on miss so the hit is still written without a sensor tag.
async fn sensor_for(ch: &ClickhouseStorage, db: &str, tenant: &str, src_ip: &str) -> String {
    #[derive(Row, Serialize, Deserialize)]
    struct SRow { sensor_id: String }
    let q = format!(
        "SELECT sensor_id FROM {db}.ndr_events \
         WHERE tenant_id = '{t}' AND src_ip = '{ip}' AND sensor_id != '' \
         ORDER BY timestamp DESC LIMIT 1",
        db = db, t = esc(tenant), ip = esc(src_ip)
    );
    ch.client.query(&q).fetch_all::<SRow>().await
        .unwrap_or_default()
        .into_iter()
        .next()
        .map(|r| r.sensor_id)
        .unwrap_or_default()
}

async fn emit(
    ch:        &ClickhouseStorage,
    tenant:    &str,
    cid:       &str,
    src_ip:    &str,
    dst_ip:    &str,
    score:     f32,
    tags:      Vec<String>,
    sensor_id: &str,
) {
    let now = now_ts();
    let hit = NdrHit {
        timestamp:          now,
        community_id:       cid.to_string(),
        src_ip:             src_ip.to_string(),
        dst_ip:             dst_ip.to_string(),
        score,
        severity:           severity_label(score).to_string(),
        tags,
        sigma_hits:         vec![],
        threat_intel:       0,
        src_country:        String::new(),
        dst_country:        String::new(),
        tenant_id:          tenant.to_string(),
        correlation_status: "multiflow".to_string(),
        agent_z_details:    "{}".to_string(),
        agent_s_details:    "{}".to_string(),
        corroborated_at:    0,
        agent_s_rule_id:    String::new(),
        agent_s_category:   String::new(),
        updated_at:         now,
        sensor_id:          sensor_id.to_string(),
    };
    if let Err(e) = ch.insert_hit_for_tenant(hit, tenant).await {
        tracing::warn!("multiflow emit failed [{}/{}]: {}", tenant, cid, e);
    }
}

// Private IP range SQL fragment for a named column
fn is_private(col: &str) -> String {
    format!(
        "(isIPAddressInRange({c},'10.0.0.0/8') \
          OR isIPAddressInRange({c},'192.168.0.0/16') \
          OR isIPAddressInRange({c},'172.16.0.0/12'))",
        c = col
    )
}

// ── Tier 1 + 2: short / medium window ─────────────────────────────────────────

async fn run_tier12(ch: &ClickhouseStorage, sup: &mut SuppressMap) {
    let tenants = match ch.get_all_tenants().await {
        Ok(t) => t,
        Err(e) => { tracing::warn!("multiflow: get_all_tenants: {}", e); return; }
    };
    for tenant in &tenants {
        detect_port_scan(ch, tenant, sup).await;
        detect_credential_stuffing(ch, tenant, sup).await;
        detect_lateral_movement(ch, tenant, sup).await;
        detect_dns_beaconing(ch, tenant, sup).await;
        detect_slow_scan(ch, tenant, sup).await;
        detect_internal_recon(ch, tenant, sup).await;
        detect_data_staging(ch, tenant, sup).await;
        detect_icmp_flood(ch, tenant, sup).await;
    }
}

// Port scan: >15 distinct ports OR >20 distinct hosts from one src in 5 min
async fn detect_port_scan(ch: &ClickhouseStorage, tenant: &str, sup: &mut SuppressMap) {
    let db = db_for(tenant);
    let t  = esc(tenant);
    let q = format!(
        "SELECT src_ip, \
                count(DISTINCT dst_port) AS cnt_a, \
                count(DISTINCT dst_ip)   AS cnt_b \
         FROM {db}.ndr_events \
         WHERE timestamp > now() - INTERVAL 5 MINUTE \
           AND tenant_id = '{t}' AND src_ip != '' \
         GROUP BY src_ip \
         HAVING cnt_a > 15 OR cnt_b > 20"
    );
    let rows: Vec<TwoCount> = ch.client.query(&q).fetch_all().await.unwrap_or_default();
    for r in rows {
        if is_suppressed(sup, "portscan", tenant, &r.src_ip, SUP_PORT_SCAN) { continue; }
        tracing::info!("multiflow[port-scan] {}/{}: {} ports {} targets",
            tenant, r.src_ip, r.cnt_a, r.cnt_b);
        let sid = sensor_for(ch, &db, tenant, &r.src_ip).await;
        emit(ch, tenant, &make_cid("portscan", tenant, &r.src_ip),
            &r.src_ip, "", 65.0,
            vec!["port-scan".into(), "t:discovery".into()], &sid).await;
    }
}

// Credential stuffing: >20 auth-failure events from one src in 10 min.
// Source-agnostic: catches Suricata alerts, Zeek HTTP 401/403/429,
// Zeek SSH auth_success=false, and Zeek FTP 530/430 reply codes.
async fn detect_credential_stuffing(ch: &ClickhouseStorage, tenant: &str, sup: &mut SuppressMap) {
    let db = db_for(tenant);
    let t  = esc(tenant);
    let q = format!(
        "SELECT src_ip, count() AS cnt \
         FROM {db}.ndr_events \
         WHERE timestamp > now() - INTERVAL 10 MINUTE \
           AND tenant_id = '{t}' AND src_ip != '' \
           AND ( \
             (source = 'agent-s' AND event_type = 'alert') \
             OR JSONExtractUInt(raw, 'status_code') IN (401, 403, 407, 429) \
             OR (event_type = 'ssh'  AND JSONExtractString(raw, 'auth_success') = 'false') \
             OR JSONExtractUInt(raw, 'reply_code') IN (530, 430, 332) \
           ) \
         GROUP BY src_ip \
         HAVING cnt > 20"
    );
    let rows: Vec<OneCount> = ch.client.query(&q).fetch_all().await.unwrap_or_default();
    for r in rows {
        if is_suppressed(sup, "credstuff", tenant, &r.src_ip, SUP_CRED_STUFF) { continue; }
        tracing::info!("multiflow[cred-stuffing] {}/{}: {} alert flows",
            tenant, r.src_ip, r.cnt);
        let sid = sensor_for(ch, &db, tenant, &r.src_ip).await;
        emit(ch, tenant, &make_cid("credstuff", tenant, &r.src_ip),
            &r.src_ip, "", 75.0,
            vec!["credential-stuffing".into(), "t:credential-access".into()], &sid).await;
    }
}

// Lateral movement: internal src hitting >5 distinct internal hosts in 10 min
async fn detect_lateral_movement(ch: &ClickhouseStorage, tenant: &str, sup: &mut SuppressMap) {
    let db      = db_for(tenant);
    let t       = esc(tenant);
    let prv_src = is_private("src_ip");
    let prv_dst = is_private("dst_ip");
    let q = format!(
        "SELECT src_ip, count(DISTINCT dst_ip) AS cnt \
         FROM {db}.ndr_events \
         WHERE timestamp > now() - INTERVAL 10 MINUTE \
           AND tenant_id = '{t}' \
           AND {prv_src} AND {prv_dst} \
           AND src_ip != '' \
         GROUP BY src_ip \
         HAVING cnt > 5"
    );
    let rows: Vec<OneCount> = ch.client.query(&q).fetch_all().await.unwrap_or_default();
    for r in rows {
        if is_suppressed(sup, "lateral", tenant, &r.src_ip, SUP_LATERAL) { continue; }
        tracing::info!("multiflow[lateral] {}/{}: {} internal targets",
            tenant, r.src_ip, r.cnt);
        let sid = sensor_for(ch, &db, tenant, &r.src_ip).await;
        emit(ch, tenant, &make_cid("lateral", tenant, &r.src_ip),
            &r.src_ip, "", 80.0,
            vec!["lateral-movement".into(), "t:lateral-movement".into()], &sid).await;
    }
}

// DNS beaconing: >100 DNS queries to the same destination in 30 min
async fn detect_dns_beaconing(ch: &ClickhouseStorage, tenant: &str, sup: &mut SuppressMap) {
    let db = db_for(tenant);
    let t  = esc(tenant);
    let q = format!(
        "SELECT src_ip, dst_ip, \
                count() AS cnt, \
                dateDiff('second', min(timestamp), max(timestamp)) AS span \
         FROM {db}.ndr_events \
         WHERE timestamp > now() - INTERVAL 30 MINUTE \
           AND tenant_id = '{t}' \
           AND event_type = 'dns' \
           AND src_ip != '' AND dst_ip != '' \
         GROUP BY src_ip, dst_ip \
         HAVING cnt > 100 AND span > 60"
    );
    let rows: Vec<PairCount> = ch.client.query(&q).fetch_all().await.unwrap_or_default();
    for r in rows {
        let key = format!("{}_{}", r.src_ip, r.dst_ip);
        if is_suppressed(sup, "dnsbeacon", tenant, &key, SUP_DNS_BEACON) { continue; }
        tracing::info!("multiflow[dns-beacon] {}/{}: {} queries/{}s → {}",
            tenant, r.src_ip, r.cnt, r.span, r.dst_ip);
        let sid = sensor_for(ch, &db, tenant, &r.src_ip).await;
        emit(ch, tenant, &make_cid("dnsbeacon", tenant, &key),
            &r.src_ip, &r.dst_ip, 65.0,
            vec!["dns-beaconing".into(), "t:command-and-control".into()], &sid).await;
    }
}

// Slow scan: >100 distinct ports OR >50 distinct hosts over 24 hours
async fn detect_slow_scan(ch: &ClickhouseStorage, tenant: &str, sup: &mut SuppressMap) {
    let db = db_for(tenant);
    let t  = esc(tenant);
    let q = format!(
        "SELECT src_ip, \
                count(DISTINCT dst_port) AS cnt_a, \
                count(DISTINCT dst_ip)   AS cnt_b \
         FROM {db}.ndr_events \
         WHERE timestamp > now() - INTERVAL 24 HOUR \
           AND tenant_id = '{t}' AND src_ip != '' \
         GROUP BY src_ip \
         HAVING cnt_a > 100 OR cnt_b > 50"
    );
    let rows: Vec<TwoCount> = ch.client.query(&q).fetch_all().await.unwrap_or_default();
    for r in rows {
        if is_suppressed(sup, "slowscan", tenant, &r.src_ip, SUP_SLOW_SCAN) { continue; }
        tracing::info!("multiflow[slow-scan] {}/{}: {} ports {} targets/24h",
            tenant, r.src_ip, r.cnt_a, r.cnt_b);
        let sid = sensor_for(ch, &db, tenant, &r.src_ip).await;
        emit(ch, tenant, &make_cid("slowscan", tenant, &r.src_ip),
            &r.src_ip, "", 70.0,
            vec!["slow-scan".into(), "t:discovery".into()], &sid).await;
    }
}

// Internal recon: private src hitting >30 distinct internal hosts in 2 hours
async fn detect_internal_recon(ch: &ClickhouseStorage, tenant: &str, sup: &mut SuppressMap) {
    let db      = db_for(tenant);
    let t       = esc(tenant);
    let prv_src = is_private("src_ip");
    let q = format!(
        "SELECT src_ip, count(DISTINCT dst_ip) AS cnt \
         FROM {db}.ndr_events \
         WHERE timestamp > now() - INTERVAL 2 HOUR \
           AND tenant_id = '{t}' \
           AND {prv_src} AND src_ip != '' \
         GROUP BY src_ip \
         HAVING cnt > 30"
    );
    let rows: Vec<OneCount> = ch.client.query(&q).fetch_all().await.unwrap_or_default();
    for r in rows {
        if is_suppressed(sup, "recon", tenant, &r.src_ip, SUP_RECON) { continue; }
        tracing::info!("multiflow[internal-recon] {}/{}: {} targets/2h",
            tenant, r.src_ip, r.cnt);
        let sid = sensor_for(ch, &db, tenant, &r.src_ip).await;
        emit(ch, tenant, &make_cid("recon", tenant, &r.src_ip),
            &r.src_ip, "", 75.0,
            vec!["internal-recon".into(), "t:discovery".into()], &sid).await;
    }
}

// Data staging + exfil: src with >100MB to internal destinations AND >50MB to
// external destinations in same 30-min window. Uses actual byte volume from
// Zeek orig_bytes (conn.log); events without byte field contribute 0.
async fn detect_data_staging(ch: &ClickhouseStorage, tenant: &str, sup: &mut SuppressMap) {
    let db      = db_for(tenant);
    let t       = esc(tenant);
    let prv_dst = is_private("dst_ip");
    let q = format!(
        "WITH staging AS ( \
           SELECT src_ip, \
                  sum(JSONExtractUInt(raw, 'orig_bytes')) AS internal_bytes \
           FROM {db}.ndr_events \
           WHERE timestamp > now() - INTERVAL 30 MINUTE \
             AND tenant_id = '{t}' AND {prv_dst} AND src_ip != '' \
           GROUP BY src_ip \
           HAVING internal_bytes > 104857600 \
         ) \
         SELECT e.src_ip, \
                toUInt64(sum(JSONExtractUInt(e.raw, 'orig_bytes'))) AS cnt_a, \
                toUInt64(0) AS cnt_b \
         FROM {db}.ndr_events e \
         INNER JOIN staging s ON e.src_ip = s.src_ip \
         WHERE e.timestamp > now() - INTERVAL 30 MINUTE \
           AND e.tenant_id = '{t}' \
           AND NOT {prv_dst} \
           AND e.dst_ip != '' AND e.src_ip != '' \
         GROUP BY e.src_ip \
         HAVING cnt_a > 52428800"
    );
    let rows: Vec<TwoCount> = ch.client.query(&q).fetch_all().await.unwrap_or_default();
    for r in rows {
        if is_suppressed(sup, "staging", tenant, &r.src_ip, SUP_STAGING) { continue; }
        tracing::info!("multiflow[data-staging] {}/{}: {} ext events after internal burst",
            tenant, r.src_ip, r.cnt_a);
        let sid = sensor_for(ch, &db, tenant, &r.src_ip).await;
        emit(ch, tenant, &make_cid("staging", tenant, &r.src_ip),
            &r.src_ip, "", 88.0,
            vec!["data-staging".into(), "t:exfiltration".into()], &sid).await;
    }
}

// ── Tier 3a: baseline refresh ─────────────────────────────────────────────────

async fn run_baseline_refresh(ch: &ClickhouseStorage) {
    let tenants = match ch.get_all_tenants().await {
        Ok(t) => t,
        Err(e) => { tracing::warn!("multiflow baseline: get_all_tenants: {}", e); return; }
    };
    for tenant in &tenants {
        refresh_baselines(ch, tenant).await;
    }
}

async fn refresh_baselines(ch: &ClickhouseStorage, tenant: &str) {
    tracing::info!("multiflow: refreshing baselines for {}", tenant);
    let db      = db_for(tenant);
    let t       = esc(tenant);
    // Midnight UTC of yesterday — the window we're summarising
    let midnight = {
        let now = Utc::now();
        let yest = now.date_naive().pred_opt().unwrap_or(now.date_naive());
        yest.and_hms_opt(0, 0, 0)
            .map(|dt| dt.and_utc().timestamp() as u32)
            .unwrap_or(0)
    };

    // 1. DNS query count per IP yesterday
    baseline_compute(ch, tenant, &db, &t, "dns_count", midnight,
        &format!(
            "SELECT src_ip, toFloat64(count()) AS value_f, '' AS value_s \
             FROM {db}.ndr_events \
             WHERE timestamp >= yesterday() AND timestamp < today() \
               AND tenant_id = '{t}' AND event_type = 'dns' AND src_ip != '' \
             GROUP BY src_ip"
        )
    ).await;

    // 2. Distinct external destinations per IP yesterday
    let prv = is_private("dst_ip");
    baseline_compute(ch, tenant, &db, &t, "ext_dst_count", midnight,
        &format!(
            "SELECT src_ip, toFloat64(count(DISTINCT dst_ip)) AS value_f, '' AS value_s \
             FROM {db}.ndr_events \
             WHERE timestamp >= yesterday() AND timestamp < today() \
               AND tenant_id = '{t}' \
               AND NOT {prv} AND dst_ip != '' AND src_ip != '' \
             GROUP BY src_ip"
        )
    ).await;

    // 3. Total event count per IP yesterday (activity level)
    baseline_compute(ch, tenant, &db, &t, "event_count", midnight,
        &format!(
            "SELECT src_ip, toFloat64(count()) AS value_f, '' AS value_s \
             FROM {db}.ndr_events \
             WHERE timestamp >= yesterday() AND timestamp < today() \
               AND tenant_id = '{t}' AND src_ip != '' \
             GROUP BY src_ip"
        )
    ).await;

    // 4. Known external contacts — one row per (src_ip, ext_dst_ip) seen yesterday
    //    value_s = dst_ip so we can anti-join for new-contact detection
    let prv2 = is_private("dst_ip");
    baseline_compute(ch, tenant, &db, &t, "ext_contact", midnight,
        &format!(
            "SELECT src_ip, toFloat64(1) AS value_f, dst_ip AS value_s \
             FROM {db}.ndr_events \
             WHERE timestamp >= yesterday() AND timestamp < today() \
               AND tenant_id = '{t}' \
               AND NOT {prv2} AND dst_ip != '' AND src_ip != '' \
             GROUP BY src_ip, dst_ip"
        )
    ).await;

    // 5. Off-hours event count per IP yesterday (23:00–05:00 UTC)
    baseline_compute(ch, tenant, &db, &t, "off_hours_count", midnight,
        &format!(
            "SELECT src_ip, toFloat64(count()) AS value_f, '' AS value_s \
             FROM {db}.ndr_events \
             WHERE timestamp >= yesterday() AND timestamp < today() \
               AND tenant_id = '{t}' AND src_ip != '' \
               AND (toHour(timestamp) >= 23 OR toHour(timestamp) < 5) \
             GROUP BY src_ip"
        )
    ).await;

    tracing::info!("multiflow: baseline refresh done for {}", tenant);
}

async fn baseline_compute(
    ch:      &ClickhouseStorage,
    tenant:  &str,
    db:      &str,
    _t:      &str,
    metric:  &str,
    window:  u32,
    query:   &str,
) {
    let rows: Vec<BRow> = match ch.client.query(query).fetch_all().await {
        Ok(r)  => r,
        Err(e) => {
            tracing::warn!("multiflow baseline [{}/{}]: {}", tenant, metric, e);
            return;
        }
    };
    if rows.is_empty() { return; }

    let table = format!("{}.ndr_baselines", db);
    let now   = now_ts();
    let mut insert = match ch.client.insert(&table) {
        Ok(i)  => i,
        Err(e) => { tracing::warn!("multiflow baseline insert open [{}/{}]: {}", tenant, metric, e); return; }
    };
    for row in rows {
        let b = NdrBaseline {
            tenant_id:  tenant.to_string(),
            src_ip:     row.src_ip,
            metric:     metric.to_string(),
            value_f:    row.value_f,
            value_s:    row.value_s,
            window_ts:  window,
            updated_at: now,
        };
        if let Err(e) = insert.write(&b).await {
            tracing::warn!("multiflow baseline write [{}/{}]: {}", tenant, metric, e);
        }
    }
    if let Err(e) = insert.end().await {
        tracing::warn!("multiflow baseline end [{}/{}]: {}", tenant, metric, e);
    }
}

// ── Tier 3b: anomaly detection against baselines ──────────────────────────────

async fn run_tier3(ch: &ClickhouseStorage, sup: &mut SuppressMap) {
    let tenants = match ch.get_all_tenants().await {
        Ok(t) => t,
        Err(e) => { tracing::warn!("multiflow tier3: get_all_tenants: {}", e); return; }
    };
    for tenant in &tenants {
        let db = db_for(tenant);
        let t  = esc(tenant);
        // Skip Tier 3 for tenants with no baseline yet — avoids alert storms on
        // day-zero deployments where every connection looks "new" or "anomalous".
        let baseline_rows: u64 = ch.client
            .query(&format!(
                "SELECT count() FROM {db}.ndr_baselines WHERE tenant_id = '{t}'"
            ))
            .fetch_one::<u64>().await.unwrap_or(0);
        if baseline_rows == 0 {
            tracing::debug!("multiflow tier3: skipping {} — no baselines yet", tenant);
            continue;
        }
        detect_volume_anomaly(ch, tenant, sup).await;
        detect_new_external_contact(ch, tenant, sup).await;
        detect_abnormal_hours(ch, tenant, sup).await;
    }
}

// Volume anomaly: last-hour event count > 3× 7-day hourly average
async fn detect_volume_anomaly(ch: &ClickhouseStorage, tenant: &str, sup: &mut SuppressMap) {
    let db = db_for(tenant);
    let t  = esc(tenant);
    let q = format!(
        "SELECT e.src_ip, \
                toUInt64(count()) AS today_cnt, \
                avg(b.value_f / 24.0) AS avg_hourly \
         FROM {db}.ndr_events e \
         LEFT JOIN ( \
             SELECT src_ip, avg(value_f) AS value_f \
             FROM {db}.ndr_baselines \
             WHERE metric = 'event_count' \
               AND window_ts >= now() - INTERVAL 7 DAY \
               AND tenant_id = '{t}' \
             GROUP BY src_ip \
         ) b ON e.src_ip = b.src_ip \
         WHERE e.timestamp > now() - INTERVAL 1 HOUR \
           AND e.tenant_id = '{t}' AND e.src_ip != '' \
         GROUP BY e.src_ip \
         HAVING today_cnt > 3 * avg_hourly AND avg_hourly > 10"
    );
    let rows: Vec<VolAnomaly> = ch.client.query(&q).fetch_all().await.unwrap_or_default();
    for r in rows {
        if is_suppressed(sup, "volanom", tenant, &r.src_ip, SUP_VOL_ANOMALY) { continue; }
        tracing::info!("multiflow[vol-anomaly] {}/{}: {} events vs avg {:.1}/hr",
            tenant, r.src_ip, r.today_cnt, r.avg_hourly);
        let sid = sensor_for(ch, &db, tenant, &r.src_ip).await;
        emit(ch, tenant, &make_cid("volanom", tenant, &r.src_ip),
            &r.src_ip, "", 75.0,
            vec!["volume-anomaly".into(), "t:exfiltration".into()], &sid).await;
    }
}

// New external contact: (src_ip, dst_ip) pair seen in last hour
// that has NO entry in the 30-day ext_contact baseline
async fn detect_new_external_contact(ch: &ClickhouseStorage, tenant: &str, sup: &mut SuppressMap) {
    let db  = db_for(tenant);
    let t   = esc(tenant);
    let prv = is_private("e.dst_ip");
    let q = format!(
        "SELECT DISTINCT e.src_ip, e.dst_ip \
         FROM {db}.ndr_events e \
         WHERE e.timestamp > now() - INTERVAL 1 HOUR \
           AND e.tenant_id = '{t}' \
           AND NOT {prv} \
           AND e.dst_ip != '' AND e.src_ip != '' \
           AND (e.src_ip, e.dst_ip) NOT IN ( \
               SELECT src_ip, value_s \
               FROM {db}.ndr_baselines \
               WHERE metric = 'ext_contact' \
                 AND tenant_id = '{t}' \
           ) \
         LIMIT 50"
    );
    let rows: Vec<NewContact> = ch.client.query(&q).fetch_all().await.unwrap_or_default();
    for r in rows {
        let key = format!("{}_{}", r.src_ip, r.dst_ip);
        if is_suppressed(sup, "newcontact", tenant, &key, SUP_NEW_CONTACT) { continue; }
        tracing::info!("multiflow[new-contact] {}/{} → {} (first seen in 30d)",
            tenant, r.src_ip, r.dst_ip);
        let sid = sensor_for(ch, &db, tenant, &r.src_ip).await;
        emit(ch, tenant, &make_cid("newcontact", tenant, &key),
            &r.src_ip, &r.dst_ip, 65.0,
            vec!["new-external-contact".into(), "t:command-and-control".into()], &sid).await;
    }
}

// ICMP flood: >500 ICMP events from one source in 5 min
// Covers ping floods, ICMP tunneling probe bursts, and smurf-style amplification attempts.
async fn detect_icmp_flood(ch: &ClickhouseStorage, tenant: &str, sup: &mut SuppressMap) {
    let db = db_for(tenant);
    let t  = esc(tenant);
    let q = format!(
        "SELECT src_ip, count() AS cnt \
         FROM {db}.ndr_events \
         WHERE timestamp > now() - INTERVAL 5 MINUTE \
           AND tenant_id = '{t}' \
           AND proto = 'icmp' AND src_ip != '' \
         GROUP BY src_ip \
         HAVING cnt > 500"
    );
    let rows: Vec<OneCount> = ch.client.query(&q).fetch_all().await.unwrap_or_default();
    for r in rows {
        if is_suppressed(sup, "icmpflood", tenant, &r.src_ip, SUP_ICMP_FLOOD) { continue; }
        tracing::info!("multiflow[icmp-flood] {}/{}: {} ICMP events/5min",
            tenant, r.src_ip, r.cnt);
        let sid = sensor_for(ch, &db, tenant, &r.src_ip).await;
        emit(ch, tenant, &make_cid("icmpflood", tenant, &r.src_ip),
            &r.src_ip, "", 70.0,
            vec!["icmp-flood".into(), "t:impact".into()], &sid).await;
    }
}

// Abnormal hours: internal IP active during 23:00–05:00 UTC with events
// exceeding 3× its 7-day off-hours baseline. Only runs during off-hours.
#[derive(Row, Serialize, Deserialize)]
struct OffHoursRow {
    src_ip:      String,
    current_cnt: u64,
    avg_baseline: f64,
}

async fn detect_abnormal_hours(ch: &ClickhouseStorage, tenant: &str, sup: &mut SuppressMap) {
    let hour = chrono::Utc::now().hour();
    // Only fire during off-hours (23:00–04:59 UTC)
    if hour >= 5 && hour < 23 { return; }

    let db      = db_for(tenant);
    let t       = esc(tenant);
    let prv_src = is_private("e.src_ip");
    let q = format!(
        "SELECT e.src_ip, \
                toUInt64(count()) AS current_cnt, \
                coalesce(avg(b.value_f), 0.0) AS avg_baseline \
         FROM {db}.ndr_events e \
         LEFT JOIN ( \
             SELECT src_ip, avg(value_f) AS value_f \
             FROM {db}.ndr_baselines \
             WHERE metric = 'off_hours_count' \
               AND window_ts >= now() - INTERVAL 7 DAY \
               AND tenant_id = '{t}' \
             GROUP BY src_ip \
         ) b ON e.src_ip = b.src_ip \
         WHERE e.timestamp > now() - INTERVAL 2 HOUR \
           AND e.tenant_id = '{t}' \
           AND {prv_src} AND e.src_ip != '' \
         GROUP BY e.src_ip \
         HAVING current_cnt > 3 * avg_baseline AND avg_baseline > 5"
    );
    let rows: Vec<OffHoursRow> = ch.client.query(&q).fetch_all().await.unwrap_or_default();
    for r in rows {
        if is_suppressed(sup, "abnormalhours", tenant, &r.src_ip, SUP_ABNORMAL_HOURS) { continue; }
        tracing::info!("multiflow[abnormal-hours] {}/{}: {} events vs avg {:.1} off-hours baseline",
            tenant, r.src_ip, r.current_cnt, r.avg_baseline);
        let sid = sensor_for(ch, &db, tenant, &r.src_ip).await;
        emit(ch, tenant, &make_cid("abnormalhours", tenant, &r.src_ip),
            &r.src_ip, "", 72.0,
            vec!["abnormal-hours".into(), "insider-threat".into(), "t:initial-access".into()], &sid).await;
    }
}
