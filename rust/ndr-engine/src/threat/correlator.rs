use std::sync::Arc;
use tracing::{info, warn};

use crate::ai::provider::{generate, UseCase};
use crate::storage::clickhouse::tenant_db_pub;

pub fn spawn_correlator(ch: Arc<crate::storage::ClickhouseStorage>) {
    tokio::spawn(async move {
        // Delay so collector runs first and populates threat_intel
        tokio::time::sleep(std::time::Duration::from_secs(900)).await;
        loop {
            match ch.get_all_tenants().await {
                Ok(tenants) => {
                    for tenant_id in tenants {
                        if let Err(e) = run_correlation(&ch, &tenant_id).await {
                            warn!("Correlation failed for {}: {}", tenant_id, e);
                        }
                    }
                }
                Err(e) => warn!("correlator: failed to get tenants: {}", e),
            }
            info!("AI correlation cycle complete — next run in 6 hours");
            tokio::time::sleep(std::time::Duration::from_secs(6 * 3600)).await;
        }
    });
}

async fn run_correlation(
    ch: &crate::storage::ClickhouseStorage,
    tenant_id: &str,
) -> anyhow::Result<()> {
    let db = tenant_db_pub(tenant_id);

    // ── 1. Internet threat patterns (today) ──────────────────────────────────

    #[derive(clickhouse::Row, serde::Deserialize)]
    struct ThreatRow {
        source:         String,
        attack_type:    String,
        severity:       String,
        ioc_value:      String,
        description:    String,
        threat_pattern: String,
    }

    let threat_rows = ch.client
        .query("SELECT source, attack_type, severity, ioc_value, description, threat_pattern \
                FROM ndr.threat_intel \
                WHERE collected_at >= now() - INTERVAL 24 HOUR \
                AND threat_pattern != '' \
                ORDER BY collected_at DESC LIMIT 30")
        .fetch_all::<ThreatRow>().await
        .unwrap_or_default();

    if threat_rows.is_empty() {
        info!("correlator: no enriched threat patterns yet for tenant {}", tenant_id);
        return Ok(());
    }

    // ── 2. YOUR network context (last 6h) ────────────────────────────────────

    // Top destination ports
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct PortRow { dst_port: u16, cnt: u64 }
    let top_ports = ch.client
        .query(&format!(
            "SELECT dst_port, count() as cnt \
             FROM {}.ndr_events \
             WHERE timestamp >= now() - INTERVAL 6 HOUR AND dst_port > 0 \
             GROUP BY dst_port ORDER BY cnt DESC LIMIT 15",
            db
        ))
        .fetch_all::<PortRow>().await.unwrap_or_default();

    // Top Suricata rule hits
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct RuleRow { rule_name: String, cnt: u64 }
    let top_rules = ch.client
        .query(&format!(
            "SELECT rule_name, count() as cnt \
             FROM {}.ndr_hits \
             WHERE timestamp >= now() - INTERVAL 6 HOUR \
             AND community_id LIKE '1:%' \
             GROUP BY rule_name ORDER BY cnt DESC LIMIT 20",
            db
        ))
        .fetch_all::<RuleRow>().await.unwrap_or_default();

    // Exposure summary
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct ExposureRow {
        rdp_sessions:            u64,
        ssh_sessions:            u64,
        #[allow(dead_code)]
        brute_force:             u64,
        #[allow(dead_code)]
        c2_like:                 u64,
        large_outbound:          u64,
        unique_external:         u64,
    }
    let exposure = ch.client
        .query(&format!(
            "SELECT \
               countIf(dst_port = 3389 OR src_port = 3389) as rdp_sessions, \
               countIf(dst_port = 22   OR src_port = 22)   as ssh_sessions, \
               0 as brute_force, 0 as c2_like, \
               countIf(bytes_sent > 10000000)               as large_outbound, \
               uniqExact(dst_ip)                             as unique_external \
             FROM {}.ndr_events \
             WHERE timestamp >= now() - INTERVAL 6 HOUR",
            db
        ))
        .fetch_all::<ExposureRow>().await.unwrap_or_default();

    let exp = exposure.into_iter().next().unwrap_or(ExposureRow {
        rdp_sessions: 0, ssh_sessions: 0, brute_force: 0,
        c2_like: 0, large_outbound: 0, unique_external: 0,
    });

    // Brute force count from ndr_hits
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct BruteRow { cnt: u64 }
    let brute = ch.client
        .query(&format!(
            "SELECT count() as cnt FROM {}.ndr_hits \
             WHERE timestamp >= now() - INTERVAL 6 HOUR \
             AND (lower(rule_name) LIKE '%brute%' OR lower(rule_name) LIKE '%ssh%failed%')",
            db
        ))
        .fetch_all::<BruteRow>().await.unwrap_or_default();
    let brute_count = brute.into_iter().next().map(|r| r.cnt).unwrap_or(0);

    // IOC matches count
    let ioc_matches = super::analyzer::match_iocs(ch, tenant_id).await;

    // ── 3. Build AI prompt ────────────────────────────────────────────────────

    let port_context = top_ports.iter()
        .map(|p| format!("{}({})", p.dst_port, p.cnt))
        .collect::<Vec<_>>().join(", ");

    let rules_context = top_rules.iter().take(10)
        .map(|r| format!("{}({})", r.rule_name, r.cnt))
        .collect::<Vec<_>>().join(", ");

    // Format threat patterns — deduplicate by attack_type, keep richest
    let mut seen_types: std::collections::HashSet<String> = Default::default();
    let mut threat_lines: Vec<String> = vec![];
    for r in &threat_rows {
        if seen_types.contains(&r.attack_type) && threat_lines.len() > 5 { continue; }
        seen_types.insert(r.attack_type.clone());
        let pattern = if !r.threat_pattern.is_empty() {
            r.threat_pattern.chars().take(200).collect::<String>()
        } else {
            r.description.clone()
        };
        let ioc_hint = if !r.ioc_value.is_empty() {
            format!(" [IOC: {}]", r.ioc_value)
        } else { String::new() };
        threat_lines.push(format!("- [{}] {} ({}){}: {}", r.source, r.attack_type, r.severity, ioc_hint, pattern));
    }

    let ioc_context = if ioc_matches.is_empty() {
        "No confirmed IOC matches in current traffic.".to_string()
    } else {
        let lines: Vec<String> = ioc_matches.iter().map(|m| {
            format!("  {} ({} traffic) — {} from {} [{}]", m.ip, m.direction, m.attack_type, m.source, m.severity)
        }).collect();
        format!("CONFIRMED IOC MATCHES IN YOUR TRAFFIC ({}):\n{}", ioc_matches.len(), lines.join("\n"))
    };

    let system = format!(
        "You are ARIA, an NDR threat correlation engine. \
         Your job is to find which internet threats ACTUALLY match this network's exposure. \
         Be specific — name the threat, the matching port/service, and the risk path. \
         Tenant: {}. Date: {}.",
        tenant_id,
        chrono::Utc::now().format("%Y-%m-%d")
    );

    let prompt = format!(
        "THREAT PATTERNS FROM INTERNET (last 24h):\n{}\n\n\
         YOUR NETWORK (last 6h):\n\
         - Top destination ports: {}\n\
         - Suricata alerts fired: {}\n\
         - RDP sessions: {}, SSH sessions: {}\n\
         - Brute force attempts: {}\n\
         - Large outbound transfers (>10MB): {}\n\
         - Unique external destinations: {}\n\n\
         {}\n\n\
         QUESTION: Which of the above threat patterns match this network's attack surface?\n\
         For each match: name the threat, explain why it matches (which port/service/behavior), \
         assign probability (0-100%), and give the #1 action to block it.\n\
         Format each match as:\n\
         THREAT: <name>\n\
         MATCH: <why it matches your network>\n\
         PROBABILITY: <0-100>%\n\
         ACTION: <single most important action>\n\
         ---\n\
         List top 3 matched threats only.",
        threat_lines.join("\n"),
        port_context,
        rules_context,
        exp.rdp_sessions, exp.ssh_sessions,
        brute_count,
        exp.large_outbound,
        exp.unique_external,
        ioc_context,
    );

    let response = generate(ch, UseCase::ThreatPrediction, &system, &prompt).await;
    if response.is_empty() {
        warn!("correlator: empty AI response for tenant {}", tenant_id);
        return Ok(());
    }

    // ── 4. Parse and store each matched threat ────────────────────────────────
    store_correlation_results(ch, tenant_id, &response).await;

    info!("AI correlation complete for tenant {}", tenant_id);
    Ok(())
}

async fn store_correlation_results(
    ch: &crate::storage::ClickhouseStorage,
    tenant_id: &str,
    ai_response: &str,
) {
    // Parse the structured response — split on ---
    let blocks: Vec<&str> = ai_response.split("---").collect();

    for block in &blocks {
        let mut threat_name = String::new();
        let mut match_reason = String::new();
        let mut probability = 0.5f32;
        let mut action = String::new();

        for line in block.lines() {
            let line = line.trim();
            if let Some(v) = line.strip_prefix("THREAT:") {
                threat_name = v.trim().to_string();
            } else if let Some(v) = line.strip_prefix("MATCH:") {
                match_reason = v.trim().to_string();
            } else if let Some(v) = line.strip_prefix("PROBABILITY:") {
                let pct = v.trim().trim_end_matches('%');
                probability = pct.parse::<f32>().unwrap_or(50.0) / 100.0;
            } else if let Some(v) = line.strip_prefix("ACTION:") {
                action = v.trim().to_string();
            }
        }

        if threat_name.is_empty() { continue; }

        let attack_type = super::collector::classify_attack(&threat_name, "");
        let alert_level = if probability > 0.75 { "critical" }
                          else if probability > 0.5 { "high" }
                          else if probability > 0.25 { "medium" }
                          else { "info" };

        let briefing = format!("{} — {}", match_reason, if !action.is_empty() { format!("Action: {}", action) } else { String::new() });
        let recs_json = serde_json::to_string(&[action]).unwrap_or_default();

        let db = crate::storage::clickhouse::tenant_db_pub(tenant_id);
        let q = format!(
            "INSERT INTO {db}.threat_predictions \
             (tenant_id, attack_type, probability, confidence, trend, trend_delta, \
              intel_signal_count, exposure_score, internal_hit_count, \
              explanation, recommendations, aria_briefing, alert_level) \
             VALUES ('{tid}','{at}',{prob:.4},{conf:.4},'stable',0.0,0,0.0,0,'{exp}','{recs}','{briefing}','{al}')",
            db = db,
            tid = esc(tenant_id),
            at = esc(&attack_type),
            prob = probability,
            conf = probability * 0.9,
            exp = esc(&briefing),
            recs = esc(&recs_json),
            briefing = esc(&briefing),
            al = alert_level,
        );
        let _ = ch.client.query(&q).execute().await;
    }
}

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}
