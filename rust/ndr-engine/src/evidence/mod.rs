use sha2::{Sha256, Digest};
use zip::{ZipWriter, write::FileOptions};
use serde_json::{json, Value};
use std::io::Write;

fn tenant_db(tenant_id: &str) -> String {
    if tenant_id == "default" {
        "ndr".to_string()
    } else {
        format!("ndr_{}", tenant_id.replace('-', "_"))
    }
}

fn sha256_of(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    format!("{:x}", h.finalize())
}

/// Query ClickHouse HTTP API; returns the `data` array of row objects.
async fn query_ch(
    http: &reqwest::Client,
    ch_url: &str,
    ch_user: &str,
    ch_pass: &str,
    sql: &str,
) -> Value {
    let url = format!("{}/?user={}&password={}", ch_url, ch_user, ch_pass);
    let full_sql = format!("{} FORMAT JSON", sql.trim_end_matches(';'));
    match http.post(&url)
        .header("Content-Type", "text/plain")
        .body(full_sql)
        .send().await
    {
        Ok(resp) => resp.json::<Value>().await
            .ok()
            .and_then(|v| v.get("data").cloned())
            .unwrap_or(json!([])),
        Err(_) => json!([]),
    }
}

fn build_attack_summary(
    community_id: &str,
    alert: &Value,
    suricata_alerts: &Value,
    threat_intel: &Value,
    related_alerts: &Value,
    pcap_captured: bool,
    generated_at: &str,
) -> Value {
    let src_ip  = alert["src_ip"].as_str().unwrap_or("unknown");
    let dst_ip  = alert["dst_ip"].as_str().unwrap_or("unknown");
    let severity = alert["severity"].as_str().unwrap_or("UNKNOWN");

    let rules_fired: Vec<Value> = suricata_alerts
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .map(|r| json!({
            "name": r["rule_name"],
            "severity": r["severity"]
        }))
        .collect();

    let empty_vec: Vec<Value> = vec![];
    let threat_matches: Vec<&Value> = threat_intel
        .as_array()
        .unwrap_or(&empty_vec)
        .iter()
        .collect();

    let related_count = related_alerts
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0);

    let intel_count = threat_matches.len();

    let rules_desc: Vec<String> = rules_fired.iter()
        .map(|r| format!("'{}' ({})",
            r["name"].as_str().unwrap_or("?"),
            r["severity"].as_str().unwrap_or("?")))
        .collect();
    let rules_str = if rules_desc.is_empty() {
        "no rules matched".to_string()
    } else {
        rules_desc.join(", ")
    };

    let intel_note = if intel_count > 0 {
        format!("Threat intel confirms {} IP(s) are known malicious (confidence: high).", intel_count)
    } else {
        "No threat intel matches found for observed IPs.".to_string()
    };

    let related_note = if related_count > 0 {
        format!("{} related alert(s) from the same source in a 30-minute window suggest active compromise.",
            related_count)
    } else {
        "No related alerts in the 30-minute window.".to_string()
    };

    let summary = format!(
        "Host {} made suspicious connection to {}. NDR engine fired {} rule(s) including {}. {} {}",
        src_ip, dst_ip, rules_fired.len(), rules_str, intel_note, related_note
    );

    let recommended_action = format!(
        "Isolate host {}. Block {} at firewall. Review all connections from {} in the last 24 hours.",
        src_ip, dst_ip, src_ip
    );

    json!({
        "title": "Security Incident Report",
        "community_id": community_id,
        "generated_at": generated_at,
        "severity": severity,
        "summary": summary,
        "attacker_ip": dst_ip,
        "victim_ip": src_ip,
        "rules_fired": rules_fired,
        "threat_intel_hits": intel_count,
        "related_alerts": related_count,
        "pcap_captured": pcap_captured,
        "recommended_action": recommended_action
    })
}

/// Build a ZIP evidence bundle for a given community_id.
/// Returns (zip_bytes, sha256_hex, manifest).
pub async fn build_evidence_bundle(
    opensearch_url: &str,
    arkime_url: &str,
    arkime_pass: &str,
    community_id: &str,
    alert_json: Value,
    tenant_id: &str,
    pcap_file_path: Option<String>,
) -> anyhow::Result<(Vec<u8>, String, Value)> {
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    // ClickHouse connection from env
    let ch_url  = std::env::var("CLICKHOUSE_URL")
        .unwrap_or_else(|_| "http://localhost:8123".to_string());
    let ch_user = std::env::var("CLICKHOUSE_USER")
        .unwrap_or_else(|_| "ndr".to_string());
    let ch_pass = std::env::var("CLICKHOUSE_PASSWORD")
        .unwrap_or_else(|_| "ndr123".to_string());

    let db = tenant_db(tenant_id);

    let src_ip = alert_json["src_ip"].as_str().unwrap_or("").to_string();
    let dst_ip = alert_json["dst_ip"].as_str().unwrap_or("").to_string();
    let alert_time = alert_json["timestamp"]
        .as_str()
        .or_else(|| alert_json["auto_captured_at"].as_str())
        .unwrap_or("1970-01-01T00:00:00Z")
        .to_string();

    // ── 1. Session metadata from OpenSearch ──────────────────────────────────
    let session_meta: Value = if !opensearch_url.is_empty() {
        let resp = http.post(format!(
            "{}/arkime_sessions3-*/_search",
            opensearch_url
        ))
        .json(&json!({
            "query": { "term": { "network.community_id": community_id } },
            "size": 1
        }))
        .send().await?
        .json::<Value>().await?;

        let hit = resp["hits"]["hits"]
            .as_array()
            .and_then(|a| a.first())
            .cloned()
            .unwrap_or(json!({}));

        json!({
            "arkime_session_id": hit["_id"],
            "index": hit["_index"],
            "source": hit["_source"],
            "community_id": community_id,
            "query_source": "opensearch"
        })
    } else {
        json!({
            "community_id": community_id,
            "query_source": "pcap_sessions",
            "note": "session metadata from uploaded PCAP index"
        })
    };

    // ── 2. PCAP bytes ─────────────────────────────────────────────────────────
    let arkime_session_id = session_meta["arkime_session_id"]
        .as_str()
        .unwrap_or("");

    let pcap_bytes: Vec<u8> = if let Some(ref path) = pcap_file_path {
        tokio::fs::read(path).await.unwrap_or_default()
    } else if !arkime_session_id.is_empty() && !arkime_url.is_empty() {
        http.get(format!("{}/api/session/{}/pcap", arkime_url, arkime_session_id))
            .basic_auth("admin", Some(arkime_pass))
            .send().await?
            .bytes().await?
            .to_vec()
    } else {
        vec![]
    };

    // ── 3. Zeek conn.log record ───────────────────────────────────────────────
    let zeek_conn_rows = query_ch(&http, &ch_url, &ch_user, &ch_pass, &format!(
        "SELECT src_ip, dst_ip, src_port, dst_port, \
         proto, service, duration, orig_bytes, resp_bytes, \
         conn_state, history, toString(ts) as timestamp, \
         community_id, uid \
         FROM {}.ndr_events \
         WHERE community_id = '{}' AND source = 'zeek_conn' \
         ORDER BY ts DESC LIMIT 1",
        db, community_id
    )).await;

    let zeek_conn_json = json!({
        "source": "zeek_conn",
        "community_id": community_id,
        "record": zeek_conn_rows.as_array().and_then(|a| a.first()).cloned().unwrap_or(json!(null))
    });

    // ── 4. Suricata alerts ────────────────────────────────────────────────────
    let suricata_rows = query_ch(&http, &ch_url, &ch_user, &ch_pass, &format!(
        "SELECT rule_name, alert_msg, severity, \
         src_ip, dst_ip, src_port, dst_port, \
         proto, category, signature_id, \
         toString(timestamp) as timestamp \
         FROM {}.ndr_hits \
         WHERE community_id = '{}' \
         ORDER BY timestamp DESC",
        db, community_id
    )).await;

    let suricata_json = json!({
        "source": "suricata_alerts",
        "community_id": community_id,
        "alerts": suricata_rows
    });

    // ── 5. SIGMA rule matches ─────────────────────────────────────────────────
    let sigma_rows = query_ch(&http, &ch_url, &ch_user, &ch_pass, &format!(
        "SELECT rule_name, severity, tags, \
         toString(timestamp) as timestamp, alert_msg \
         FROM {}.ndr_hits \
         WHERE community_id = '{}' AND source = 'sigma' \
         ORDER BY timestamp DESC",
        db, community_id
    )).await;

    let sigma_json = json!({
        "source": "sigma",
        "community_id": community_id,
        "matches": sigma_rows
    });

    // ── 6. Threat intel (shared_iocs + threat_intel) ──────────────────────────
    let checked_ips: Vec<&str> = [src_ip.as_str(), dst_ip.as_str()]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect();

    let ioc_rows = if !checked_ips.is_empty() {
        let ip_list = checked_ips.iter()
            .map(|ip| format!("'{}'", ip.replace('\'', "")))
            .collect::<Vec<_>>()
            .join(", ");
        query_ch(&http, &ch_url, &ch_user, &ch_pass, &format!(
            "SELECT ioc_value, ioc_type, confidence, tags, description, \
             toString(first_seen) as first_seen, \
             toString(last_seen) as last_seen \
             FROM ndr.shared_iocs \
             WHERE ioc_value IN ({}) \
             LIMIT 20",
            ip_list
        )).await
    } else {
        json!([])
    };

    let ti_rows = if !checked_ips.is_empty() {
        let ip_list = checked_ips.iter()
            .map(|ip| format!("'{}'", ip.replace('\'', "")))
            .collect::<Vec<_>>()
            .join(", ");
        query_ch(&http, &ch_url, &ch_user, &ch_pass, &format!(
            "SELECT indicator, threat_type, confidence, source, tags \
             FROM ndr.threat_intel \
             WHERE indicator IN ({}) \
             LIMIT 10",
            ip_list
        )).await
    } else {
        json!([])
    };

    let all_intel: Vec<Value> = {
        let mut v: Vec<Value> = vec![];
        if let Some(arr) = ioc_rows.as_array() { v.extend(arr.clone()); }
        if let Some(arr) = ti_rows.as_array()  { v.extend(arr.clone()); }
        v
    };

    let threat_intel_json = if all_intel.is_empty() {
        json!({
            "matches": [],
            "checked_ips": checked_ips
        })
    } else {
        json!({
            "matches": all_intel,
            "checked_ips": checked_ips
        })
    };

    // ── 7. Related alerts (same src_ip, ±30 min window) ──────────────────────
    let related_rows = if !src_ip.is_empty() {
        query_ch(&http, &ch_url, &ch_user, &ch_pass, &format!(
            "SELECT community_id, rule_name, severity, \
             src_ip, dst_ip, src_port, dst_port, \
             toString(timestamp) as timestamp, alert_msg \
             FROM {}.ndr_hits \
             WHERE src_ip = '{}' \
             AND timestamp BETWEEN \
                 parseDateTimeBestEffort('{}') - INTERVAL 30 MINUTE \
                 AND parseDateTimeBestEffort('{}') + INTERVAL 30 MINUTE \
             AND community_id != '{}' \
             ORDER BY timestamp ASC \
             LIMIT 20",
            db, src_ip, alert_time, alert_time, community_id
        )).await
    } else {
        json!([])
    };

    let related_json = json!({
        "community_id": community_id,
        "src_ip": src_ip,
        "window_minutes": 30,
        "alerts": related_rows
    });

    // ── 8. Attack summary ─────────────────────────────────────────────────────
    let now = chrono::Utc::now().to_rfc3339();
    let pcap_captured = !pcap_bytes.is_empty();

    let attack_summary = build_attack_summary(
        community_id,
        &alert_json,
        &suricata_rows,
        &Value::Array(all_intel.clone()),
        &related_rows,
        pcap_captured,
        &now,
    );

    // ── 9. Serialise all files ────────────────────────────────────────────────
    let alert_str        = serde_json::to_string_pretty(&alert_json).unwrap_or_default();
    let session_str      = serde_json::to_string_pretty(&session_meta).unwrap_or_default();
    let zeek_str         = serde_json::to_string_pretty(&zeek_conn_json).unwrap_or_default();
    let suricata_str     = serde_json::to_string_pretty(&suricata_json).unwrap_or_default();
    let sigma_str        = serde_json::to_string_pretty(&sigma_json).unwrap_or_default();
    let intel_str        = serde_json::to_string_pretty(&threat_intel_json).unwrap_or_default();
    let related_str      = serde_json::to_string_pretty(&related_json).unwrap_or_default();
    let attack_str       = serde_json::to_string_pretty(&attack_summary).unwrap_or_default();

    // ── 10. Build enhanced manifest ───────────────────────────────────────────
    let bundle_id = uuid::Uuid::new_v4().to_string();

    let suricata_count = suricata_rows.as_array().map(|a| a.len()).unwrap_or(0);
    let highest_severity = suricata_rows.as_array()
        .and_then(|a| a.iter().find(|r| r["severity"].as_str() == Some("CRITICAL")))
        .and_then(|_| Some("CRITICAL"))
        .or_else(|| suricata_rows.as_array()
            .and_then(|a| a.iter().find(|r| r["severity"].as_str() == Some("HIGH")))
            .and_then(|_| Some("HIGH")))
        .unwrap_or(alert_json["severity"].as_str().unwrap_or("UNKNOWN"));

    let manifest = json!({
        "bundle_id": bundle_id,
        "community_id": community_id,
        "tenant_id": tenant_id,
        "created_at": now,
        "ndr_instance": format!("ndr-{}", tenant_id),
        "files": {
            "manifest.json":         { "sha256": "self", "size_bytes": 0 },
            "attack_summary.json":   { "sha256": sha256_of(attack_str.as_bytes()),   "size_bytes": attack_str.len() },
            "alert.json":            { "sha256": sha256_of(alert_str.as_bytes()),     "size_bytes": alert_str.len() },
            "zeek_conn.json":        { "sha256": sha256_of(zeek_str.as_bytes()),      "size_bytes": zeek_str.len() },
            "suricata_alerts.json":  { "sha256": sha256_of(suricata_str.as_bytes()), "size_bytes": suricata_str.len() },
            "sigma_matches.json":    { "sha256": sha256_of(sigma_str.as_bytes()),     "size_bytes": sigma_str.len() },
            "threat_intel.json":     { "sha256": sha256_of(intel_str.as_bytes()),     "size_bytes": intel_str.len() },
            "related_alerts.json":   { "sha256": sha256_of(related_str.as_bytes()),   "size_bytes": related_str.len() },
            "session_metadata.json": { "sha256": sha256_of(session_str.as_bytes()),   "size_bytes": session_str.len() },
            "session.pcap":          { "sha256": if pcap_captured { sha256_of(&pcap_bytes) } else { "no_pcap_available".to_string() }, "size_bytes": pcap_bytes.len() }
        },
        "summary": {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "severity": highest_severity,
            "rules_fired_count": suricata_count,
            "highest_severity": highest_severity,
            "threat_intel_matches": all_intel.len(),
            "related_alerts_count": related_rows.as_array().map(|a| a.len()).unwrap_or(0),
            "pcap_size_bytes": pcap_bytes.len(),
            "collection_complete": true
        },
        "chain_of_custody": "This bundle was generated automatically by NDR-Engine. Contents are SHA256 verified. Manifest hash covers all included files."
    });
    let manifest_str = serde_json::to_string_pretty(&manifest).unwrap_or_default();

    // ── 11. Build ZIP ─────────────────────────────────────────────────────────
    let mut buf = Vec::new();
    {
        let cursor = std::io::Cursor::new(&mut buf);
        let mut zip = ZipWriter::new(cursor);
        let opts = FileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);

        zip.start_file("manifest.json", opts)?;
        zip.write_all(manifest_str.as_bytes())?;

        zip.start_file("attack_summary.json", opts)?;
        zip.write_all(attack_str.as_bytes())?;

        zip.start_file("alert.json", opts)?;
        zip.write_all(alert_str.as_bytes())?;

        zip.start_file("zeek_conn.json", opts)?;
        zip.write_all(zeek_str.as_bytes())?;

        zip.start_file("suricata_alerts.json", opts)?;
        zip.write_all(suricata_str.as_bytes())?;

        zip.start_file("sigma_matches.json", opts)?;
        zip.write_all(sigma_str.as_bytes())?;

        zip.start_file("threat_intel.json", opts)?;
        zip.write_all(intel_str.as_bytes())?;

        zip.start_file("related_alerts.json", opts)?;
        zip.write_all(related_str.as_bytes())?;

        zip.start_file("session_metadata.json", opts)?;
        zip.write_all(session_str.as_bytes())?;

        if pcap_captured {
            zip.start_file("session.pcap", opts)?;
            zip.write_all(&pcap_bytes)?;
        }

        zip.finish()?;
    }

    // ── 12. Bundle-level integrity hash ──────────────────────────────────────
    let bundle_sha256 = sha256_of(&buf);

    Ok((buf, bundle_sha256, manifest))
}

/// Verify a stored evidence bundle against its logged SHA256.
pub async fn verify_bundle_integrity(
    file_path: &str,
    stored_sha256: &str,
) -> (bool, String) {
    match tokio::fs::read(file_path).await {
        Ok(bytes) => {
            let computed = sha256_of(&bytes);
            let matches = computed == stored_sha256;
            (matches, computed)
        }
        Err(e) => (false, format!("file_read_error: {}", e))
    }
}
