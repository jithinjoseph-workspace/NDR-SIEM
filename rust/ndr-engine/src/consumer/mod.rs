// NDR Engine — Kafka Consumer (pure-Rust via rdkafka)
// License: Apache-2.0

use rdkafka::config::ClientConfig;
use rdkafka::consumer::{Consumer, StreamConsumer};
use rdkafka::message::Message;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::api::AppState;
use crate::normalizer::{NormalizedEvent, EventSource};
use crate::storage::clickhouse::NdrEvent;

// Drains the channel every 100 ms and batch-inserts into ClickHouse.
// One HTTP round-trip per tenant per tick instead of one per event.
async fn batch_writer(
    ch: Arc<crate::storage::clickhouse::ClickhouseStorage>,
    mut rx: mpsc::UnboundedReceiver<(NdrEvent, String)>,
) {
    let mut ticker = tokio::time::interval(tokio::time::Duration::from_millis(100));
    let mut buf: HashMap<String, Vec<NdrEvent>> = HashMap::new();

    loop {
        tokio::select! {
            Some((event, tenant_id)) = rx.recv() => {
                buf.entry(tenant_id).or_default().push(event);
            }
            _ = ticker.tick() => {
                if buf.is_empty() { continue; }
                for (tenant_id, events) in buf.drain() {
                    let ch2 = ch.clone();
                    tokio::spawn(async move {
                        if let Err(e) = ch2.batch_insert_events_for_tenant(events, &tenant_id).await {
                            warn!("ClickHouse batch insert error: {}", e);
                        }
                    });
                }
            }
        }
    }
}

pub async fn start_consumer(state: Arc<AppState>) {
    let brokers = std::env::var("KAFKA_BROKERS")
        .unwrap_or_else(|_| crate::KAFKA_DEFAULT.to_string());

    let instance_id = std::env::var("INSTANCE_ID")
        .unwrap_or_else(|_| "1".to_string());

    let consumer: StreamConsumer = ClientConfig::new()
        .set("group.id", "ndr-engine-group")
        .set("bootstrap.servers", &brokers)
        .set("enable.auto.commit", "true")
        .set("auto.offset.reset", "latest")
        .set("client.id", format!("ndr-engine-{}", instance_id))
        .create()
        .expect("Consumer creation failed");

    consumer
        .subscribe(&["ndr-events"])
        .expect("Topic subscription failed");

    // Channel: consumer sends events here; batch_writer flushes to ClickHouse every 100 ms
    let (ch_tx, ch_rx) = mpsc::unbounded_channel::<(NdrEvent, String)>();
    tokio::spawn(batch_writer(state.ch_storage.clone(), ch_rx));

    info!("Kafka consumer ready — group: ndr-engine-group instance: {}", instance_id);
    use dashmap::DashMap;
    let known_assets: Arc<DashMap<String, u32>> = Arc::new(DashMap::new());

    // Hourly eviction: remove IPs not seen in the last 24h to bound memory under DHCP churn
    {
        let assets_evict = known_assets.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(3600));
            loop {
                ticker.tick().await;
                let cutoff = chrono::Utc::now().timestamp() as u32;
                assets_evict.retain(|_, ts| cutoff.saturating_sub(*ts) < 86400);
            }
        });
    }

    // Background flush: dirty assets in Redis → ClickHouse every 30s
    {
        let ch_flush = state.ch_storage.clone();
        let mut redis_flush = state.redis_mux.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(30));
            loop {
                ticker.tick().await;
                // SCAN instead of KEYS — non-blocking cursor scan, safe at any key count
                let mut dirty_keys: Vec<String> = Vec::new();
                let mut cursor: u64 = 0;
                loop {
                    let (next, batch): (u64, Vec<String>) = redis::cmd("SCAN")
                        .arg(cursor)
                        .arg("MATCH").arg("ndr:assets_dirty:*")
                        .arg("COUNT").arg(100u64)
                        .query_async(&mut redis_flush).await.unwrap_or((0, vec![]));
                    dirty_keys.extend(batch);
                    cursor = next;
                    if cursor == 0 { break; }
                }
                for dirty_key in dirty_keys {
                    let tenant_id = dirty_key.trim_start_matches("ndr:assets_dirty:").to_string();
                    let ips: Vec<String> = redis::cmd("SPOP")
                        .arg(&dirty_key).arg(200u64)
                        .query_async(&mut redis_flush).await.unwrap_or_default();
                    for ip in ips {
                        let hash_key = format!("ndr:asset:{}:{}", tenant_id, ip);
                        // HGETALL returns [field, value, field, value, ...]
                        let pairs: Vec<String> = redis::cmd("HGETALL")
                            .arg(&hash_key)
                            .query_async(&mut redis_flush).await.unwrap_or_default();
                        let mut m: std::collections::HashMap<String,String> = std::collections::HashMap::new();
                        let mut i = 0;
                        while i + 1 < pairs.len() { m.insert(pairs[i].clone(), pairs[i+1].clone()); i += 2; }
                        if m.get("mac").map(|s| s.is_empty()).unwrap_or(true) { continue; }
                        let asset = crate::storage::clickhouse::AssetRow {
                            ip:             ip.clone(),
                            mac:            m.get("mac").cloned().unwrap_or_default(),
                            hostname:       m.get("hostname").cloned().unwrap_or_default(),
                            vendor:         m.get("vendor").cloned().unwrap_or_default(),
                            os_guess:       m.get("os_guess").cloned().unwrap_or_default(),
                            device_type:    m.get("device_type").cloned().unwrap_or_default(),
                            custom_name:    m.get("custom_name").cloned().unwrap_or_default(),
                            tenant_id:      tenant_id.clone(),
                            first_seen:     m.get("first_seen").and_then(|s| s.parse().ok()).unwrap_or(0),
                            last_seen:      m.get("last_seen").and_then(|s| s.parse().ok()).unwrap_or(0),
                            ip_history:     m.get("ip_history").cloned().unwrap_or_else(|| "[]".to_string()),
                            trusted:        0,
                            threat_flagged: 0,
                            role:           String::new(),
                            criticality:    0,
                            open_ports:     "[]".to_string(),
                            subnet_role:    String::new(),
                            ja3_os:         String::new(),
                        };
                        let ch2 = ch_flush.clone();
                        tokio::spawn(async move {
                            let mut final_asset = asset;
                            if let Ok(Some(existing)) = ch2.get_asset_by_ip(&final_asset.tenant_id.clone(), &ip).await {
                                if existing.trusted != 0 { final_asset.trusted = existing.trusted; }
                                if existing.threat_flagged != 0 { final_asset.threat_flagged = existing.threat_flagged; }
                                if !existing.role.is_empty() { final_asset.role = existing.role; }
                                if existing.criticality != 0 { final_asset.criticality = existing.criticality; }
                                if existing.open_ports != "[]" && !existing.open_ports.is_empty() { final_asset.open_ports = existing.open_ports; }
                                if !existing.subnet_role.is_empty() { final_asset.subnet_role = existing.subnet_role; }
                                if !existing.ja3_os.is_empty() { final_asset.ja3_os = existing.ja3_os; }
                            }
                            if let Err(e) = ch2.upsert_asset(&final_asset).await {
                                warn!("Asset flush error {}: {}", ip, e);
                            }
                        });
                    }
                }
            }
        });
    }

    loop {
        match consumer.recv().await {
            Ok(msg) => {
                let payload = match msg.payload() {
                    Some(p) => p,
                    None => continue,
                };

                let raw: serde_json::Value = match serde_json::from_slice(payload) {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                let Some(event) = NormalizedEvent::from_raw(raw.clone()) else { continue; };

                if event.should_drop() { continue; }

                let tenant_id = raw.get("tenant_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("default")
                    .to_string();

                // ── Hash threat-intel: Zeek `files` log + Suricata `fileinfo` ──────
                // Extract SHA256 from the appropriate field location for each source,
                // then check against the MalwareBazaar feed DashSet.
                let is_file_event = event.log_source.as_deref() == Some("files")
                    || event.event_type.as_deref() == Some("fileinfo");
                if is_file_event {
                    let sha256_opt = raw.get("sha256")
                        .or_else(|| raw.get("fileinfo").and_then(|f| f.get("sha256")))
                        .and_then(|v| v.as_str())
                        .filter(|s| s.len() >= 32)
                        .map(|s| s.to_lowercase());

                    if let Some(sha256) = sha256_opt {
                        if state.enrichment.threat_intel.is_malicious_hash(&sha256) {
                            let now_ts  = chrono::Utc::now().timestamp() as u32;
                            let src     = event.source_ip.clone().unwrap_or_default();
                            let dst     = event.dest_ip.clone().unwrap_or_default();
                            // Use sha256 + 5-min bucket so repeated transfers of the
                            // same file within one window collapse to a single alert.
                            let bucket  = now_ts / 300 * 300;
                            let cid     = event.community_id.clone()
                                .unwrap_or_else(|| format!("hash-{}-{}", sha256, bucket));
                            let filename = raw.get("filename")
                                .or_else(|| raw.get("fileinfo").and_then(|f| f.get("filename")))
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let details = serde_json::json!({
                                "sha256":   sha256,
                                "filename": filename,
                                "source":   match event.event_source {
                                    EventSource::Zeek => "zeek-files",
                                    _                 => "suricata-fileinfo",
                                },
                            });
                            let (az, as_) = if event.event_source == EventSource::Zeek {
                                (serde_json::to_string(&details).unwrap_or_else(|_| "{}".into()), "{}".to_string())
                            } else {
                                ("{}".to_string(), serde_json::to_string(&details).unwrap_or_else(|_| "{}".into()))
                            };
                            let ch_hit = crate::storage::clickhouse::NdrHit {
                                timestamp:          now_ts,
                                community_id:       cid,
                                src_ip:             src,
                                dst_ip:             dst,
                                score:              90.0,
                                severity:           "HIGH".to_string(),
                                tags:               vec!["malware-hash".to_string(), "threat-intel".to_string()],
                                sigma_hits:         vec![],
                                threat_intel:       1,
                                src_country:        String::new(),
                                dst_country:        String::new(),
                                tenant_id:          tenant_id.clone(),
                                correlation_status: "hash_match".to_string(),
                                agent_z_details:    az,
                                agent_s_details:    as_,
                                corroborated_at:    0,
                                agent_s_rule_id:    String::new(),
                                agent_s_category:   "malware".to_string(),
                                updated_at:         now_ts,
                                sensor_id:          raw.get("sensor_host")
                                    .and_then(|v| v.as_str()).unwrap_or("").to_string(),
                            };
                            let ch_cl  = state.ch_storage.clone();
                            let tid_cl = tenant_id.clone();
                            let sha_log = sha256.clone();
                            tokio::spawn(async move {
                                if let Err(e) = ch_cl.insert_hit_for_tenant(ch_hit, &tid_cl).await {
                                    tracing::warn!("hash-match hit insert error: {}", e);
                                } else {
                                    tracing::info!(sha256 = %sha_log, tenant = %tid_cl, "malware hash matched — hit created");
                                }
                            });
                        }
                    }
                }
                // ── JA3 threat-intel: Zeek ssl log ──────────────────────────────
                if event.log_source.as_deref() == Some("ssl") {
                    let ja3_opt = raw.get("ja3")
                        .and_then(|v| v.as_str())
                        .filter(|s| s.len() == 32)
                        .map(|s| s.to_lowercase());
                    if let Some(ja3) = ja3_opt {
                        if state.enrichment.threat_intel.is_malicious_ja3(&ja3) {
                            let now_ts = chrono::Utc::now().timestamp() as u32;
                            let src    = event.source_ip.clone().unwrap_or_default();
                            let dst    = event.dest_ip.clone().unwrap_or_default();
                            let cid    = event.community_id.clone()
                                .unwrap_or_else(|| format!("ja3-{}-{}", ja3, now_ts / 300 * 300));
                            let sni    = raw.get("server_name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                            let details = serde_json::json!({ "ja3": ja3, "sni": sni });
                            let ch_hit = crate::storage::clickhouse::NdrHit {
                                timestamp:          now_ts,
                                community_id:       cid,
                                src_ip:             src,
                                dst_ip:             dst,
                                score:              80.0,
                                severity:           "HIGH".to_string(),
                                tags:               vec!["malicious-ja3".to_string(), "threat-intel".to_string(), "encrypted-traffic".to_string()],
                                sigma_hits:         vec![],
                                threat_intel:       1,
                                src_country:        String::new(),
                                dst_country:        String::new(),
                                tenant_id:          tenant_id.clone(),
                                correlation_status: "ja3_match".to_string(),
                                agent_z_details:    serde_json::to_string(&details).unwrap_or_else(|_| "{}".into()),
                                agent_s_details:    "{}".to_string(),
                                corroborated_at:    0,
                                agent_s_rule_id:    String::new(),
                                agent_s_category:   "malware".to_string(),
                                updated_at:         now_ts,
                                sensor_id:          raw.get("sensor_host").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                            };
                            let ch_cl  = state.ch_storage.clone();
                            let tid_cl = tenant_id.clone();
                            let ja3_log = ja3.clone();
                            tokio::spawn(async move {
                                if let Err(e) = ch_cl.insert_hit_for_tenant(ch_hit, &tid_cl).await {
                                    tracing::warn!("ja3-match hit insert error: {}", e);
                                } else {
                                    tracing::info!(ja3 = %ja3_log, tenant = %tid_cl, "malicious JA3 matched — hit created");
                                }
                            });
                        }
                    }
                }

                // ── DoH evasion: HTTPS traffic to known DNS-over-HTTPS providers ─
                // A host bypassing the local resolver to use DoH is a policy violation
                // and common C2 evasion technique.
                {
                    const DOH_IPS: &[&str] = &[
                        "1.1.1.1", "1.0.0.1",                   // Cloudflare
                        "8.8.8.8", "8.8.4.4",                   // Google
                        "9.9.9.9", "149.112.112.112",            // Quad9
                        "208.67.222.222", "208.67.220.220",      // OpenDNS
                        "94.140.14.14",  "94.140.15.15",         // AdGuard
                        "185.228.168.168", "185.228.169.168",    // CleanBrowsing
                        "76.76.2.0", "76.76.10.0",               // Alternate DNS
                    ];
                    let dst_port = event.dest_port.unwrap_or(0);
                    let dst_ip   = event.dest_ip.as_deref().unwrap_or("");
                    let is_conn_or_ssl = matches!(
                        event.log_source.as_deref().or(event.event_type.as_deref()),
                        Some("conn") | Some("ssl") | Some("flow")
                    );
                    if is_conn_or_ssl && dst_port == 443 && DOH_IPS.contains(&dst_ip) {
                        if let Some(src) = event.source_ip.clone() {
                            if crate::enrichment::is_private_ip(&src) {
                                let now_ts = chrono::Utc::now().timestamp() as u32;
                                let bucket = now_ts / 300 * 300;
                                let cid    = event.community_id.clone()
                                    .unwrap_or_else(|| format!("doh-{}-{}-{}", src, dst_ip, bucket));
                                let ch_hit = crate::storage::clickhouse::NdrHit {
                                    timestamp:          now_ts,
                                    community_id:       cid,
                                    src_ip:             src.clone(),
                                    dst_ip:             dst_ip.to_string(),
                                    score:              65.0,
                                    severity:           "MEDIUM".to_string(),
                                    tags:               vec!["doh-evasion".to_string(), "t:command-and-control".to_string()],
                                    sigma_hits:         vec![],
                                    threat_intel:       0,
                                    src_country:        String::new(),
                                    dst_country:        String::new(),
                                    tenant_id:          tenant_id.clone(),
                                    correlation_status: "doh_evasion".to_string(),
                                    agent_z_details:    serde_json::json!({ "dst_ip": dst_ip, "dst_port": 443 }).to_string(),
                                    agent_s_details:    "{}".to_string(),
                                    corroborated_at:    0,
                                    agent_s_rule_id:    String::new(),
                                    agent_s_category:   "policy-violation".to_string(),
                                    updated_at:         now_ts,
                                    sensor_id:          raw.get("sensor_host").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                                };
                                let ch_cl  = state.ch_storage.clone();
                                let tid_cl = tenant_id.clone();
                                let src_log = src.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = ch_cl.insert_hit_for_tenant(ch_hit, &tid_cl).await {
                                        tracing::warn!("doh-evasion hit insert error: {}", e);
                                    } else {
                                        tracing::info!(src = %src_log, tenant = %tid_cl, "DoH evasion detected — hit created");
                                    }
                                });
                            }
                        }
                    }
                }
                // ────────────────────────────────────────────────────────────────

                let source_str = match event.event_source {
                    EventSource::Zeek     => "agent-z",
                    EventSource::Suricata => "agent-s",
                    _ => "unknown",
                }.to_string();

                let ch_event = NdrEvent {
                    timestamp: if event.timestamp > 0 {
                        (event.timestamp / 1000) as u32
                    } else {
                        chrono::Utc::now().timestamp() as u32
                    },
                    source: source_str,
                    src_ip: event.source_ip.clone().unwrap_or_default(),
                    dst_ip: event.dest_ip.clone().unwrap_or_default(),
                    src_port: event.source_port.unwrap_or(0),
                    dst_port: event.dest_port.unwrap_or(0),
                    proto: event.proto.clone().unwrap_or_default(),
                    event_type: event.event_type.clone()
                        .or(event.log_source.clone())
                        .unwrap_or_default(),
                    community_id: event.community_id.clone().unwrap_or_default(),
                    raw: raw.to_string(),
                    tenant_id: tenant_id.clone(),
                    sensor_id: raw.get("sensor_host").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                };

                // ARP events are only used for asset discovery — never store as ndr_events
                if event.log_source.as_deref() == Some("arp") {
                    // fall through to ARP asset handler below
                } else {
                    let _ = ch_tx.send((ch_event, tenant_id.clone()));
                }

                // --- Asset Identification (DHCP) ---
                if event.log_source.as_deref() == Some("dhcp") {
                    let mac = raw.get("mac").and_then(|v| v.as_str()).unwrap_or("");
                    let ip = raw.get("assigned_addr")
                        .or_else(|| raw.get("requested_addr"))
                        .or_else(|| raw.get("client_addr"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let hostname = raw.get("host_name")
                        .or_else(|| raw.get("client_fqdn"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");

                    if !mac.is_empty() && !ip.is_empty() {
                        let is_gateway = ip.ends_with(".1") || ip.ends_with(".254");
                        let vendor = state.enrichment.asset_id.lookup_vendor(mac);
                        // Queue for vendor backfill if OUI not resolved
                        if vendor == "Unknown" {
                            let mut rc = state.redis_mux.clone();
                            let qi = format!("{}|{}|{}", tenant_id, ip, mac);
                            tokio::spawn(async move {
                                let _: Result<i64, _> = redis::cmd("SADD")
                                    .arg("ndr:vendor_pending").arg(qi)
                                    .query_async(&mut rc).await;
                            });
                        }
                        let device_type = state.enrichment.asset_id.guess_device_type(hostname, &vendor, is_gateway);
                        let asset = crate::storage::clickhouse::AssetRow {
                            ip:             ip.to_string(),
                            mac:            mac.to_string(),
                            hostname:       hostname.to_string(),
                            vendor,
                            os_guess:       "".to_string(),
                            device_type,
                            custom_name:    "".to_string(),
                            tenant_id:      tenant_id.clone(),
                            first_seen:     chrono::Utc::now().timestamp() as u32,
                            last_seen:      chrono::Utc::now().timestamp() as u32,
                            ip_history:     "[]".to_string(),
                            trusted:        0,
                            threat_flagged: 0,
                            role:           String::new(),
                            criticality:    0,
                            open_ports:     "[]".to_string(),
                            subnet_role:    String::new(),
                            ja3_os:         String::new(),
                        };
                        let ch_clone = state.ch_storage.clone();
                        let mac_clone = mac.to_string();
                        let tenant_clone2 = tenant_id.clone();
                        tokio::spawn(async move {
                            let now_ts = chrono::Utc::now().timestamp() as u32;
                            let mut final_asset = asset;

                            if !mac_clone.is_empty() {
                                if let Ok(Some(existing_by_mac)) = ch_clone.get_asset_by_mac(&tenant_clone2, &mac_clone).await {
                                    if !existing_by_mac.os_guess.is_empty() {
                                        final_asset.os_guess = existing_by_mac.os_guess.clone();
                                    }
                                    if !existing_by_mac.custom_name.is_empty() {
                                        final_asset.custom_name = existing_by_mac.custom_name.clone();
                                    }
                                    if !existing_by_mac.hostname.is_empty() && final_asset.hostname.is_empty() {
                                        final_asset.hostname = existing_by_mac.hostname.clone();
                                    }
                                    if existing_by_mac.first_seen > 0 {
                                        final_asset.first_seen = existing_by_mac.first_seen;
                                    }
                                    if existing_by_mac.ip != final_asset.ip {
                                        tracing::info!(
                                            "[HybridAsset] MAC {} moved: {} → {}",
                                            mac_clone, existing_by_mac.ip, final_asset.ip
                                        );
                                        let mut history: Vec<serde_json::Value> =
                                            serde_json::from_str(&existing_by_mac.ip_history)
                                                .unwrap_or_default();
                                        history.push(serde_json::json!({
                                            "ip": existing_by_mac.ip,
                                            "start_time": existing_by_mac.first_seen,
                                            "end_time": now_ts
                                        }));
                                        if history.len() > 50 {
                                            let skip = history.len() - 50;
                                            history = history.into_iter().skip(skip).collect();
                                        }
                                        final_asset.ip_history =
                                            serde_json::to_string(&history).unwrap_or_else(|_| "[]".to_string());
                                    } else {
                                        final_asset.ip_history = existing_by_mac.ip_history.clone();
                                    }
                                    // Preserve user-set fields that the pipeline never overwrites
                                    if existing_by_mac.trusted != 0 { final_asset.trusted = existing_by_mac.trusted; }
                                    if existing_by_mac.threat_flagged != 0 { final_asset.threat_flagged = existing_by_mac.threat_flagged; }
                                    if !existing_by_mac.role.is_empty() { final_asset.role = existing_by_mac.role.clone(); }
                                    if existing_by_mac.criticality != 0 { final_asset.criticality = existing_by_mac.criticality; }
                                    if existing_by_mac.open_ports != "[]" && !existing_by_mac.open_ports.is_empty() { final_asset.open_ports = existing_by_mac.open_ports.clone(); }
                                    if !existing_by_mac.subnet_role.is_empty() { final_asset.subnet_role = existing_by_mac.subnet_role.clone(); }
                                    if !existing_by_mac.ja3_os.is_empty() { final_asset.ja3_os = existing_by_mac.ja3_os.clone(); }
                                }
                            } else {
                                if let Ok(Some(existing)) = ch_clone.get_asset_by_ip(&final_asset.tenant_id, &final_asset.ip).await {
                                    if !existing.os_guess.is_empty() { final_asset.os_guess = existing.os_guess; }
                                    if existing.first_seen > 0 { final_asset.first_seen = existing.first_seen; }
                                    final_asset.ip_history = existing.ip_history;
                                    if existing.trusted != 0 { final_asset.trusted = existing.trusted; }
                                    if existing.threat_flagged != 0 { final_asset.threat_flagged = existing.threat_flagged; }
                                    if !existing.role.is_empty() { final_asset.role = existing.role; }
                                    if existing.criticality != 0 { final_asset.criticality = existing.criticality; }
                                    if existing.open_ports != "[]" && !existing.open_ports.is_empty() { final_asset.open_ports = existing.open_ports; }
                                    if !existing.subnet_role.is_empty() { final_asset.subnet_role = existing.subnet_role; }
                                    if !existing.ja3_os.is_empty() { final_asset.ja3_os = existing.ja3_os; }
                                }
                            }

                            if let Err(e) = ch_clone.upsert_asset(&final_asset).await {
                                warn!("Asset upsert error: {}", e);
                            }
                        });
                    }
                } else if event.log_source.as_deref() == Some("software") {
                    let ip = raw.get("host")
                        .or_else(|| raw.get("id.orig_h"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let software_type = raw.get("software_type").and_then(|v| v.as_str()).unwrap_or("");
                    let name = raw.get("name").and_then(|v| v.as_str()).unwrap_or("");

                    if !ip.is_empty() && software_type == "OS" && !name.is_empty() {
                        let ch_clone = state.ch_storage.clone();
                        let ip_clone = ip.to_string();
                        let os_name = name.to_string();
                        let tenant_clone = tenant_id.clone();
                        tokio::spawn(async move {
                            if let Ok(Some(mut updated_asset)) = ch_clone.get_asset_by_ip(&tenant_clone, &ip_clone).await {
                                updated_asset.os_guess = os_name;
                                updated_asset.last_seen = chrono::Utc::now().timestamp() as u32;
                                if let Err(e) = ch_clone.upsert_asset(&updated_asset).await {
                                    warn!("Asset OS upsert error: {}", e);
                                }
                            }
                        });
                    }
                } else if event.log_source.as_deref() == Some("http") {
                    let ip = raw.get("id.orig_h")
                        .or_else(|| raw.get("src_ip"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let user_agent = raw.get("user_agent")
                        .or_else(|| raw.get("useragent"))
                        .and_then(|v| v.as_str())
                        .or_else(|| raw.get("http").and_then(|h| h.get("http_user_agent")).and_then(|v| v.as_str()))
                        .unwrap_or("");

                    if !ip.is_empty() && !user_agent.is_empty() {
                        let os_guess = guess_os_from_ua(user_agent);
                        if !os_guess.is_empty() {
                            let ch_clone = state.ch_storage.clone();
                            let ip_clone = ip.to_string();
                            let tenant_clone = tenant_id.clone();
                            tokio::spawn(async move {
                                if let Ok(Some(mut asset)) = ch_clone.get_asset_by_ip(&tenant_clone, &ip_clone).await {
                                    if asset.os_guess.is_empty() {
                                        asset.os_guess = os_guess;
                                        asset.last_seen = chrono::Utc::now().timestamp() as u32;
                                        if let Err(e) = ch_clone.upsert_asset(&asset).await {
                                            warn!("Asset OS (UA) upsert error: {}", e);
                                        }
                                    }
                                }
                            });
                        }
                    }
                } else if event.log_source.as_deref() == Some("arp") {
                    let mac = raw.get("mac").or_else(|| raw.get("SHA")).and_then(|v| v.as_str()).unwrap_or("");
                    let ip  = raw.get("SPA").or_else(|| raw.get("ip")).and_then(|v| v.as_str()).unwrap_or("");

                    if !mac.is_empty() && !ip.is_empty() {
                        let now        = chrono::Utc::now().timestamp() as u32;
                        let hash_key   = format!("ndr:asset:{}:{}", tenant_id, ip);
                        let dirty_key  = format!("ndr:assets_dirty:{}", tenant_id);
                        let mut rc     = state.redis_mux.clone();
                        let ip_s       = ip.to_string();
                        let mac_s      = mac.to_string();
                        let tid        = tenant_id.clone();
                        let is_gateway = ip.ends_with(".1") || ip.ends_with(".254");
                        let vendor     = state.enrichment.asset_id.lookup_vendor(mac);
                        let device_type = state.enrichment.asset_id.guess_device_type("", &vendor, is_gateway);
                        let conflict_ch = state.ch_storage.clone();

                        // Vendor backfill if unresolved
                        if vendor == "Unknown" {
                            let mut rc2 = state.redis_mux.clone();
                            let qi = format!("{}|{}|{}", tenant_id, ip, mac);
                            tokio::spawn(async move {
                                let _: Result<i64, _> = redis::cmd("SADD")
                                    .arg("ndr:vendor_pending").arg(qi)
                                    .query_async(&mut rc2).await;
                            });
                        }

                        tokio::spawn(async move {
                            // Read existing asset from Redis (pure in-memory, no ClickHouse)
                            let pairs: Vec<String> = redis::cmd("HGETALL")
                                .arg(&hash_key)
                                .query_async(&mut rc).await.unwrap_or_default();
                            let mut existing: std::collections::HashMap<String,String> = std::collections::HashMap::new();
                            let mut i = 0;
                            while i + 1 < pairs.len() { existing.insert(pairs[i].clone(), pairs[i+1].clone()); i += 2; }

                            let existing_mac = existing.get("mac").cloned().unwrap_or_default();

                            // IP conflict detection — purely from Redis, zero ClickHouse calls
                            if !existing_mac.is_empty() && existing_mac != mac_s && !existing_mac.contains("00:00:00") {
                                warn!("IP CONFLICT: {} claimed by {} and {} — possible ARP spoofing", ip_s, existing_mac, mac_s);
                                let hit = crate::storage::clickhouse::NdrHit {
                                    timestamp:          now,
                                    community_id:       format!("arp-conflict-{}", ip_s),
                                    src_ip:             mac_s.clone(),
                                    dst_ip:             ip_s.clone(),
                                    score:              85.0,
                                    severity:           "HIGH".to_string(),
                                    tags:               vec!["ip-conflict".to_string(), "arp-spoofing".to_string()],
                                    sigma_hits:         vec![],
                                    threat_intel:       0,
                                    src_country:        "".to_string(),
                                    dst_country:        "".to_string(),
                                    tenant_id:          tid.clone(),
                                    correlation_status: "arp_conflict".to_string(),
                                    agent_z_details:    "{}".to_string(),
                                    agent_s_details:    "{}".to_string(),
                                    corroborated_at:    0,
                                    agent_s_rule_id:    "".to_string(),
                                    agent_s_category:   "".to_string(),
                                    updated_at:         now,
                                    sensor_id:          raw.get("sensor_host").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                                };
                                let _ = conflict_ch.insert_hit_for_tenant(hit, &tid).await;
                            }

                            // Merge: preserve existing enriched fields, update last_seen
                            let final_vendor      = if existing.get("vendor").map(|v| v != "Unknown" && !v.is_empty()).unwrap_or(false) { existing["vendor"].clone() } else { vendor };
                            let final_os          = existing.get("os_guess").cloned().unwrap_or_default();
                            let final_hostname    = existing.get("hostname").cloned().unwrap_or_default();
                            let final_device_type = if existing.get("device_type").map(|v| v != "unknown" && !v.is_empty()).unwrap_or(false) { existing["device_type"].clone() } else { device_type };
                            let final_custom      = existing.get("custom_name").cloned().unwrap_or_default();
                            let first_seen        = existing.get("first_seen").and_then(|s| s.parse::<u32>().ok()).unwrap_or(now);
                            let ip_history        = existing.get("ip_history").cloned().unwrap_or_else(|| "[]".to_string());

                            // Write back to Redis (hot store)
                            let _: Result<(), _> = redis::cmd("HSET")
                                .arg(&hash_key)
                                .arg("mac").arg(&mac_s)
                                .arg("hostname").arg(&final_hostname)
                                .arg("vendor").arg(&final_vendor)
                                .arg("os_guess").arg(&final_os)
                                .arg("device_type").arg(&final_device_type)
                                .arg("custom_name").arg(&final_custom)
                                .arg("first_seen").arg(first_seen)
                                .arg("last_seen").arg(now)
                                .arg("ip_history").arg(&ip_history)
                                .query_async(&mut rc).await;

                            // 24h TTL so stale assets auto-expire
                            let _: Result<(), _> = redis::cmd("EXPIRE")
                                .arg(&hash_key).arg(86400u64)
                                .query_async(&mut rc).await;

                            // Mark as dirty for next 30s flush to ClickHouse
                            let _: Result<i64, _> = redis::cmd("SADD")
                                .arg(&dirty_key).arg(&ip_s)
                                .query_async(&mut rc).await;
                        });
                    }
                } else if event.log_source.as_deref() == Some("ipam") {
                    let cidr      = raw.get("cidr").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let interface = raw.get("interface").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let local_ip  = raw.get("local_ip").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let gateway   = raw.get("gateway").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let sensor_id = raw.get("sensor_host").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    if !cidr.is_empty() {
                        let ch_clone = state.ch_storage.clone();
                        let tid = tenant_id.clone();
                        tokio::spawn(async move {
                            if let Err(e) = ch_clone.upsert_ipam_subnet(&tid, &interface, &cidr, &local_ip, &gateway, &sensor_id).await {
                                tracing::debug!("IPAM subnet upsert: {}", e);
                            } else {
                                tracing::debug!("IPAM: {} {} → {}", sensor_id, interface, cidr);
                            }
                        });
                    }
                } else if event.log_source.as_deref() == Some("dns") {
                    let ip = raw.get("id.orig_h").or_else(|| raw.get("src_ip")).and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let query = raw.get("query").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let mut domain = query.clone();
                    let mut resolved_ips: Vec<String> = Vec::new();

                    if let Some(ans_val) = raw.get("answers") {
                        if let Some(ans_arr) = ans_val.as_array() {
                            for ans in ans_arr {
                                if let Some(s) = ans.as_str() { resolved_ips.push(s.to_string()); }
                            }
                        } else if let Some(ans_str) = ans_val.as_str() {
                            for s in ans_str.split(',') { resolved_ips.push(s.trim().to_string()); }
                        }
                    }
                    if let Some(dns_obj) = raw.get("dns") {
                        if domain.is_empty() {
                            domain = dns_obj.get("rrname").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        }
                        if let Some(rdata) = dns_obj.get("rdata").and_then(|v| v.as_str()) {
                            resolved_ips.push(rdata.to_string());
                        }
                        if let Some(grouped) = dns_obj.get("grouped").and_then(|v| v.get("A")).and_then(|v| v.as_array()) {
                            for ans in grouped {
                                if let Some(s) = ans.as_str() { resolved_ips.push(s.to_string()); }
                            }
                        }
                    }

                    if !domain.is_empty() && !domain.ends_with(".local") {
                        // Real-time domain IOC check against the in-memory threat intel DashSet.
                        // This fires immediately on the DNS query — no 30-min sweep delay.
                        if state.enrichment.threat_intel.is_malicious_domain(&domain) {
                            let now_ts  = chrono::Utc::now().timestamp() as u32;
                            let src     = event.source_ip.clone().unwrap_or_default();
                            let dst     = event.dest_ip.clone().unwrap_or_default();
                            let bucket  = now_ts / 300 * 300;
                            let cid     = event.community_id.clone()
                                .unwrap_or_else(|| format!("domain-{}-{}", bucket,
                                    domain.replace('.', "-")));
                            let details = serde_json::json!({ "domain": domain, "query": query });
                            let ch_hit  = crate::storage::clickhouse::NdrHit {
                                timestamp:          now_ts,
                                community_id:       cid,
                                src_ip:             src,
                                dst_ip:             dst,
                                score:              85.0,
                                severity:           "HIGH".to_string(),
                                tags:               vec!["malicious-domain".to_string(), "threat-intel".to_string()],
                                sigma_hits:         vec![],
                                threat_intel:       1,
                                src_country:        String::new(),
                                dst_country:        String::new(),
                                tenant_id:          tenant_id.clone(),
                                correlation_status: "domain_match".to_string(),
                                agent_z_details:    serde_json::to_string(&details).unwrap_or_else(|_| "{}".into()),
                                agent_s_details:    "{}".to_string(),
                                corroborated_at:    0,
                                agent_s_rule_id:    String::new(),
                                agent_s_category:   "c2".to_string(),
                                updated_at:         now_ts,
                                sensor_id:          raw.get("sensor_host").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                            };
                            let ch_cl   = state.ch_storage.clone();
                            let tid_cl  = tenant_id.clone();
                            let dom_log = domain.clone();
                            tokio::spawn(async move {
                                if let Err(e) = ch_cl.insert_hit_for_tenant(ch_hit, &tid_cl).await {
                                    tracing::warn!("domain-match hit insert error: {}", e);
                                } else {
                                    tracing::info!(domain = %dom_log, tenant = %tid_cl, "malicious domain in DNS query — hit created");
                                }
                            });
                        }

                        resolved_ips.retain(|ans_str| ans_str.parse::<std::net::IpAddr>().is_ok());
                        if !resolved_ips.is_empty() {
                            let ch_clone = state.ch_storage.clone();
                            tokio::spawn(async move {
                                for ans_ip in resolved_ips {
                                    if let Err(e) = ch_clone.insert_passive_dns(&ans_ip, &domain).await {
                                        tracing::warn!("Passive DNS insert error: {}", e);
                                    }
                                }
                            });
                        }
                    }

                    if !ip.is_empty() && query.ends_with(".local") {
                        let hostname = query.strip_suffix(".local").unwrap_or(&query).to_string();
                        let ch_clone = state.ch_storage.clone();
                        let ip_clone = ip.clone();
                        let tenant_clone = tenant_id.clone();
                        let is_gateway = ip.ends_with(".1") || ip.ends_with(".254");
                        tokio::spawn(async move {
                            if let Ok(Some(mut updated_asset)) = ch_clone.get_asset_by_ip(&tenant_clone, &ip_clone).await {
                                if updated_asset.hostname.is_empty() {
                                    updated_asset.hostname = hostname;
                                    let h = updated_asset.hostname.to_lowercase();
                                    if is_gateway { updated_asset.device_type = "router".into(); }
                                    else if h.contains("macbook") || h.contains("imac") || h.contains("lap") { updated_asset.device_type = "laptop".into(); }
                                    else if h.contains("iphone") || h.contains("ipad") { updated_asset.device_type = "phone".into(); }
                                    else if h.contains("print") { updated_asset.device_type = "printer".into(); }
                                    else if h.contains("tv") || h.contains("cast") { updated_asset.device_type = "tv".into(); }
                                    updated_asset.last_seen = chrono::Utc::now().timestamp() as u32;
                                    if let Err(e) = ch_clone.upsert_asset(&updated_asset).await {
                                        warn!("Asset mDNS upsert error: {}", e);
                                    }
                                }
                            }
                        });
                    }
                }

                // --- Placeholder Asset Creation ---
                // Update last_seen for confirmed assets (MAC-verified) seen in traffic.
                // Never create new placeholder rows — assets only enter the table via
                // ARP/DHCP events that carry a real MAC address.
                let update_last_seen = |ip: &str, tenant: &str| {
                    if ip.is_empty() { return; }
                    if ip.ends_with(".255") || ip.ends_with(".0")
                        || ip.starts_with("224.") || ip.starts_with("239.")
                        || ip == "255.255.255.255" { return; }
                    if !crate::enrichment::is_private_ip(ip) { return; }
                    let cache_key = format!("{}:{}", tenant, ip);
                    let now = chrono::Utc::now().timestamp() as u32;
                    let mut needs_db_sync = false;
                    if let Some(mut last_sync) = known_assets.get_mut(&cache_key) {
                        if now.saturating_sub(*last_sync) > 300 {
                            *last_sync = now;
                            needs_db_sync = true;
                        }
                    } else {
                        known_assets.insert(cache_key.clone(), now);
                        needs_db_sync = true;
                    }
                    if needs_db_sync {
                        let ch_clone = state.ch_storage.clone();
                        let ip_clone = ip.to_string();
                        let tenant_clone = tenant.to_string();
                        tokio::spawn(async move {
                            if let Ok(Some(mut existing)) = ch_clone.get_asset_by_ip(&tenant_clone, &ip_clone).await {
                                if !existing.mac.is_empty() {
                                    existing.last_seen = chrono::Utc::now().timestamp() as u32;
                                    let _ = ch_clone.upsert_asset(&existing).await;
                                }
                            }
                        });
                    }
                };
                if let Some(src) = &event.source_ip {
                    update_last_seen(src, &tenant_id);
                }
                if let Some(dst) = &event.dest_ip {
                    update_last_seen(dst, &tenant_id);
                }
                // -----------------------------------

                // Broadcast immediately (non-blocking)
                crate::api::broadcast_raw_event(&state, &event);

                // Inline SIGMA for all Zeek events — Suricata can't always corroborate
                // (DNS alerts have empty IPs; SMB/Kerberos/SSL often have no ET rule).
                // Store as zeek_only; corroborated hits will overwrite via ReplacingMergeTree.
                if event.event_source == EventSource::Zeek {
                    let detections = {
                        let engine = state.detection.read().await;
                        engine.check_for_tenant(&event, &tenant_id)
                    };
                    if !detections.is_empty() {
                        let now_ts = chrono::Utc::now().timestamp() as u32;
                        let score: f32 = detections.iter().map(|d| match d.severity.to_lowercase().as_str() {
                            "critical" => 90.0_f32,
                            "high"     => 70.0,
                            "medium"   => 50.0,
                            "low"      => 30.0,
                            _          => 10.0,
                        }).fold(0.0_f32, f32::max);
                        let severity = if score >= 90.0 { "CRITICAL" }
                            else if score >= 70.0 { "HIGH" }
                            else if score >= 50.0 { "MEDIUM" }
                            else if score >= 30.0 { "LOW" }
                            else { "INFO" };
                        let sigma_titles: Vec<String> = {
                            let mut seen = std::collections::HashSet::new();
                            detections.iter().map(|d| d.title.clone()).filter(|t| seen.insert(t.clone())).collect()
                        };
                        let cid = event.community_id.clone().unwrap_or_else(|| format!("zeek-{}-{}", now_ts, event.uid.as_deref().unwrap_or("x")));
                        let src = event.source_ip.clone().unwrap_or_default();
                        let dst = event.dest_ip.clone().unwrap_or_default();
                        let agent_z_details = serde_json::to_string(&event.raw).unwrap_or_else(|_| "{}".into());
                        let ch_hit = crate::storage::clickhouse::NdrHit {
                            timestamp:          now_ts,
                            community_id:       cid,
                            src_ip:             src,
                            dst_ip:             dst,
                            score,
                            severity:           severity.to_string(),
                            tags:               vec!["sigma".to_string()],
                            sigma_hits:         sigma_titles,
                            threat_intel:       0,
                            src_country:        String::new(),
                            dst_country:        String::new(),
                            tenant_id:          tenant_id.clone(),
                            correlation_status: "zeek_only".to_string(),
                            agent_z_details,
                            agent_s_details:    "{}".to_string(),
                            corroborated_at:    0,
                            agent_s_rule_id:    String::new(),
                            agent_s_category:   String::new(),
                            updated_at:         now_ts,
                            sensor_id:          event.raw.get("sensor_host").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        };
                        let ch_clone        = state.ch_storage.clone();
                        let tid_clone       = tenant_id.clone();
                        let cid_clone       = ch_hit.community_id.clone();
                        let src_clone       = ch_hit.src_ip.clone();
                        let dst_clone       = ch_hit.dst_ip.clone();
                        let sev_clone       = ch_hit.severity.clone();
                        let sigma_log       = detections.iter().map(|d| d.title.as_str()).collect::<Vec<_>>().join(",");
                        let do_evidence     = matches!(severity, "HIGH" | "CRITICAL" | "MEDIUM")
                                             && cid_clone.starts_with("1:");
                        tracing::info!(
                            sigma = %sigma_log,
                            src   = %event.source_ip.as_deref().unwrap_or("-"),
                            dst   = %event.dest_ip.as_deref().unwrap_or("-"),
                            "zeek_only SIGMA hit"
                        );
                        tokio::spawn(async move {
                            if let Err(e) = ch_clone.insert_hit_for_tenant(ch_hit, &tid_clone).await {
                                tracing::warn!("zeek_only hit insert error: {}", e);
                                return;
                            }
                            if !do_evidence { return; }

                            let opensearch_url = std::env::var("OPENSEARCH_URL")
                                .unwrap_or_else(|_| "http://localhost:9200".to_string());
                            let arkime_url  = std::env::var("ARKIME_URL").unwrap_or_default();
                            let arkime_pass = std::env::var("ARKIME_PASS")
                                .unwrap_or_else(|_| "admin".to_string());
                            let now_str  = chrono::Utc::now().to_rfc3339();
                            let alert_json = serde_json::json!({
                                "community_id":    cid_clone,
                                "tenant_id":       tid_clone,
                                "severity":        sev_clone,
                                "src_ip":          src_clone,
                                "dst_ip":          dst_clone,
                                "rule_name":       sigma_log,
                                "timestamp":       now_str,
                                "auto_captured_at": now_str,
                            });
                            let ev_sem = crate::api::evidence_semaphore();
                            let _permit = ev_sem.acquire_owned().await;
                            match crate::evidence::build_evidence_bundle(
                                &opensearch_url, &arkime_url, &arkime_pass,
                                &cid_clone, alert_json, &tid_clone, None,
                            ).await {
                                Ok((zip_bytes, sha256, _manifest)) => {
                                    let date      = chrono::Utc::now().format("%Y-%m-%d").to_string();
                                    let dir       = format!("/opt/ndr/evidence/{}/{}", tid_clone, date);
                                    let _         = tokio::fs::create_dir_all(&dir).await;
                                    let bundle_id = uuid::Uuid::new_v4().to_string();
                                    let file_path = format!("{}/{}.zip", dir, bundle_id);
                                    let size      = zip_bytes.len() as u64;
                                    if tokio::fs::write(&file_path, &zip_bytes).await.is_ok() {
                                        let _ = ch_clone.save_evidence_bundle(
                                            &tid_clone, &bundle_id, &cid_clone,
                                            &file_path, &sha256, size,
                                            1, 90,
                                            &src_clone, &dst_clone, &sev_clone, "",
                                        ).await;
                                        let _ = ch_clone.log_evidence_action(
                                            &tid_clone, &cid_clone, &bundle_id,
                                            "auto_captured", "auto",
                                            &sev_clone, "", "",
                                            "Automatically captured on SIGMA zeek_only hit",
                                            "",
                                        ).await;
                                        tracing::info!(
                                            "Evidence bundle {} captured for zeek_only cid {}",
                                            bundle_id, cid_clone
                                        );
                                    }
                                }
                                Err(e) => tracing::warn!("Evidence capture failed for {}: {}", cid_clone, e),
                            }
                        });
                    }
                }

                // Correlate in a bounded background task — semaphore caps concurrent
                // ClickHouse+SOAR calls at 16 so a burst of hits can't saturate the
                // connection pool or starve the tokio runtime
                if let Some(hit) = state.correlator.process(event) {
                    let state_clone = state.as_ref().clone();
                    let sem = state.correlation_semaphore.clone();
                    tokio::spawn(async move {
                        let _permit = sem.acquire_owned().await;
                        crate::api::process_correlation_hit(&state_clone, hit).await;
                    });
                }
            }
            Err(e) => {
                error!("Kafka error: {}", e);
                tokio::time::sleep(
                    tokio::time::Duration::from_secs(1)
                ).await;
            }
        }
    }
}

fn guess_os_from_ua(ua: &str) -> String {
    if ua.contains("Windows NT 10") || ua.contains("Windows NT 11") {
        return "Windows 10/11".to_string();
    }
    if ua.contains("Windows NT 6.3") { return "Windows 8.1".to_string(); }
    if ua.contains("Windows NT 6.1") { return "Windows 7".to_string(); }
    if ua.contains("Windows") { return "Windows".to_string(); }
    if ua.contains("iPhone") || ua.contains("iPad") { return "iOS".to_string(); }
    if ua.contains("Android") { return "Android".to_string(); }
    if ua.contains("Mac OS X") { return "macOS".to_string(); }
    if ua.contains("Ubuntu") { return "Ubuntu Linux".to_string(); }
    if ua.contains("Debian") { return "Debian Linux".to_string(); }
    if ua.contains("Linux") { return "Linux".to_string(); }
    String::new()
}
