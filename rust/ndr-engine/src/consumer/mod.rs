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
        .unwrap_or_else(|_| "kafka:9092".to_string());

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

                let source_str = match event.event_source {
                    EventSource::Zeek     => "zeek",
                    EventSource::Suricata => "suricata",
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
                            ip: ip.to_string(),
                            mac: mac.to_string(),
                            hostname: hostname.to_string(),
                            vendor,
                            os_guess: "".to_string(),
                            device_type,
                            custom_name: "".to_string(),
                            tenant_id: tenant_id.clone(),
                            first_seen: chrono::Utc::now().timestamp() as u32,
                            last_seen: chrono::Utc::now().timestamp() as u32,
                            ip_history: "[]".to_string(),
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
                                }
                            } else {
                                if let Ok(Some(existing)) = ch_clone.get_asset_by_ip(&final_asset.tenant_id, &final_asset.ip).await {
                                    if !existing.os_guess.is_empty() {
                                        final_asset.os_guess = existing.os_guess;
                                    }
                                    if existing.first_seen > 0 {
                                        final_asset.first_seen = existing.first_seen;
                                    }
                                    final_asset.ip_history = existing.ip_history;
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
                } else if event.log_source.as_deref() == Some("arp") {
                    let mac = raw.get("mac").or_else(|| raw.get("SHA")).and_then(|v| v.as_str()).unwrap_or("");
                    let ip = raw.get("SPA").or_else(|| raw.get("ip")).and_then(|v| v.as_str()).unwrap_or("");

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
                        let device_type = state.enrichment.asset_id.guess_device_type("", &vendor, is_gateway);
                        let asset = crate::storage::clickhouse::AssetRow {
                            ip: ip.to_string(),
                            mac: mac.to_string(),
                            hostname: "".to_string(),
                            vendor,
                            os_guess: "".to_string(),
                            device_type,
                            custom_name: "".to_string(),
                            tenant_id: tenant_id.clone(),
                            first_seen: chrono::Utc::now().timestamp() as u32,
                            last_seen: chrono::Utc::now().timestamp() as u32,
                            ip_history: "[]".to_string(),
                        };
                        let ch_clone = state.ch_storage.clone();
                        let conflict_ch = state.ch_storage.clone();
                        let conflict_tenant = tenant_id.clone();
                        let conflict_ip = ip.to_string();
                        let conflict_mac = mac.to_string();
                        // IP conflict detection: two different MACs claiming the same IP = ARP spoofing
                        tokio::spawn(async move {
                            if let Ok(Some(existing)) = conflict_ch.get_asset_by_ip(&conflict_tenant, &conflict_ip).await {
                                if !existing.mac.is_empty()
                                    && existing.mac != conflict_mac
                                    && !existing.mac.contains("00:00:00")
                                {
                                    warn!(
                                        "IP CONFLICT: {} claimed by {} and {} — possible ARP spoofing",
                                        conflict_ip, existing.mac, conflict_mac
                                    );
                                    let hit = crate::storage::clickhouse::NdrHit {
                                        timestamp: chrono::Utc::now().timestamp() as u32,
                                        community_id: format!("arp-conflict-{}", conflict_ip),
                                        src_ip: conflict_mac.clone(),
                                        dst_ip: conflict_ip.clone(),
                                        score: 85.0,
                                        severity: "HIGH".to_string(),
                                        tags: vec!["ip-conflict".to_string(), "arp-spoofing".to_string()],
                                        sigma_hits: vec![],
                                        threat_intel: 0,
                                        src_country: "".to_string(),
                                        dst_country: "".to_string(),
                                        tenant_id: conflict_tenant.clone(),
                                    };
                                    let _ = conflict_ch.insert_hit_for_tenant(hit, &conflict_tenant).await;
                                }
                            }
                        });
                        tokio::spawn(async move {
                            let mut final_asset = asset;
                            if let Ok(Some(existing)) = ch_clone.get_asset_by_ip(&final_asset.tenant_id, &final_asset.ip).await {
                                if !existing.os_guess.is_empty() { final_asset.os_guess = existing.os_guess; }
                                if !existing.hostname.is_empty() { final_asset.hostname = existing.hostname; }
                                if !existing.device_type.is_empty() && existing.device_type != "unknown" { final_asset.device_type = existing.device_type; }
                                if !existing.vendor.is_empty() && existing.vendor != "Unknown" { final_asset.vendor = existing.vendor; }
                                if existing.first_seen > 0 { final_asset.first_seen = existing.first_seen; }
                                if !existing.ip_history.is_empty() && existing.ip_history != "[]" {
                                    final_asset.ip_history = existing.ip_history;
                                }
                            }
                            if let Err(e) = ch_clone.upsert_asset(&final_asset).await {
                                warn!("Asset ARP upsert error: {}", e);
                            }
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
                                info!("IPAM: {} {} → {}", sensor_id, interface, cidr);
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
                    let is_internal = ip.starts_with("10.")
                        || ip.starts_with("192.168.")
                        || (ip.starts_with("172.") && {
                            let parts: Vec<&str> = ip.split('.').collect();
                            parts.len() >= 2 && parts[1].parse::<u8>().map(|n| n >= 16 && n <= 31).unwrap_or(false)
                        });
                    if !is_internal { return; }
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
