// NDR Engine — Kafka Consumer (pure-Rust via rdkafka)
// License: Apache-2.0

use rdkafka::config::ClientConfig;
use rdkafka::consumer::{Consumer, StreamConsumer};
use rdkafka::message::Message;
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::api::AppState;
use crate::normalizer::{NormalizedEvent, EventSource};
use crate::storage::clickhouse::NdrEvent;

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

    info!("Kafka consumer ready — group: ndr-engine-group instance: {}", instance_id);

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

                // Parse event (same logic as before)
                let Some(event) = NormalizedEvent::from_raw(raw.clone()) else { continue; };

                if event.should_drop() { continue; }

                let tenant_id = raw.get("tenant_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("default")
                    .to_string();

                // Insert to ClickHouse
                let source_str = match event.event_source {
                    EventSource::Zeek     => "zeek",
                    EventSource::Suricata => "suricata",
                    _ => "unknown",
                }.to_string();

                let ch = state.ch_storage.clone();
                let ch_event = NdrEvent {
                    timestamp: chrono::Utc::now().timestamp() as u32,
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

                let ch_clone = ch.clone();
                let event_clone = ch_event;
                let tenant_id_clone = tenant_id.clone();
                tokio::spawn(async move {
                    if let Err(e) = ch_clone.insert_event_for_tenant(event_clone, &tenant_id_clone).await {
                        warn!("ClickHouse event insert error: {}", e);
                    }
                });

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
