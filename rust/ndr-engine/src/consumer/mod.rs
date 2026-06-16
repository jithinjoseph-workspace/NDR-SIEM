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

                // Non-blocking send to batch writer — zero overhead in consumer loop
                let _ = ch_tx.send((ch_event, tenant_id.clone()));

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
