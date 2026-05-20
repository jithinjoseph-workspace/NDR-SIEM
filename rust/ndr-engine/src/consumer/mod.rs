// NDR Engine — Kafka Consumer (pure-Rust via rskafka)
// License: Apache-2.0

use rskafka::{
    client::{
        partition::{OffsetAt, UnknownTopicHandling},
        ClientBuilder,
    },
    record::RecordAndOffset,
};
use serde_json::Value;
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::api::AppState;
use crate::normalizer::{NormalizedEvent, EventSource};
use crate::storage::clickhouse::NdrEvent;

pub async fn start_consumer(state: Arc<AppState>) {
    let brokers = std::env::var("KAFKA_BROKERS")
        .unwrap_or_else(|_| "kafka:9092".to_string());

    info!("📡 Connecting to Kafka at {}", brokers);

    let client = loop {
        match ClientBuilder::new(vec![brokers.clone()]).build().await {
            Ok(c) => break c,
            Err(e) => {
                error!("Kafka connect error: {}. Retrying in 5s…", e);
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }
        }
    };

    info!(" Kafka client ready");

    let partition_client = loop {
        match client
            .partition_client(
                "ndr-events",
                0,
                UnknownTopicHandling::Retry,
            )
            .await
        {
            Ok(pc) => break pc,
            Err(e) => {
                error!("Topic error: {}. Retrying in 5s…", e);
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }
        }
    };

    info!(" Kafka consumer ready — topic: ndr-events");

    let mut offset = partition_client
        .get_offset(OffsetAt::Latest)
        .await
        .unwrap_or(0);

    loop {
        match partition_client
            .fetch_records(offset, 1..10_000_000, 100)
            .await
        {
            Ok((records, _watermark)) => {
                if records.is_empty() {
                    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                    continue;
                }
                for RecordAndOffset { record, offset: rec_offset } in &records {
                    if let Some(bytes) = &record.value {
                        match std::str::from_utf8(bytes) {
                            Ok(s) => match serde_json::from_str::<Value>(s) {
                                Ok(raw) => process_event(raw, &state).await,
                                Err(e)  => warn!("JSON parse error: {}", e),
                            },
                            Err(e) => warn!("Bad UTF-8 in message: {}", e),
                        }
                    }
                    offset = rec_offset + 1;
                }
            }
            Err(e) => {
                error!("Kafka fetch error: {}", e);
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            }
        }
    }
}

async fn process_event(raw: Value, state: &Arc<AppState>) {
    let Some(event) = NormalizedEvent::from_raw(raw.clone()) else { return };

    if event.should_drop() { return; }

    // ── Write raw event to ClickHouse ─────────────────────────────────────
    let source_str = match event.event_source {
        EventSource::Zeek     => "zeek",
        EventSource::Suricata => "suricata",
        EventSource::Unknown  => "unknown",
    }.to_string();

    let ch = state.ch_storage.clone();
    let ch_event = NdrEvent {
        timestamp:    chrono::Utc::now().timestamp() as u32,
        source:       source_str,
        src_ip:       event.source_ip.clone().unwrap_or_default(),
        dst_ip:       event.dest_ip.clone().unwrap_or_default(),
        src_port:     event.source_port.unwrap_or(0),
        dst_port:     event.dest_port.unwrap_or(0),
        proto:        event.proto.clone().unwrap_or_default(),
        event_type:   event.event_type.clone()
                        .or(event.log_source.clone())
                        .unwrap_or_default(),
        community_id: event.community_id.clone().unwrap_or_default(),
        raw:          raw.to_string(),
        tenant_id:    std::env::var("TENANT_ID").unwrap_or_else(|_| "default".to_string()),
    };

    tokio::spawn(async move {
        if let Err(e) = ch.insert_event(ch_event).await {
            warn!("ClickHouse event insert error: {}", e);
        }
    });

    // ── Broadcast and correlate ───────────────────────────────────────────
    crate::api::broadcast_raw_event(state, &event);

    if let Some(hit) = state.correlator.process(event) {
        crate::api::process_correlation_hit(state, hit).await;
    }
}