// NDR Engine — Kafka Consumer (pure-Rust via rskafka)
// Reads from "ndr-events" topic, routes through the existing normalizer /
// correlator / enrichment / scoring pipeline.
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
use crate::normalizer::NormalizedEvent;

pub async fn start_consumer(state: Arc<AppState>) {
    let brokers = std::env::var("KAFKA_BROKERS")
        .unwrap_or_else(|_| "kafka:9092".to_string());

    info!("📡 Connecting to Kafka at {}", brokers);

    // Build client — retry loop so the engine keeps trying if Kafka isn't up yet
    let client = loop {
        match ClientBuilder::new(vec![brokers.clone()]).build().await {
            Ok(c) => break c,
            Err(e) => {
                error!("Kafka connect error: {}. Retrying in 5s…", e);
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }
        }
    };

    info!("✅ Kafka client ready");

    // Discover partitions for "ndr-events"
    let partition_client = loop {
        match client
            .partition_client(
                "ndr-events",
                0, // partition 0
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

    info!("✅ Kafka consumer ready — topic: ndr-events");

    // Start from the latest offset so we don't replay old events on restart
    let mut offset = partition_client
        .get_offset(OffsetAt::Latest)
        .await
        .unwrap_or(0);

    loop {
        // Fetch up to 10 MB, wait up to 100 ms for at least 1 byte
        match partition_client
            .fetch_records(
                offset,
                1..10_000_000, // min_bytes..max_bytes
                100,           // max_wait_ms
            )
            .await
        {
            Ok((records, _watermark)) => {
                if records.is_empty() {
                    // Nothing yet — small sleep to avoid busy-spin
                    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                    continue;
                }
                for RecordAndOffset { record, offset: rec_offset } in &records {
                    if let Some(bytes) = &record.value {
                        match std::str::from_utf8(bytes) {
                            Ok(s) => match serde_json::from_str::<Value>(s) {
                                Ok(raw) => process_event(raw, &state),
                                Err(e)  => warn!("JSON parse error: {}", e),
                            },
                            Err(e) => warn!("Bad UTF-8 in message: {}", e),
                        }
                    }
                    // Advance past this record
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

/// Mirrors the per-event logic from `api::handle_event` / `api::process_hit`.
fn process_event(raw: Value, state: &Arc<AppState>) {
    let Some(event) = NormalizedEvent::from_raw(raw) else { return };

    if event.should_drop() { return; }

    crate::api::broadcast_raw_event(state, &event);

    if let Some(hit) = state.correlator.process(event) {
        crate::api::process_correlation_hit(state, hit);
    }
}
