// Kafka publisher — publishes OcsfEvent to the siem-logs topic
// Uses rdkafka FutureProducer with idempotent delivery (acks=all, retries=MAX)

use rdkafka::config::ClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord};
use std::time::Duration;
use tracing::info;
use crate::ingest::normalizer::OcsfEvent;

pub struct KafkaPublisher {
    producer: FutureProducer,
}

impl KafkaPublisher {
    pub fn new(brokers: &str) -> Self {
        let producer: FutureProducer = ClientConfig::new()
            .set("bootstrap.servers", brokers)
            .set("enable.idempotence", "true")   // exactly-once delivery guarantee
            .set("acks", "all")                  // wait for all ISR replicas
            .set("retries", "2147483647")        // retry forever on transient errors
            .set("max.in.flight.requests.per.connection", "5")
            .set("compression.type", "lz4")     // compress for network efficiency
            .set("linger.ms", "5")              // small batch window — low latency
            .set("batch.size", "65536")
            .create()
            .expect("Kafka FutureProducer creation failed");

        info!("Kafka producer connected to {brokers}");
        Self { producer }
    }

    pub async fn publish(&self, event: &OcsfEvent) -> anyhow::Result<()> {
        let payload = serde_json::to_string(event)?;

        let record = FutureRecord::to("siem-logs")
            .key(event.tenant_id.as_str())  // same tenant → same partition → ordered
            .payload(payload.as_str());

        self.producer
            .send(record, Duration::from_secs(10))
            .await
            .map_err(|(e, _)| anyhow::anyhow!("Kafka send failed: {e}"))?;

        info!(
            "Kafka: published log_id={} tenant={} bytes={}",
            event.log_id, event.tenant_id, payload.len()
        );
        Ok(())
    }
}
