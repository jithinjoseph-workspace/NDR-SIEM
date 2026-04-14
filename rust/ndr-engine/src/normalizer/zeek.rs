// NDR Engine — Zeek Log Normalizer
// Field mapping concepts from Malcolm's 1200_zeek_mutate.conf (public domain, CC0).
// Zero code copied — all logic freshly implemented. License: Apache-2.0

use serde_json::Value;
use super::{NormalizedEvent, EventSource};
use std::time::{SystemTime, UNIX_EPOCH};

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

/// Normalise a raw Zeek JSON event from Vector into our canonical model.
/// Zeek conn.log TSV is pre-parsed by Vector into JSON fields.
pub fn normalize_zeek(raw: Value) -> Option<NormalizedEvent> {
    // community_id is mandatory for correlation — drop without it
    let community_id = raw.get("community_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty() && *s != "-")
        .map(String::from)?;

    // Malcolm maps id.orig_h → source.ip; Vector renames it to src_ip
    let source_ip = raw.get("src_ip")
        .or_else(|| raw.get("id.orig_h"))
        .and_then(|v| v.as_str())
        .map(String::from);

    let dest_ip = raw.get("dst_ip")
        .or_else(|| raw.get("id.resp_h"))
        .and_then(|v| v.as_str())
        .map(String::from);

    // Ports may arrive as strings (TSV origin) or integers
    let source_port = raw.get("src_port")
        .or_else(|| raw.get("id.orig_p"))
        .and_then(|v| {
            v.as_u64().map(|n| n as u16)
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        });

    let dest_port = raw.get("dst_port")
        .or_else(|| raw.get("id.resp_p"))
        .and_then(|v| {
            v.as_u64().map(|n| n as u16)
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        });

    let proto = raw.get("proto")
        .and_then(|v| v.as_str())
        .map(|s| s.to_lowercase());

    // Malcolm: network.protocol ← Zeek service field (e.g. "http", "dns", "ssl")
    // Vector exposes this as network_protocol (Task 1 from previous session)
    let network_protocol = raw.get("network_protocol")
        .or_else(|| raw.get("service"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty() && *s != "-")
        .map(|s| s.to_lowercase());

    let uid = raw.get("uid")
        .and_then(|v| v.as_str())
        .map(String::from);

    let conn_state = raw.get("conn_state")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty() && *s != "-")
        .map(String::from);

    // log_source helps the drop filter (stats, capture_loss, etc.)
    let log_source = raw.get("log_type")
        .or_else(|| raw.get("_path"))
        .and_then(|v| v.as_str())
        .map(String::from);

    // Zeek ts is a Unix float (seconds.microseconds)
    let timestamp = raw.get("ts")
        .and_then(|v| v.as_f64())
        .map(|f| (f * 1000.0) as u64)
        .unwrap_or_else(now_ms);

    Some(NormalizedEvent {
        source_ip,
        source_port,
        dest_ip,
        dest_port,
        proto,
        network_protocol,
        community_id: Some(community_id),
        event_source: EventSource::Zeek,
        log_source,
        timestamp,
        uid,
        conn_state,
        event_type: None,
        alert: None,
        raw,
    })
}
