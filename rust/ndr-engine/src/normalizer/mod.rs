// NDR Engine — Canonical Event Model + Normalizer
// Field names inspired by Malcolm's ECS normalization (public domain, CC0).
// This code is 100% original. License: Apache-2.0

mod zeek;
mod suricata;

pub use zeek::normalize_zeek;
pub use suricata::normalize_suricata;

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── Event source tag ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventSource {
    Zeek,
    Suricata,
    Unknown,
}

// ── Suricata alert sub-object ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertInfo {
    pub signature:        String,
    pub signature_id:     u64,
    pub category:         String,
    /// 1 = high, 2 = medium, 3 = low  (Suricata convention)
    pub severity:         u8,
    pub mitre_tactics:    Vec<String>,
    pub mitre_techniques: Vec<String>,
}

// ── Canonical normalized event ────────────────────────────────────────────
// This is our internal ECS-like representation shared by every module.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedEvent {
    // Network 5-tuple
    pub source_ip:        Option<String>,
    pub source_port:      Option<u16>,
    pub dest_ip:          Option<String>,
    pub dest_port:        Option<u16>,
    pub proto:            Option<String>,   // tcp / udp / icmp

    // Application layer (Malcolm: network.protocol, from Zeek service / Suricata app_proto)
    pub network_protocol: Option<String>,

    // Correlation join key — both Zeek and Suricata emit this for the same flow
    pub community_id:     Option<String>,

    // Source metadata
    pub event_source:     EventSource,
    pub log_source:       Option<String>,   // conn / dns / alert / flow …
    pub timestamp:        u64,              // Unix milliseconds

    // Zeek-specific
    pub uid:              Option<String>,
    pub conn_state:       Option<String>,

    // Suricata-specific
    pub event_type:       Option<String>,   // alert / flow / dns / http …
    pub alert:            Option<AlertInfo>,

    // Raw payload kept for dashboard & storage display
    pub raw:              Value,
}

impl NormalizedEvent {
    /// Parse a raw JSON value arriving from Vector into a NormalizedEvent.
    /// Returns None if the event is missing a community_id or is totally malformed.
    pub fn from_raw(raw: Value) -> Option<Self> {
        // Zeek heuristic: uid present  OR  (proto AND conn_state both present)
        let is_zeek = raw.get("uid").is_some()
            || (raw.get("proto").is_some() && raw.get("conn_state").is_some());

        if is_zeek {
            normalize_zeek(raw)
        } else {
            normalize_suricata(raw)
        }
    }

    /// True if this event should be silently dropped before correlation.
    /// Mirrors Malcolm's LOGSTASH_ZEEK_IGNORED_LOGS list and Suricata noise filter.
    pub fn should_drop(&self) -> bool {
        if let Some(ls) = &self.log_source {
            matches!(
                ls.as_str(),
                "stats" | "capture_loss" | "analyzer" | "analyzer_debug"
                    | "broker" | "reporter" | "loaded_scripts"
                    | "packet_filter" | "cluster" | "config"
                    | "stderr" | "stdout" | "prof"
            )
        } else if let Some(et) = &self.event_type {
            matches!(et.as_str(), "stats" | "fileinfo")
        } else {
            false
        }
    }

    /// Return a field value as a String for SIGMA rule matching.
    /// Falls back to the raw JSON field if not in the canonical struct.
    pub fn get_field(&self, field: &str) -> Option<String> {
    match field {
        // ── Canonical field names ─────────────────
        "source_ip"        => self.source_ip.clone(),
        "dest_ip"          => self.dest_ip.clone(),
        "source_port"      => self.source_port.map(|p| p.to_string()),
        "dest_port"        => self.dest_port.map(|p| p.to_string()),
        "proto"            => self.proto.clone(),
        "network_protocol" => self.network_protocol.clone(),
        "community_id"     => self.community_id.clone(),
        "conn_state"       => self.conn_state.clone(),
        "event_type"       => self.event_type.clone(),
        "log_source"       => self.log_source.clone(),
        "alert.signature"  => self.alert.as_ref().map(|a| a.signature.clone()),
        "alert.category"   => self.alert.as_ref().map(|a| a.category.clone()),
        "alert.severity"   => self.alert.as_ref().map(|a| a.severity.to_string()),

        // ── Aliases ───────────────────────────────
        "src_ip"    => self.source_ip.clone(),
        "dst_ip"    => self.dest_ip.clone(),
        "src_port"  => self.source_port.map(|p| p.to_string()),
        "dst_port"  => self.dest_port.map(|p| p.to_string()),
        "source"    => Some(match self.event_source {
                          EventSource::Zeek     => "zeek".to_string(),
                          EventSource::Suricata => "suricata".to_string(),
                          EventSource::Unknown  => "unknown".to_string(),
                       }),

        // ── Fallback to raw JSON ──────────────────
        _ => self.raw.get(field)
                .and_then(|v| v.as_str())
                .map(String::from),
    }
}
}

#[allow(dead_code)]
pub fn normalize(raw: &Value) -> Option<NormalizedEvent> {
    NormalizedEvent::from_raw(raw.clone())
}