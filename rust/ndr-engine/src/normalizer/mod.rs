// NDR Engine — Canonical Event Model + Normalizer
// Field names inspired by Malcolm's ECS normalization (public domain, CC0).
// This code is 100% original. License: Apache-2.0

mod zeek;
mod suricata;
mod linux;

pub use zeek::normalize_zeek;
pub use suricata::normalize_suricata;
pub use linux::normalize_linux;

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── Event source tag ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventSource {
    Zeek,
    Suricata,
    Linux,
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

    // ── Enrichment fields ─────────────────────────────────────────────────
    // Populated by the consumer BEFORE Sigma detection so rules can test
    // geo, threat-intel, and direction. Absent from wire data — default.
    #[serde(default)]
    pub is_malicious:     bool,
    #[serde(default)]
    pub src_country_code: String,
    #[serde(default)]
    pub dst_country_code: String,
    #[serde(default)]
    pub src_asn_org:      String,
    #[serde(default)]
    pub dst_asn_org:      String,
    #[serde(default)]
    pub direction:        String,  // "inbound" | "outbound" | "internal" | "unknown"
}

impl NormalizedEvent {
    /// A blank event used as the "absent" half of a Zeek-only CorrelationHit
    /// when we need to call RiskScorer without a matching Suricata event.
    pub fn blank() -> Self {
        NormalizedEvent {
            source_ip: None, source_port: None,
            dest_ip:   None, dest_port:   None,
            proto: None, network_protocol: None, community_id: None,
            event_source: EventSource::Unknown, log_source: None,
            timestamp: 0, uid: None, conn_state: None,
            event_type: None, alert: None,
            raw: Value::Null,
            is_malicious: false,
            src_country_code: String::new(), dst_country_code: String::new(),
            src_asn_org: String::new(),      dst_asn_org: String::new(),
            direction: String::new(),
        }
    }

    /// Parse a raw JSON value arriving from Vector into a NormalizedEvent.
    /// Returns None if the event is missing a community_id or is totally malformed.
    pub fn from_raw(raw: Value) -> Option<Self> {
        let source = raw.get("source").and_then(|v| v.as_str()).unwrap_or("");

        // Linux endpoint events from auditd take priority — they have no community_id
        if source == "linux" {
            return normalize_linux(raw);
        }

        // Use explicit source tag from Vector, fallback to heuristic
        let is_zeek = source == "agent-z" || source == "zeek"
            || raw.get("uid").is_some()
            || raw.get("_path").is_some()
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
        // Drop conn-log entries with no IP endpoints — malformed packet fragments
        // Zeek couldn't fully decode (show as "- -> -" in UI). Only applies to
        // conn/flow logs; dhcp, weird, files etc. legitimately lack the IP tuple.
        let is_conn_log = self.log_source.as_deref()
            .map(|s| matches!(s, "conn" | "flow"))
            .unwrap_or(false);
        if is_conn_log {
            let no_src = self.source_ip.as_deref().map(|s| s.is_empty()).unwrap_or(true);
            let no_dst = self.dest_ip.as_deref().map(|s| s.is_empty()).unwrap_or(true);
            if no_src && no_dst {
                return true;
            }
        }

        if let Some(ls) = &self.log_source {
            matches!(
                ls.as_str(),
                "stats" | "capture_loss" | "analyzer" | "analyzer_debug"
                    | "broker" | "reporter" | "loaded_scripts"
                    | "packet_filter" | "cluster" | "config"
                    | "stderr" | "stdout" | "prof"
            )
        } else if let Some(et) = &self.event_type {
            matches!(et.as_str(), "stats")
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

        // ── Linux endpoint fields (SIGMA linux rules) ─────────────────────
        "Image"               => self.raw.get("Image").and_then(|v| v.as_str()).map(String::from),
        "CommandLine"         => self.raw.get("CommandLine").and_then(|v| v.as_str()).map(String::from),
        "ParentImage"         => self.raw.get("ParentImage").and_then(|v| v.as_str()).map(String::from),
        "ParentCommandLine"   => self.raw.get("ParentCommandLine").and_then(|v| v.as_str()).map(String::from),
        "User"                => self.raw.get("User").and_then(|v| v.as_str()).map(String::from),
        "ProcessId"           => self.raw.get("pid").and_then(|v| v.as_str()).map(String::from),
        "ParentProcessId"     => self.raw.get("ppid").and_then(|v| v.as_str()).map(String::from),
        "TargetFilename"      => self.raw.get("TargetFilename").and_then(|v| v.as_str()).map(String::from),
        "DestinationIp"       => self.dest_ip.clone()
                                    .or_else(|| self.raw.get("DestinationIp").and_then(|v| v.as_str()).map(String::from)),
        "DestinationPort"     => self.dest_port.map(|p| p.to_string())
                                    .or_else(|| self.raw.get("DestinationPort").and_then(|v| v.as_str()).map(String::from)),
        "DestinationHostname" => self.raw.get("DestinationHostname").and_then(|v| v.as_str()).map(String::from),
        "Initiated"           => self.raw.get("Initiated").and_then(|v| v.as_str()).map(String::from),
        "type"                => self.raw.get("record_type").and_then(|v| v.as_str()).map(String::from),
        "exe"                 => self.raw.get("exe").and_then(|v| v.as_str()).map(String::from),
        "comm"                => self.raw.get("comm").and_then(|v| v.as_str()).map(String::from),

        // ── Enrichment fields (populated before Sigma in consumer) ───────
        "is_malicious"      => Some(self.is_malicious.to_string()),
        "direction"         => if self.direction.is_empty() { None } else { Some(self.direction.clone()) },
        "src_country_code"
        | "src_country"     => if self.src_country_code.is_empty() { None } else { Some(self.src_country_code.clone()) },
        "dst_country_code"
        | "dst_country"     => if self.dst_country_code.is_empty() { None } else { Some(self.dst_country_code.clone()) },
        "src_asn_org"       => if self.src_asn_org.is_empty() { None } else { Some(self.src_asn_org.clone()) },
        "dst_asn_org"
        | "asn_org"         => if self.dst_asn_org.is_empty() { None } else { Some(self.dst_asn_org.clone()) },

        // ── Aliases ───────────────────────────────
        "src_ip"    => self.source_ip.clone(),
        "dst_ip"    => self.dest_ip.clone(),
        "src_port"  => self.source_port.map(|p| p.to_string()),
        "dst_port"  => self.dest_port.map(|p| p.to_string()),

        // ── Zeek raw field names (SigmaHQ community rules use these) ─────
        // Community Zeek rules reference the original TSV column names that
        // Zeek writes before Vector remaps them. Map them to canonical fields
        // so rules like `id.orig_h|cidr: 10.0.0.0/8` resolve correctly.
        "id.orig_h" => self.source_ip.clone(),
        "id.resp_h" => self.dest_ip.clone(),
        "id.orig_p" => self.source_port.map(|p| p.to_string()),
        "id.resp_p" => self.dest_port.map(|p| p.to_string()),
        "source"    => Some(match self.event_source {
                          EventSource::Zeek     => "agent-z".to_string(),
                          EventSource::Suricata => "agent-s".to_string(),
                          EventSource::Linux    => "linux".to_string(),
                          EventSource::Unknown  => "unknown".to_string(),
                       }),

        // ── Fallback to raw JSON with dot-path traversal ─────────────────
        // Handles both flat keys ("query") and nested paths ("certificate.serial")
        _ => {
            // Try exact flat key first
            if let Some(v) = self.raw.get(field).and_then(|v| v.as_str()) {
                return Some(v.to_string());
            }
            // Traverse dot-separated path through nested objects
            let parts: Vec<&str> = field.split('.').collect();
            if parts.len() > 1 {
                let mut cur = &self.raw;
                for part in &parts {
                    match cur.get(*part) {
                        Some(v) => cur = v,
                        None    => return None,
                    }
                }
                return cur.as_str().map(String::from)
                    .or_else(|| if cur.is_null() { None } else { Some(cur.to_string()) });
            }
            None
        }
    }
}
}

#[allow(dead_code)]
pub fn normalize(raw: &Value) -> Option<NormalizedEvent> {
    NormalizedEvent::from_raw(raw.clone())
}