pub mod feeds;

use serde::{Deserialize, Serialize};

// ── IOC types ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IocType {
    Ip,
    Domain,
    Url,
    Hash,
    Cve,
    Email,
    /// Catch-all for feed-specific types (e.g. "FileHash-SHA256")
    Other(String),
}

impl IocType {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "ip" | "ipv4" | "ipv6" => IocType::Ip,
            "domain" | "hostname"  => IocType::Domain,
            "url"                  => IocType::Url,
            "md5" | "sha1" | "sha256" | "hash" => IocType::Hash,
            "cve"                  => IocType::Cve,
            "email"                => IocType::Email,
            other                  => IocType::Other(other.to_string()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            IocType::Ip     => "ip",
            IocType::Domain => "domain",
            IocType::Url    => "url",
            IocType::Hash   => "hash",
            IocType::Cve    => "cve",
            IocType::Email  => "email",
            IocType::Other(s) => s.as_str(),
        }
    }
}

// ── Feed source ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedSource {
    CisaKev,
    AbuseIpDb,
    Otx,
    EmergingThreats,
    Custom(String),
}

impl FeedSource {
    pub fn as_str(&self) -> &str {
        match self {
            FeedSource::CisaKev         => "cisa_kev",
            FeedSource::AbuseIpDb       => "abuseipdb",
            FeedSource::Otx             => "otx",
            FeedSource::EmergingThreats => "emerging_threats",
            FeedSource::Custom(s)       => s.as_str(),
        }
    }
}

// ── A single IOC ready to be stored ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelEntry {
    pub source:         String,
    pub attack_type:    String,
    /// "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    pub severity:       String,
    pub ioc_type:       String,
    pub ioc_value:      String,
    pub description:    String,
    /// Rich narrative text used by the AI correlation layer
    pub threat_pattern: String,
}

// ── Lookup result returned by enrichment ─────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ThreatLookupResult {
    pub is_malicious: bool,
    /// Highest severity across all matched IOC entries
    pub severity:     String,
    /// Feed sources that matched (e.g. ["abuseipdb", "otx"])
    pub sources:      Vec<String>,
    pub attack_types: Vec<String>,
    pub description:  String,
}

// ── Feed URLs (same for both ndr-engine and siem-engine) ─────────────────────

pub const FEED_CISA_KEV: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

pub const FEED_ABUSEIPDB: &str =
    "https://api.abuseipdb.com/api/v2/blacklist?limit=1000&confidenceMinimum=90";

pub const FEED_OTX: &str =
    "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=20";

pub const FEED_EMERGING_THREATS: &str =
    "https://rules.emergingthreats.net/open/suricata-5.0/rules/emerging-current_events.rules";
