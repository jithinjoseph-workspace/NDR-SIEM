//! Pure feed parsers — take an already-fetched HTTP response body and return
//! a list of [`ThreatIntelEntry`] values ready to store.
//!
//! No network calls here.  The engine (ndr-engine / siem-engine) does:
//!   1. HTTP GET  →  raw text / JSON
//!   2. parse_*(…) from this module
//!   3. Insert the returned Vec<ThreatIntelEntry> into its own storage
//!
//! This keeps the parsing logic in one place and lets every engine stay in sync
//! automatically when feeds change their format.

use super::ThreatIntelEntry;
use chrono::Duration;

// ── CISA Known Exploited Vulnerabilities ─────────────────────────────────────

/// Parse the CISA KEV JSON feed.
/// Only returns vulnerabilities added in the last 90 days to keep the table lean.
pub fn parse_cisa_kev(data: &serde_json::Value) -> Vec<ThreatIntelEntry> {
    let vulns = match data["vulnerabilities"].as_array() {
        Some(v) => v,
        None => return vec![],
    };
    let cutoff = (chrono::Utc::now() - Duration::days(90)).date_naive();
    let mut out = Vec::new();

    for v in vulns.iter().take(200) {
        let date_added = v["dateAdded"].as_str().unwrap_or("");
        if let Ok(added) = chrono::NaiveDate::parse_from_str(date_added, "%Y-%m-%d") {
            if added < cutoff { continue; }
        }

        let cve        = v["cveID"].as_str().unwrap_or("");
        let vendor     = v["vendorProject"].as_str().unwrap_or("");
        let product    = v["product"].as_str().unwrap_or("");
        let vuln_name  = v["vulnerabilityName"].as_str().unwrap_or("");
        let short_desc = v["shortDescription"].as_str().unwrap_or("");
        let action     = v["requiredAction"].as_str().unwrap_or("");
        let due_date   = v["dueDate"].as_str().unwrap_or("");
        let ransomware = v["knownRansomwareCampaignUse"].as_str().unwrap_or("Unknown");

        let attack_type = classify_attack(short_desc, cve);
        let severity    = if ransomware == "Known" { "CRITICAL" } else { "HIGH" };
        let description = format!("{} {} — {}", vendor, product, short_desc);
        let threat_pattern = format!(
            "{} affects {} {}. Vulnerability: {}. {}{}Action required: {}. Patch by: {}.",
            cve, vendor, product, vuln_name,
            if ransomware == "Known" { "ACTIVE RANSOMWARE CAMPAIGN USE. " } else { "" },
            if !short_desc.is_empty() { format!("Attack: {}. ", short_desc) } else { String::new() },
            action, due_date
        );

        out.push(ThreatIntelEntry {
            source: "cisa_kev".into(),
            attack_type,
            severity: severity.into(),
            ioc_type: "cve".into(),
            ioc_value: cve.to_string(),
            description,
            threat_pattern,
        });
    }
    out
}

// ── AbuseIPDB ────────────────────────────────────────────────────────────────

/// Parse the AbuseIPDB blacklist JSON response.
/// Requires the response body already fetched with the API key header.
pub fn parse_abuseipdb(data: &serde_json::Value) -> Vec<ThreatIntelEntry> {
    let ips = match data["data"].as_array() {
        Some(v) => v,
        None => return vec![],
    };
    let mut out = Vec::new();

    for entry in ips {
        let ip    = entry["ipAddress"].as_str().unwrap_or("");
        let score = entry["abuseConfidenceScore"].as_u64().unwrap_or(0);
        let country = entry["countryCode"].as_str().unwrap_or("??");
        let last_reported = entry["lastReportedAt"].as_str().unwrap_or("");
        if ip.is_empty() { continue; }

        let sev = if score > 95 { "HIGH" } else { "MEDIUM" };

        let categories = entry["abuseCategories"]
            .as_array()
            .map(|arr| arr.iter()
                .filter_map(|c| c.as_u64())
                .map(abuseipdb_category_name)
                .collect::<Vec<_>>()
                .join(", "))
            .unwrap_or_else(|| "malicious activity".to_string());

        let attack_type = categories_to_attack(&categories);
        let description = format!("Reported malicious IP from {} — confidence {}%", country, score);
        let threat_pattern = format!(
            "IP {} ({}): confidence {}%, reported for: {}. Last seen: {}. \
             Actively targeting internet-facing services.",
            ip, country, score, categories, last_reported
        );

        out.push(ThreatIntelEntry {
            source: "abuseipdb".into(),
            attack_type,
            severity: sev.into(),
            ioc_type: "ip".into(),
            ioc_value: ip.to_string(),
            description,
            threat_pattern,
        });
    }
    out
}

// ── AlienVault OTX ───────────────────────────────────────────────────────────

/// Parse OTX pulse subscriptions JSON response. Returns up to 20 IOCs per pulse.
pub fn parse_otx(data: &serde_json::Value) -> Vec<ThreatIntelEntry> {
    let pulses = match data["results"].as_array() {
        Some(v) => v,
        None => return vec![],
    };
    let mut out = Vec::new();

    for pulse in pulses {
        let name    = pulse["name"].as_str().unwrap_or("");
        let desc    = pulse["description"].as_str().unwrap_or("");
        let author  = pulse["author_name"].as_str().unwrap_or("");
        let tags    = pulse["tags"].as_array()
            .map(|t| t.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(", "))
            .unwrap_or_default();
        let tlp     = pulse["tlp"].as_str().unwrap_or("white");
        let attack_type = classify_attack(name, desc);

        let threat_pattern = format!(
            "Threat pulse '{}' by {}. Tags: {}. TLP: {}. {}",
            name, author, tags, tlp,
            if !desc.is_empty() { desc.chars().take(300).collect::<String>() }
            else { "No description.".into() }
        );
        let desc_short = format!("OTX pulse: {} [{}]", name, tags);

        if let Some(indicators) = pulse["indicators"].as_array() {
            for ioc in indicators.iter().take(20) {
                let ioc_type = ioc["type"].as_str().unwrap_or("");
                let ioc_val  = ioc["indicator"].as_str().unwrap_or("");
                if ioc_val.is_empty() { continue; }

                out.push(ThreatIntelEntry {
                    source: "otx".into(),
                    attack_type: attack_type.clone(),
                    severity: "MEDIUM".into(),
                    ioc_type: ioc_type.to_string(),
                    ioc_value: ioc_val.to_string(),
                    description: desc_short.clone(),
                    threat_pattern: threat_pattern.clone(),
                });
            }
        }
    }
    out
}

// ── Emerging Threats ─────────────────────────────────────────────────────────

/// Parse an Emerging Threats .rules file (plain text).
/// Groups by classtype and returns one entry per attack category.
pub fn parse_emerging_threats(text: &str) -> Vec<ThreatIntelEntry> {
    let mut categories: std::collections::HashMap<String, (u32, Vec<String>)> = Default::default();

    for line in text.lines().take(500) {
        if line.starts_with('#') { continue; }
        let classtype = line.split("classtype:").nth(1)
            .and_then(|s| s.split(';').next())
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let msg = line.split("msg:\"").nth(1)
            .and_then(|s| s.split('"').next())
            .map(|s| s.to_string())
            .unwrap_or_default();
        if classtype.is_empty() { continue; }
        let entry = categories.entry(classtype_to_attack(&classtype)).or_insert((0, vec![]));
        entry.0 += 1;
        if entry.1.len() < 3 && !msg.is_empty() {
            entry.1.push(msg);
        }
    }

    categories.into_iter().map(|(attack_type, (count, examples))| {
        ThreatIntelEntry {
            source:      "emerging_threats".into(),
            attack_type: attack_type.clone(),
            severity:    "MEDIUM".into(),
            ioc_type:    String::new(),
            ioc_value:   String::new(),
            description: format!("{} active rules in current events", count),
            threat_pattern: format!(
                "Emerging Threats: {} active rules for {} attack type. Examples: {}.",
                count, attack_type, examples.join(" | ")
            ),
        }
    }).collect()
}

// ── Shared helpers ────────────────────────────────────────────────────────────

/// Classify an attack type from free-text (rule title, description, CVE id).
pub fn classify_attack(a: &str, b: &str) -> String {
    let t = format!("{} {}", a, b).to_lowercase();
    if t.contains("ransom")                                                   { return "ransomware".into(); }
    if t.contains("credential") || t.contains("brute") || t.contains("phish") { return "credential_attack".into(); }
    if t.contains("exploit") || t.contains("rce")                             { return "exploitation".into(); }
    if t.contains("lateral") || t.contains("pivot") || t.contains("smb")     { return "lateral_movement".into(); }
    if t.contains("c2") || t.contains("beacon") || t.contains("rat ")        { return "c2_communication".into(); }
    if t.contains("exfil") || t.contains("stealer")                          { return "data_exfiltration".into(); }
    if t.contains("scan") || t.contains("recon")                             { return "recon".into(); }
    if t.contains("supply chain") || t.contains("package")                   { return "supply_chain".into(); }
    "general_threat".into()
}

pub fn classtype_to_attack(ct: &str) -> String {
    match ct {
        "trojan-activity"  => "c2_communication",
        "attempted-user"   => "exploitation",
        "attempted-admin"  => "exploitation",
        "network-scan"     => "recon",
        "attempted-recon"  => "recon",
        "credential-theft" => "credential_attack",
        _                  => "general_threat",
    }.into()
}

pub fn abuseipdb_category_name(code: u64) -> &'static str {
    match code {
        3  => "fraud orders",    4  => "DDoS attack",
        5  => "FTP brute force", 6  => "ping of death",
        7  => "phishing",        8  => "fraud VoIP",
        9  => "open proxy",      10 => "web spam",
        11 => "email spam",      12 => "blog spam",
        13 => "VPN IP",          14 => "port scan",
        15 => "hacking",         16 => "SQL injection",
        17 => "spoofing",        18 => "brute force",
        19 => "bad web bot",     20 => "exploited host",
        21 => "web app attack",  22 => "SSH brute force",
        23 => "IoT targeted",    _  => "malicious activity",
    }
}

pub fn categories_to_attack(cats: &str) -> String {
    let c = cats.to_lowercase();
    if c.contains("brute") || c.contains("ssh") { return "credential_attack".into(); }
    if c.contains("scan")                        { return "recon".into(); }
    if c.contains("phish")                       { return "credential_attack".into(); }
    if c.contains("exploit") || c.contains("sql"){ return "exploitation".into(); }
    if c.contains("ddos")                        { return "denial_of_service".into(); }
    "general_threat".into()
}
