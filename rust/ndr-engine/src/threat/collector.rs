use tokio::time::Duration;
use tracing::{info, warn};

pub fn spawn_collector(ch: std::sync::Arc<crate::storage::ClickhouseStorage>) {
    tokio::spawn(async move {
        loop {
            info!("Threat intel collection starting");
            collect_all(&ch).await;
            info!("Threat intel collection done — next run in 6 hours");
            tokio::time::sleep(Duration::from_secs(6 * 3600)).await;
        }
    });
}

pub async fn collect_all(ch: &crate::storage::ClickhouseStorage) {
    let settings = ch.get_settings_by_tenant("default").await.unwrap_or_default();
    let abuseipdb_key = settings["abuseipdb_api_key"].as_str().unwrap_or("").to_string();
    let otx_key      = settings["otx_api_key"].as_str().unwrap_or("").to_string();

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("NDR-Engine/1.0")
        .build()
        .unwrap_or_default();

    tokio::join!(
        collect_cisa_kev(&http, ch),
        collect_abuseipdb(&http, ch, &abuseipdb_key),
        collect_otx(&http, ch, &otx_key),
        collect_emerging_threats(&http, ch),
    );
}

async fn insert_intel(
    ch: &crate::storage::ClickhouseStorage,
    source: &str,
    attack_type: &str,
    severity: &str,
    ioc_type: &str,
    ioc_value: &str,
    description: &str,
    threat_pattern: &str,
) {
    let q = format!(
        "INSERT INTO ndr.threat_intel \
         (source, attack_type, severity, ioc_type, ioc_value, description, threat_pattern) \
         VALUES ('{}','{}','{}','{}','{}','{}','{}')",
        esc(source), esc(attack_type), esc(severity),
        esc(ioc_type), esc(ioc_value), esc(description), esc(threat_pattern)
    );
    let _ = ch.client.query(&q).execute().await;
}

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

// ── CISA Known Exploited Vulnerabilities ─────────────────────────────────────
async fn collect_cisa_kev(
    http: &reqwest::Client,
    ch: &crate::storage::ClickhouseStorage,
) {
    let url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    let Ok(resp) = http.get(url).send().await else { return };
    let Ok(data) = resp.json::<serde_json::Value>().await else { return };

    let vulns = data["vulnerabilities"].as_array().cloned().unwrap_or_default();
    let cutoff = (chrono::Utc::now() - chrono::Duration::days(90)).date_naive();
    let mut count = 0;

    for v in vulns.iter().take(200) {
        let date_added = v["dateAdded"].as_str().unwrap_or("");
        if let Ok(added) = chrono::NaiveDate::parse_from_str(date_added, "%Y-%m-%d") {
            if added < cutoff { continue; }
        }
        let cve         = v["cveID"].as_str().unwrap_or("");
        let vendor      = v["vendorProject"].as_str().unwrap_or("");
        let product     = v["product"].as_str().unwrap_or("");
        let vuln_name   = v["vulnerabilityName"].as_str().unwrap_or("");
        let short_desc  = v["shortDescription"].as_str().unwrap_or("");
        let action      = v["requiredAction"].as_str().unwrap_or("");
        let due_date    = v["dueDate"].as_str().unwrap_or("");
        let ransomware  = v["knownRansomwareCampaignUse"].as_str().unwrap_or("Unknown");

        let attack_type = classify_attack(short_desc, cve);
        let severity    = if ransomware == "Known" { "CRITICAL" } else { "HIGH" };

        let description = format!("{} {} — {}", vendor, product, short_desc);

        // Rich pattern text for AI correlation
        let threat_pattern = format!(
            "{} affects {} {}. Vulnerability: {}. {}{}Action required: {}. Patch by: {}.",
            cve, vendor, product, vuln_name,
            if ransomware == "Known" { "ACTIVE RANSOMWARE CAMPAIGN USE. " } else { "" },
            if !short_desc.is_empty() { format!("Attack: {}. ", short_desc) } else { String::new() },
            action, due_date
        );

        insert_intel(ch, "cisa_kev", &attack_type, severity, "cve", cve, &description, &threat_pattern).await;
        count += 1;
    }
    info!("CISA KEV: {} recent vulns collected", count);
}

// ── AbuseIPDB ────────────────────────────────────────────────────────────────
async fn collect_abuseipdb(
    http: &reqwest::Client,
    ch: &crate::storage::ClickhouseStorage,
    api_key: &str,
) {
    if api_key.is_empty() {
        warn!("abuseipdb_api_key not configured in settings — skipping");
        return;
    }
    let url = "https://api.abuseipdb.com/api/v2/blacklist?limit=1000&confidenceMinimum=90";
    let Ok(resp) = http.get(url)
        .header("Key", api_key)
        .header("Accept", "application/json")
        .send().await else { return };
    let Ok(data) = resp.json::<serde_json::Value>().await else { return };

    let ips = data["data"].as_array().cloned().unwrap_or_default();
    let count = ips.len();
    for entry in &ips {
        let ip           = entry["ipAddress"].as_str().unwrap_or("");
        let score        = entry["abuseConfidenceScore"].as_u64().unwrap_or(0);
        let country      = entry["countryCode"].as_str().unwrap_or("??");
        let last_reported = entry["lastReportedAt"].as_str().unwrap_or("");
        if ip.is_empty() { continue; }

        let sev = if score > 95 { "HIGH" } else { "MEDIUM" };

        // Map category codes to readable text
        let categories = entry["abuseCategories"]
            .as_array()
            .map(|arr| arr.iter()
                .filter_map(|c| c.as_u64())
                .map(category_name)
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

        insert_intel(ch, "abuseipdb", &attack_type, sev, "ip", ip, &description, &threat_pattern).await;
    }
    info!("AbuseIPDB: {} malicious IPs collected", count);
}

fn category_name(code: u64) -> &'static str {
    match code {
        3  => "fraud orders",
        4  => "DDoS attack",
        5  => "FTP brute force",
        6  => "ping of death",
        7  => "phishing",
        8  => "fraud VoIP",
        9  => "open proxy",
        10 => "web spam",
        11 => "email spam",
        12 => "blog spam",
        13 => "VPN IP",
        14 => "port scan",
        15 => "hacking",
        16 => "SQL injection",
        17 => "spoofing",
        18 => "brute force",
        19 => "bad web bot",
        20 => "exploited host",
        21 => "web app attack",
        22 => "SSH brute force",
        23 => "IoT targeted",
        _  => "malicious activity",
    }
}

fn categories_to_attack(cats: &str) -> String {
    let c = cats.to_lowercase();
    if c.contains("brute") || c.contains("ssh") { return "credential_attack".into(); }
    if c.contains("scan") { return "recon".into(); }
    if c.contains("phish") { return "credential_attack".into(); }
    if c.contains("exploit") || c.contains("sql") { return "exploitation".into(); }
    if c.contains("ddos") { return "denial_of_service".into(); }
    "general_threat".into()
}

// ── AlienVault OTX ───────────────────────────────────────────────────────────
async fn collect_otx(
    http: &reqwest::Client,
    ch: &crate::storage::ClickhouseStorage,
    api_key: &str,
) {
    if api_key.is_empty() {
        warn!("otx_api_key not configured in settings — skipping");
        return;
    }
    let url = "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=20";
    let Ok(resp) = http.get(url)
        .header("X-OTX-API-KEY", api_key)
        .send().await else { return };
    let Ok(data) = resp.json::<serde_json::Value>().await else { return };

    let pulses = data["results"].as_array().cloned().unwrap_or_default();
    let mut total = 0usize;

    for pulse in &pulses {
        let name        = pulse["name"].as_str().unwrap_or("");
        let description = pulse["description"].as_str().unwrap_or("");
        let author      = pulse["author_name"].as_str().unwrap_or("");
        let tags        = pulse["tags"].as_array()
            .map(|t| t.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(", "))
            .unwrap_or_default();
        let tlp         = pulse["tlp"].as_str().unwrap_or("white");
        let attack_type = classify_attack(name, description);

        // Full attack narrative for AI
        let threat_pattern = format!(
            "Threat pulse '{}' by {}. Tags: {}. TLP: {}. {}",
            name, author, tags, tlp,
            if !description.is_empty() {
                description.chars().take(300).collect::<String>()
            } else { "No description.".into() }
        );

        let desc_short = format!("OTX pulse: {} [{}]", name, tags);

        if let Some(indicators) = pulse["indicators"].as_array() {
            for ioc in indicators.iter().take(20) {
                let ioc_type = ioc["type"].as_str().unwrap_or("");
                let ioc_val  = ioc["indicator"].as_str().unwrap_or("");
                if ioc_val.is_empty() { continue; }
                insert_intel(ch, "otx", &attack_type, "MEDIUM", ioc_type, ioc_val, &desc_short, &threat_pattern).await;
                total += 1;
            }
        }
    }
    info!("OTX: {} IOCs from {} pulses", total, pulses.len());
}

// ── Emerging Threats ─────────────────────────────────────────────────────────
async fn collect_emerging_threats(
    http: &reqwest::Client,
    ch: &crate::storage::ClickhouseStorage,
) {
    let url = "https://rules.emergingthreats.net/open/suricata-5.0/rules/emerging-current_events.rules";
    let Ok(resp) = http.get(url).send().await else { return };
    let Ok(text) = resp.text().await else { return };

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

    for (attack_type, (count, examples)) in &categories {
        let desc = format!("{} active rules in current events", count);
        let threat_pattern = format!(
            "Emerging Threats: {} active rules for {} attack type. Examples: {}.",
            count, attack_type,
            examples.join(" | ")
        );
        insert_intel(ch, "emerging_threats", attack_type, "MEDIUM", "", "", &desc, &threat_pattern).await;
    }
    info!("Emerging Threats: {} attack categories", categories.len());
}

// ── Helpers ──────────────────────────────────────────────────────────────────
pub fn classify_attack(a: &str, b: &str) -> String {
    let t = format!("{} {}", a, b).to_lowercase();
    if t.contains("ransom")                                              { return "ransomware".into(); }
    if t.contains("credential") || t.contains("brute") || t.contains("phish") { return "credential_attack".into(); }
    if t.contains("exploit") || t.contains("rce")                       { return "exploitation".into(); }
    if t.contains("lateral") || t.contains("pivot") || t.contains("smb") { return "lateral_movement".into(); }
    if t.contains("c2") || t.contains("beacon") || t.contains("rat ")   { return "c2_communication".into(); }
    if t.contains("exfil") || t.contains("stealer")                     { return "data_exfiltration".into(); }
    if t.contains("scan") || t.contains("recon")                        { return "recon".into(); }
    if t.contains("supply chain") || t.contains("package")              { return "supply_chain".into(); }
    "general_threat".into()
}

fn classtype_to_attack(ct: &str) -> String {
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
