use tokio::time::Duration;
use tracing::{info, warn};
use provigil_common::threat_intel::{
    ThreatIntelEntry,
    FEED_CISA_KEV, FEED_ABUSEIPDB, FEED_OTX, FEED_EMERGING_THREATS,
    FEED_FEODO, FEED_URLHAUS, FEED_THREATFOX,
    FEED_SPAMHAUS_DROP, FEED_SPAMHAUS_EDROP,
    feeds::{parse_cisa_kev, parse_abuseipdb, parse_otx, parse_emerging_threats,
            parse_feodo, parse_urlhaus, parse_threatfox, parse_spamhaus_drop},
};

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
    let existing = std::sync::Arc::new(fetch_existing_iocs(ch).await);

    let settings = ch.get_settings_by_tenant("default").await.unwrap_or_default();
    let abuseipdb_key = settings["abuseipdb_api_key"].as_str().unwrap_or("").to_string();
    let otx_key      = settings["otx_api_key"].as_str().unwrap_or("").to_string();

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("NDR-Engine/1.0")
        .build()
        .unwrap_or_default();

    tokio::join!(
        run_feed_cisa_kev(&http, ch, &existing),
        run_feed_abuseipdb(&http, ch, &abuseipdb_key, &existing),
        run_feed_otx(&http, ch, &otx_key, &existing),
        run_feed_emerging_threats(&http, ch, &existing),
        run_feed_feodo(&http, ch, &existing),
        run_feed_urlhaus(&http, ch, &existing),
        run_feed_threatfox(&http, ch, &existing),
        run_feed_spamhaus(&http, ch, &existing),
    );
}

async fn fetch_existing_iocs(
    ch: &crate::storage::ClickhouseStorage,
) -> std::collections::HashSet<(String, String)> {
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct Row { source: String, ioc_value: String }

    ch.client
        .query("SELECT source, ioc_value FROM ndr.threat_intel FINAL WHERE expires_at > now()")
        .fetch_all::<Row>()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|r| (r.source, r.ioc_value))
        .collect()
}

async fn insert_entries(
    ch: &crate::storage::ClickhouseStorage,
    existing: &std::collections::HashSet<(String, String)>,
    entries: Vec<ThreatIntelEntry>,
) -> usize {
    let mut saved = 0;
    for e in entries {
        if existing.contains(&(e.source.clone(), e.ioc_value.clone())) { continue; }
        let q = format!(
            "INSERT INTO ndr.threat_intel \
             (source, attack_type, severity, ioc_type, ioc_value, description, threat_pattern) \
             VALUES ('{}','{}','{}','{}','{}','{}','{}')",
            esc(&e.source), esc(&e.attack_type), esc(&e.severity),
            esc(&e.ioc_type), esc(&e.ioc_value), esc(&e.description), esc(&e.threat_pattern)
        );
        if ch.client.query(&q).execute().await.is_ok() { saved += 1; }
    }
    saved
}

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

// ── Feed runners — HTTP fetch + shared parser + insert ────────────────────────

async fn run_feed_cisa_kev(
    http: &reqwest::Client,
    ch: &crate::storage::ClickhouseStorage,
    existing: &std::collections::HashSet<(String, String)>,
) {
    let Ok(resp) = http.get(FEED_CISA_KEV).send().await else { return };
    let Ok(data) = resp.json::<serde_json::Value>().await else { return };
    let entries = parse_cisa_kev(&data);
    let n = insert_entries(ch, existing, entries).await;
    info!("CISA KEV: {} recent vulns collected", n);
}

async fn run_feed_abuseipdb(
    http: &reqwest::Client,
    ch: &crate::storage::ClickhouseStorage,
    api_key: &str,
    existing: &std::collections::HashSet<(String, String)>,
) {
    if api_key.is_empty() {
        warn!("abuseipdb_api_key not configured in settings — skipping");
        return;
    }
    let Ok(resp) = http.get(FEED_ABUSEIPDB)
        .header("Key", api_key)
        .header("Accept", "application/json")
        .send().await else { return };
    let Ok(data) = resp.json::<serde_json::Value>().await else { return };
    let entries = parse_abuseipdb(&data);
    let n = entries.len();
    insert_entries(ch, existing, entries).await;
    info!("AbuseIPDB: {} malicious IPs collected", n);
}

async fn run_feed_otx(
    http: &reqwest::Client,
    ch: &crate::storage::ClickhouseStorage,
    api_key: &str,
    existing: &std::collections::HashSet<(String, String)>,
) {
    if api_key.is_empty() {
        warn!("otx_api_key not configured in settings — skipping");
        return;
    }
    let Ok(resp) = http.get(FEED_OTX)
        .header("X-OTX-API-KEY", api_key)
        .send().await else { return };
    let Ok(data) = resp.json::<serde_json::Value>().await else { return };
    let entries = parse_otx(&data);
    let n = entries.len();
    insert_entries(ch, existing, entries).await;
    info!("OTX: {} IOCs collected", n);
}

async fn run_feed_emerging_threats(
    http: &reqwest::Client,
    ch: &crate::storage::ClickhouseStorage,
    existing: &std::collections::HashSet<(String, String)>,
) {
    let Ok(resp) = http.get(FEED_EMERGING_THREATS).send().await else { return };
    let Ok(text) = resp.text().await else { return };
    let entries = parse_emerging_threats(&text);
    let n = entries.len();
    insert_entries(ch, existing, entries).await;
    info!("Emerging Threats: {} attack categories", n);
}

async fn run_feed_feodo(
    http: &reqwest::Client,
    ch: &crate::storage::ClickhouseStorage,
    existing: &std::collections::HashSet<(String, String)>,
) {
    let Ok(resp) = http.get(FEED_FEODO).send().await else { return };
    let Ok(data) = resp.json::<serde_json::Value>().await else { return };
    let entries = parse_feodo(&data);
    let n = insert_entries(ch, existing, entries).await;
    info!("Feodo Tracker: {} botnet C2 IPs collected", n);
}

async fn run_feed_urlhaus(
    http: &reqwest::Client,
    ch: &crate::storage::ClickhouseStorage,
    existing: &std::collections::HashSet<(String, String)>,
) {
    let Ok(resp) = http.get(FEED_URLHAUS).send().await else { return };
    let Ok(data) = resp.json::<serde_json::Value>().await else { return };
    let entries = parse_urlhaus(&data);
    let n = insert_entries(ch, existing, entries).await;
    info!("URLhaus: {} malware distribution IOCs collected", n);
}

async fn run_feed_threatfox(
    http: &reqwest::Client,
    ch: &crate::storage::ClickhouseStorage,
    existing: &std::collections::HashSet<(String, String)>,
) {
    // ThreatFox uses a POST request with a JSON body to query recent IOCs
    let body = serde_json::json!({ "query": "get_iocs", "days": 3 });
    let Ok(resp) = http.post(FEED_THREATFOX)
        .json(&body)
        .send().await else { return };
    let Ok(data) = resp.json::<serde_json::Value>().await else { return };
    let entries = parse_threatfox(&data);
    let n = insert_entries(ch, existing, entries).await;
    info!("ThreatFox: {} malware family IOCs collected", n);
}

async fn run_feed_spamhaus(
    http: &reqwest::Client,
    ch: &crate::storage::ClickhouseStorage,
    existing: &std::collections::HashSet<(String, String)>,
) {
    // Fetch DROP and EDROP in parallel — same format, same parser
    let (drop_res, edrop_res) = tokio::join!(
        http.get(FEED_SPAMHAUS_DROP).send(),
        http.get(FEED_SPAMHAUS_EDROP).send(),
    );

    let mut all_entries = Vec::new();

    if let Ok(r) = drop_res {
        if let Ok(text) = r.text().await {
            all_entries.extend(parse_spamhaus_drop(&text, "DROP"));
        }
    }
    if let Ok(r) = edrop_res {
        if let Ok(text) = r.text().await {
            all_entries.extend(parse_spamhaus_drop(&text, "EDROP"));
        }
    }

    let n = insert_entries(ch, existing, all_entries).await;
    info!("Spamhaus DROP+EDROP: {} criminal CIDR blocks collected", n);
}

// Re-export for use in other ndr-engine modules that already call classify_attack
pub use provigil_common::threat_intel::feeds::classify_attack;
