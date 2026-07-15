// SIGMA community rules auto-updater.
// Weekly background fetch from SigmaHQ GitHub (network rules only).
// Also exposes `sync_now()` for the admin UI "Sync Rules" button.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{info, warn};

use super::{DetectionEngine, parse_rule_content};

const GITHUB_NETWORK_API: &str =
    "https://api.github.com/repos/SigmaHQ/sigma/contents/rules/network";
const GITHUB_LINUX_API: &str =
    "https://api.github.com/repos/SigmaHQ/sigma/contents/rules/linux";

/// Rules that should never appear in the active rule set regardless of sync or DB state.
/// These are removed from ClickHouse on startup and skipped during every sync.
pub const GLOBAL_RULE_BLOCKLIST: &[&str] = &[
    "1fc0809e-06bf-4de3-ad52-25e5263b7623", // Publicly Accessible RDP Service (noisy false-positive)
];

/// Spawn a background task that re-fetches SigmaHQ network rules once a week
/// and publishes the Redis `system:reload_rules` signal on success.
pub fn spawn_sigma_updater(
    rules_dir: String,
    redis_url: String,
    engine:    Arc<RwLock<DetectionEngine>>,
    ch:        Arc<crate::storage::ClickhouseStorage>,
) {
    tokio::spawn(async move {
        // First run 1 hour after engine start, then every 7 days.
        tokio::time::sleep(Duration::from_secs(3_600)).await;
        loop {
            info!("SIGMA updater: checking SigmaHQ for new rules…");
            match fetch_all_rules(&rules_dir, &ch).await {
                Ok(0)     => info!("SIGMA updater: no new rules fetched"),
                Ok(count) => {
                    info!("SIGMA updater: {} new rules saved — reloading engine", count);
                    reload_engine(&rules_dir, &redis_url, &engine, &ch).await;
                }
                Err(e) => warn!("SIGMA updater: fetch failed — {}", e),
            }
            tokio::time::sleep(Duration::from_secs(7 * 24 * 3_600)).await;
        }
    });
}

/// Called by the admin API endpoint to trigger an immediate sync.
/// Returns the number of newly-saved rules.
pub async fn sync_now(
    rules_dir: &str,
    redis_url: &str,
    engine:    &Arc<RwLock<DetectionEngine>>,
    ch:        &Arc<crate::storage::ClickhouseStorage>,
) -> anyhow::Result<usize> {
    let count = fetch_all_rules(rules_dir, ch).await?;
    if count > 0 {
        reload_engine(rules_dir, redis_url, engine, ch).await;
    }
    Ok(count)
}

// ── Internal helpers ──────────────────────────────────────────────────────

/// Fetch both network and Linux endpoint rules from SigmaHQ, save to disk + ClickHouse.
async fn fetch_all_rules(
    rules_dir: &str,
    ch: &Arc<crate::storage::ClickhouseStorage>,
) -> anyhow::Result<usize> {
    let client = reqwest::Client::builder()
        .user_agent("NDR-Engine/1.0 (SigmaHQ community rules sync)")
        .timeout(Duration::from_secs(30))
        .build()?;

    std::fs::create_dir_all(rules_dir)?;

    let mut all_urls: Vec<(String, String)> = Vec::new();

    for (category, api_url) in &[
        ("network", GITHUB_NETWORK_API),
        ("linux",   GITHUB_LINUX_API),
    ] {
        match collect_yaml_urls(&client, api_url).await {
            Ok(urls) => {
                info!("SIGMA updater: {} {} rules found", urls.len(), category);
                for (name, url) in urls {
                    all_urls.push((format!("{}_{}", category, name), url));
                }
            }
            Err(e) => warn!("SIGMA updater: failed fetching {} rules — {}", category, e),
        }
    }

    if all_urls.is_empty() {
        return Err(anyhow::anyhow!(
            "GitHub API returned no items — possible rate-limit or network issue"
        ));
    }

    // Rules permanently excluded from community sync — see GLOBAL_RULE_BLOCKLIST above.
    let sync_blocklist = GLOBAL_RULE_BLOCKLIST;

    // Fetch existing community rule IDs so we never overwrite a manually disabled rule
    let existing_ids = ch.get_community_rule_ids().await.unwrap_or_default();

    let mut saved = 0usize;
    for (filename, url) in &all_urls {
        let content = match client.get(url).send().await {
            Ok(r) => match r.text().await { Ok(t) => t, Err(_) => continue },
            Err(_) => continue,
        };

        let rule = match parse_rule_content(&content) {
            Ok(r)  => r,
            Err(e) => { warn!("SIGMA updater: skipping {} — {}", filename, e); continue; }
        };

        // Permanently blocked rules — never import even after a DB wipe
        if sync_blocklist.contains(&rule.id.as_str()) {
            continue;
        }

        // Skip rules already in DB — preserves enabled/disabled state set by admin
        if existing_ids.contains(&rule.id) {
            continue;
        }

        // Save YAML to disk (cache/backup)
        let dest = format!("{}/community_{}", rules_dir, filename);
        let _ = std::fs::write(&dest, &content);

        // Save into ClickHouse as a community rule (tenant_id='*', source='community')
        match ch.save_community_rule(&rule.id, &rule.title, &content).await {
            Ok(_)  => { saved += 1; }
            Err(e) => warn!("SIGMA updater: CH insert failed for {} — {}", filename, e),
        }
    }

    Ok(saved)
}

/// Walk the top-level directory listing. For each subdirectory found, fetch
/// its contents too. Returns (filename, download_url) pairs for all YAML files.
async fn collect_yaml_urls(
    client: &reqwest::Client,
    api_url: &str,
) -> anyhow::Result<Vec<(String, String)>> {
    let resp = client.get(api_url)
        .header("Accept", "application/vnd.github.v3+json")
        .send().await?;

    if !resp.status().is_success() {
        return Err(anyhow::anyhow!("GitHub API returned {}", resp.status()));
    }

    let entries: Vec<serde_json::Value> = resp.json().await?;
    let mut results = Vec::new();

    for entry in &entries {
        let typ  = entry["type"].as_str().unwrap_or("");
        let name = entry["name"].as_str().unwrap_or("");

        if typ == "file" && (name.ends_with(".yml") || name.ends_with(".yaml")) {
            if let Some(url) = entry["download_url"].as_str() {
                if !url.is_empty() {
                    results.push((name.to_string(), url.to_string()));
                }
            }
        } else if typ == "dir" {
            // One level of subdirectories (dns/, firewall/, etc.)
            if let Some(subdir_url) = entry["url"].as_str() {
                let sub_resp = client.get(subdir_url)
                    .header("Accept", "application/vnd.github.v3+json")
                    .send().await;
                if let Ok(r) = sub_resp {
                    if let Ok(sub_entries) = r.json::<Vec<serde_json::Value>>().await {
                        for sub in &sub_entries {
                            let sname = sub["name"].as_str().unwrap_or("");
                            if sname.ends_with(".yml") || sname.ends_with(".yaml") {
                                if let Some(url) = sub["download_url"].as_str() {
                                    if !url.is_empty() {
                                        // Prefix with subdir name to avoid filename collisions
                                        let prefixed = format!("{}_{}", name, sname);
                                        results.push((prefixed, url.to_string()));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(results)
}

async fn reload_engine(
    rules_dir: &str,
    redis_url: &str,
    engine: &Arc<RwLock<DetectionEngine>>,
    ch:     &Arc<crate::storage::ClickhouseStorage>,
) {
    let (new_rules, overrides) = crate::api::load_rules_from_clickhouse(ch, rules_dir).await;
    let count                  = new_rules.len();
    engine.write().await.set_rules(new_rules, overrides);
    info!("SIGMA updater: engine reloaded with {} rules", count);

    // Notify other engine instances via Redis pub/sub
    if let Ok(client) = redis::Client::open(redis_url) {
        if let Ok(mut conn) = client.get_multiplexed_async_connection().await {
            let _: Result<(), _> = redis::cmd("PUBLISH")
                .arg("system:reload_rules")
                .arg("sigma_updater")
                .query_async(&mut conn)
                .await;
        }
    }
}
