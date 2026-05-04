// NDR Engine — Threat Intelligence Feed
// Source: abuse.ch Feodo Tracker (free, no license restrictions on data)
// URL: https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.csv
// License: Apache-2.0

use dashmap::DashSet;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{info, warn};

/// In-memory threat intel store backed by a DashSet for lock-free lookups.
pub struct ThreatIntel {
    malicious_ips: Arc<DashSet<IpAddr>>,
}

impl ThreatIntel {
    pub fn new() -> Self {
        Self {
            malicious_ips: Arc::new(DashSet::new()),
        }
    }

    /// Fetch and reload the Feodo Tracker IP blocklist.
    /// Called at startup and every 60 minutes by the background refresh task.
pub async fn refresh(&self) {
    let url = "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.csv";

    let text = match reqwest::get(url).await {
        Ok(r)  => match r.text().await {
            Ok(t) => t,
            Err(e) => { warn!("Threat intel body error: {}", e); return; }
        },
        Err(e) => { warn!("Threat intel fetch error: {}", e); return; }
    };

    self.malicious_ips.clear();
    let mut loaded = 0usize;
    let mut header_parsed = false;
    let mut ip_column_index = 0usize;

    for line in text.lines() {
        let line = line.trim();

        // Skip comments
        if line.starts_with('#') || line.is_empty() { continue; }

        // Parse header to find IP column
        if !header_parsed {
            let columns: Vec<&str> = line.split(',').collect();
            for (i, col) in columns.iter().enumerate() {
                let col_clean = col.trim_matches('"').to_lowercase();
                if col_clean == "dst_ip" || col_clean == "ip_address" {
                    ip_column_index = i;
                    break;
                }
            }
            header_parsed = true;
            continue;
        }

        // Parse data rows
        let columns: Vec<&str> = line.split(',').collect();
        if let Some(ip_str) = columns.get(ip_column_index) {
            let ip_clean = ip_str.trim_matches('"').trim();
            if let Ok(ip) = IpAddr::from_str(ip_clean) {
                self.malicious_ips.insert(ip);
                loaded += 1;
            }
        }
    }

    info!("Threat intel refreshed: {} malicious IPs loaded", loaded);
}
    /// Returns true if the IP is in the malicious set.
    pub fn is_malicious(&self, ip: &str) -> bool {
        IpAddr::from_str(ip)
            .ok()
            .map(|addr| self.malicious_ips.contains(&addr))
            .unwrap_or(false)
    }

    #[allow(dead_code)]
    pub fn count(&self) -> usize {
        self.malicious_ips.len()
    }
}
