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

        for line in text.lines() {
            let line = line.trim();
            // Lines starting with '#' are comments (date header, column names)
            if line.starts_with('#') || line.is_empty() { continue; }

            // CSV format: ip_address,port,date_added,last_online,malware
            if let Some(ip_str) = line.split(',').next() {
                if let Ok(ip) = IpAddr::from_str(ip_str.trim()) {
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
