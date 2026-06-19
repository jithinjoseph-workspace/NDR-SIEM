use dashmap::DashSet;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{info, warn};

#[derive(Clone)]
pub struct ThreatIntel {
    pub malicious_ips:     Arc<DashSet<IpAddr>>,
    pub malicious_hashes:  Arc<DashSet<String>>,
    pub malicious_domains: Arc<DashSet<String>>,
    pub malicious_urls:    Arc<DashSet<String>>,
    // Unix timestamp (seconds) of the last completed refresh
    pub last_refreshed_at: Arc<AtomicU64>,
}

impl ThreatIntel {
    pub fn new() -> Self {
        Self {
            malicious_ips:     Arc::new(DashSet::new()),
            malicious_hashes:  Arc::new(DashSet::new()),
            malicious_domains: Arc::new(DashSet::new()),
            malicious_urls:    Arc::new(DashSet::new()),
            last_refreshed_at: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn last_refresh_iso(&self) -> String {
        let ts = self.last_refreshed_at.load(Ordering::Relaxed);
        if ts == 0 { return "never".to_string(); }
        chrono::DateTime::from_timestamp(ts as i64, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M UTC").to_string())
            .unwrap_or_else(|| "unknown".to_string())
    }

    pub fn is_malicious_ip(&self, ip: &str) -> bool {
        if let Ok(addr) = IpAddr::from_str(ip) {
            self.malicious_ips.contains(&addr)
        } else { false }
    }

    pub fn is_malicious_hash(&self, hash: &str) -> bool {
        self.malicious_hashes.contains(
            &hash.to_lowercase()
        )
    }

    pub fn is_malicious_domain(&self, domain: &str) -> bool {
        let d = domain.to_lowercase();
        // Check exact match and parent domains
        if self.malicious_domains.contains(&d) {
            return true;
        }
        // Check if subdomain of malicious domain
        let parts: Vec<&str> = d.split('.').collect();
        for i in 1..parts.len().saturating_sub(1) {
            let parent = parts[i..].join(".");
            if self.malicious_domains.contains(&parent) {
                return true;
            }
        }
        false
    }

    pub fn ip_count(&self)     -> usize { self.malicious_ips.len() }
    pub fn hash_count(&self)   -> usize { self.malicious_hashes.len() }
    pub fn domain_count(&self) -> usize { self.malicious_domains.len() }

    pub fn add_ioc(&self, ioc_type: &str, value: &str) {
        match ioc_type {
            "ip" => {
                if let Ok(ip) = IpAddr::from_str(value) {
                    self.malicious_ips.insert(ip);
                }
            }
            "hash" | "md5" | "sha256" | "sha1" => {
                self.malicious_hashes.insert(value.to_lowercase());
            }
            "domain" | "hostname" => {
                self.malicious_domains.insert(value.to_lowercase());
            }
            "url" => {
    self.malicious_urls.insert(value.to_lowercase());
    // Also extract host from URL
    if let Some(host) = extract_host(value) {
        if let Ok(ip) = IpAddr::from_str(&host) {
            self.malicious_ips.insert(ip);
        } else {
            self.malicious_domains.insert(host);
        }
    }
}
            _ => {}
        }
    }

    pub async fn refresh(&self) {
        self.refresh_feodo().await;
        self.refresh_urlhaus().await;
        self.refresh_malware_bazaar().await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_refreshed_at.store(now, Ordering::Relaxed);
        info!("Threat intel refresh complete — {} IPs, {} hashes, {} domains",
            self.ip_count(), self.hash_count(), self.domain_count());
    }

    /// Refresh with per-feed toggle support from settings.
    pub async fn refresh_with_settings(
        &self,
        feodo_enabled: bool,
        malwarebazaar_enabled: bool,
        urlhaus_enabled: bool,
        custom_feed_url: &str,
    ) {
        if feodo_enabled {
            self.refresh_feodo().await;
        } else {
            info!("Feodo Tracker feed disabled — skipping");
        }
        if urlhaus_enabled {
            self.refresh_urlhaus().await;
        } else {
            info!("URLhaus feed disabled — skipping");
        }
        if malwarebazaar_enabled {
            self.refresh_malware_bazaar().await;
        } else {
            info!("MalwareBazaar feed disabled — skipping");
        }
        if !custom_feed_url.is_empty() {
            self.refresh_custom_feed(custom_feed_url).await;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_refreshed_at.store(now, Ordering::Relaxed);
    }

    /// Refresh from a custom IOC feed (plain text, one IOC per line).
    /// Auto-detects IOC type: IP, hash (SHA256/MD5/SHA1), or domain.
    async fn refresh_custom_feed(&self, url: &str) {
        let text = match reqwest::get(url).await {
            Ok(r) => match r.text().await {
                Ok(t) => t,
                Err(e) => { warn!("Custom feed body error: {}", e); return; }
            },
            Err(e) => { warn!("Custom feed fetch error: {}", e); return; }
        };

        let mut ips = 0usize;
        let mut hashes = 0usize;
        let mut domains = 0usize;

        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() { continue; }

            // Detect IOC type by format
            if let Ok(addr) = std::net::IpAddr::from_str(line) {
                self.malicious_ips.insert(addr);
                ips += 1;
            } else if (line.len() == 32 || line.len() == 40 || line.len() == 64)
                && line.chars().all(|c| c.is_ascii_hexdigit())
            {
                self.malicious_hashes.insert(line.to_lowercase());
                hashes += 1;
            } else if line.contains('.') && !line.contains('/') {
                self.malicious_domains.insert(line.to_lowercase());
                domains += 1;
            }
        }
        info!("Custom feed: {} IPs, {} hashes, {} domains loaded from {}", ips, hashes, domains, url);
    }

    // ── Feodo Tracker — IPs ───────────────────
    async fn refresh_feodo(&self) {
        let url = "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.csv";
        let text = match reqwest::get(url).await {
            Ok(r) => match r.text().await {
                Ok(t) => t,
                Err(e) => { warn!("Feodo body error: {}", e); return; }
            },
            Err(e) => { warn!("Feodo fetch error: {}", e); return; }
        };

        self.malicious_ips.clear();
        let mut loaded = 0usize;
        let mut header_parsed = false;
        let mut ip_col = 0usize;

        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() { continue; }

            if !header_parsed {
                let cols: Vec<&str> = line.split(',').collect();
                for (i, col) in cols.iter().enumerate() {
                    let c = col.trim_matches('"').to_lowercase();
                    if c == "dst_ip" || c == "ip_address" {
                        ip_col = i;
                        break;
                    }
                }
                header_parsed = true;
                continue;
            }

            let cols: Vec<&str> = line.split(',').collect();
            if let Some(ip_str) = cols.get(ip_col) {
                let ip = ip_str.trim_matches('"').trim();
                if let Ok(addr) = IpAddr::from_str(ip) {
                    self.malicious_ips.insert(addr);
                    loaded += 1;
                }
            }
        }
        info!("Feodo: {} malicious IPs loaded", loaded);
    }

    // ── MalwareBazaar — File Hashes ───────────
    async fn refresh_malware_bazaar(&self) {
        let url = "https://bazaar.abuse.ch/export/txt/sha256/recent/";
        let text = match reqwest::get(url).await {
            Ok(r) => match r.text().await {
                Ok(t) => t,
                Err(e) => { warn!("MalwareBazaar body: {}", e); return; }
            },
            Err(e) => { warn!("MalwareBazaar fetch: {}", e); return; }
        };

        self.malicious_hashes.clear();
        let mut loaded = 0usize;

        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() { continue; }
            // SHA256 hash — 64 hex chars
            if line.len() == 64 && line.chars().all(|c| c.is_ascii_hexdigit()) {
                self.malicious_hashes.insert(line.to_lowercase());
                loaded += 1;
            }
        }
        info!("MalwareBazaar: {} malicious hashes loaded", loaded);
    }

    // ── URLhaus — Domains/URLs ─────────────────
async fn refresh_urlhaus(&self) {
    let url = "https://urlhaus.abuse.ch/downloads/text_online/";
    let text = match reqwest::get(url).await {
        Ok(r) => match r.text().await {
            Ok(t) => t,
            Err(e) => { warn!("URLhaus body: {}", e); return; }
        },
        Err(e) => { warn!("URLhaus fetch: {}", e); return; }
    };

    // Only clear domains and urls — NOT ips (Feodo already loaded them)
    self.malicious_domains.clear();
    self.malicious_urls.clear();
    let mut loaded_domains = 0usize;
    let mut loaded_ips = 0usize;

    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() { continue; }

        self.malicious_urls.insert(line.to_lowercase());

        if let Some(host) = extract_host(line) {
            if let Ok(ip) = IpAddr::from_str(&host) {
                // ADD to existing IPs — don't clear!
                self.malicious_ips.insert(ip);
                loaded_ips += 1;
            } else {
                self.malicious_domains.insert(host);
                loaded_domains += 1;
            }
        }
    }
    info!("URLhaus: {} malicious domains + {} IPs loaded",
        loaded_domains, loaded_ips);
}
}

fn extract_host(url: &str) -> Option<String> {
    let url = url.trim_start_matches("http://")
        .trim_start_matches("https://");
    let host = url.split('/').next()?
        .split(':').next()?  // remove port
        .to_lowercase()
        .trim()
        .to_string();
    if !host.is_empty() {
        Some(host)
    } else {
        None
    }
}