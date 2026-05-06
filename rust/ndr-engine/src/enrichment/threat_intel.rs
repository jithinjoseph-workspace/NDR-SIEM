use dashmap::DashSet;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{info, warn};

#[derive(Clone)]
pub struct ThreatIntel {
    pub malicious_ips:     Arc<DashSet<IpAddr>>,
    pub malicious_hashes:  Arc<DashSet<String>>,
    pub malicious_domains: Arc<DashSet<String>>,
    pub malicious_urls:    Arc<DashSet<String>>,
}

impl ThreatIntel {
    pub fn new() -> Self {
        Self {
            malicious_ips:     Arc::new(DashSet::new()),
            malicious_hashes:  Arc::new(DashSet::new()),
            malicious_domains: Arc::new(DashSet::new()),
            malicious_urls:    Arc::new(DashSet::new()),
        }
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
        tokio::join!(
            self.refresh_feodo(),
            self.refresh_malware_bazaar(),
            self.refresh_urlhaus(),
        );
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

    self.malicious_domains.clear();
    self.malicious_urls.clear();
    let mut loaded_domains = 0usize;
    let mut loaded_ips = 0usize;

    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() { continue; }

        // Store full URL
        self.malicious_urls.insert(line.to_lowercase());

        // Extract host (could be IP or domain)
        if let Some(host) = extract_host(line) {
            // Check if host is an IP address
            if let Ok(ip) = IpAddr::from_str(&host) {
                self.malicious_ips.insert(ip);
                loaded_ips += 1;
            } else {
                // It's a domain
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