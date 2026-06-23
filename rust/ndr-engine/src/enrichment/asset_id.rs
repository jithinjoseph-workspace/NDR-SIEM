use dashmap::DashMap;
use std::fs;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

pub struct AssetIdentifier {
    oui_map: DashMap<String, String>,
}

impl AssetIdentifier {
    pub fn new() -> Self {
        let oui_map = DashMap::new();
        let oui_path = std::env::var("OUI_JSON").unwrap_or_else(|_| "data/oui_vendors.json".to_string());
        if let Ok(content) = fs::read_to_string(&oui_path) {
            if let Ok(json) = serde_json::from_str::<std::collections::HashMap<String, String>>(&content) {
                for (k, v) in json {
                    oui_map.insert(k.to_uppercase(), v);
                }
                info!("Loaded {} OUI prefixes from disk.", oui_map.len());
            } else {
                tracing::warn!("Failed to parse OUI JSON at {}", oui_path);
            }
        } else {
            tracing::warn!("OUI JSON file not found at {} — vendor lookup will be empty until first update.", oui_path);
        }
        Self { oui_map }
    }

    pub fn lookup_vendor(&self, mac: &str) -> String {
        let clean_mac = mac.replace('-', ":").to_uppercase();
        if clean_mac.len() >= 8 {
            let oui = &clean_mac[0..8];
            if let Some(vendor_ref) = self.oui_map.get(oui) {
                return vendor_ref.value().clone();
            }
        }
        "Unknown".to_string()
    }

    pub fn guess_device_type(&self, hostname: &str, vendor: &str, is_gateway: bool) -> String {
        let h = hostname.to_lowercase();
        let v = vendor.to_lowercase();

        if is_gateway { return "router".to_string(); }
        if h.contains("iphone") || (v.contains("apple") && h.contains("phone")) { return "phone".to_string(); }
        if h.contains("android") || h.contains("galaxy") || v.contains("samsung") { return "phone".to_string(); }
        if h.contains("macbook") || h.contains("imac") || h.contains("mac-") { return "laptop".to_string(); }
        if h.contains("lap") || h.contains("thinkpad") || h.contains("latitude") || h.contains("notebook") { return "laptop".to_string(); }
        if h.contains("pc") || h.contains("desktop") || h.contains("workstation") { return "desktop".to_string(); }
        if h.contains("print") || v.contains("hp") || v.contains("epson") || v.contains("brother") { return "printer".to_string(); }
        if h.contains("tv") || h.contains("cast") || h.contains("roku") || v.contains("roku") { return "tv".to_string(); }
        if h.contains("cam") || v.contains("ubiquiti") || v.contains("raspberry") || v.contains("espressif") || v.contains("sonoff") { return "iot".to_string(); }
        if h.contains("srv") || h.contains("server") { return "server".to_string(); }
        if h.contains("router") || h.contains("gateway") || h.contains("switch") || v.contains("cisco") || v.contains("tp-link") || v.contains("netgear") || v.contains("mikrotik") { return "router".to_string(); }

        "unknown".to_string()
    }

    /// Spawns a background task to update the OUI database monthly from the IEEE registry.
    pub fn spawn_auto_updater(self: Arc<Self>) {
        tokio::spawn(async move {
            let oui_path = std::env::var("OUI_JSON").unwrap_or_else(|_| "data/oui_vendors.json".to_string());

            // Wait 10s on boot before first fetch
            tokio::time::sleep(Duration::from_secs(10)).await;

            loop {
                info!("Fetching latest IEEE OUI Registry...");
                let client = reqwest::Client::builder()
                    .timeout(Duration::from_secs(30))
                    .build()
                    .unwrap_or_default();

                let mut success = false;
                if let Ok(resp) = client.get("http://standards-oui.ieee.org/oui/oui.csv").send().await {
                    if let Ok(text) = resp.text().await {
                        let mut reader = csv::ReaderBuilder::new().from_reader(text.as_bytes());
                        let mut new_map = std::collections::HashMap::new();

                        for result in reader.records() {
                            if let Ok(record) = result {
                                if record.len() >= 3 {
                                    let assignment = record[1].trim();
                                    let org = record[2].trim();
                                    if assignment.len() == 6 {
                                        let formatted = format!("{}:{}:{}", &assignment[0..2], &assignment[2..4], &assignment[4..6]);
                                        new_map.insert(formatted.to_uppercase(), org.to_string());
                                        self.oui_map.insert(formatted.to_uppercase(), org.to_string());
                                    }
                                }
                            }
                        }

                        if !new_map.is_empty() {
                            info!("Parsed {} OUI prefixes from IEEE.", new_map.len());
                            if let Ok(json_str) = serde_json::to_string_pretty(&new_map) {
                                // Ensure data dir exists
                                let _ = fs::create_dir_all(std::path::Path::new(&oui_path).parent().unwrap_or(std::path::Path::new(".")));
                                if fs::write(&oui_path, json_str).is_ok() {
                                    info!("OUI database updated at {}", oui_path);
                                    success = true;
                                }
                            }
                        }
                    }
                }

                let sleep_secs = if success {
                    30 * 24 * 3600 // 30 days
                } else {
                    tracing::warn!("Failed to fetch OUI registry. Will retry in 7 days.");
                    7 * 24 * 3600
                };
                tokio::time::sleep(Duration::from_secs(sleep_secs)).await;
            }
        });
    }
}
