// NDR Engine — Firewall API Integration for Active Blocking
// Supports: pfSense (fauxapi/REST), Fortinet FortiGate, Palo Alto PAN-OS, OPNsense, Generic REST
// Each firewall returns a rule_id that is stored in ndr.active_blocks for later revocation.

use reqwest::Client;
use serde_json::{json, Value};
use std::time::Duration;
use tracing::warn;

pub struct FirewallResult {
    pub success:       bool,
    pub rule_id:       String,
    pub firewall_type: String,
    pub message:       String,
}

impl FirewallResult {
    fn ok(fw: &str, rule_id: impl Into<String>, msg: impl Into<String>) -> Self {
        Self { success: true, rule_id: rule_id.into(), firewall_type: fw.to_string(), message: msg.into() }
    }
    fn err(fw: &str, msg: impl Into<String>) -> Self {
        Self { success: false, rule_id: String::new(), firewall_type: fw.to_string(), message: msg.into() }
    }
}

// ── Public entry points ────────────────────────────────────────────────────

pub async fn push_block(
    fw_type: &str,
    config:  &Value,
    src_ip:  &str,
    duration_hours: u64,
) -> FirewallResult {
    let host    = config["host"].as_str().unwrap_or("");
    let api_key = config["api_key"].as_str().unwrap_or("");

    match fw_type {
        "pfsense"  => pfsense_block(host, api_key, src_ip, duration_hours).await,
        "fortinet" => fortinet_block(host, api_key, config, src_ip).await,
        "panos"    => panos_block(host, api_key, src_ip).await,
        "opnsense" => opnsense_block(host, api_key, config, src_ip).await,
        "rest"     => generic_rest_block(host, api_key, src_ip, duration_hours).await,
        _          => FirewallResult::err(fw_type, "unsupported firewall type"),
    }
}

pub async fn revoke_block(
    fw_type: &str,
    config:  &Value,
    src_ip:  &str,
    rule_id: &str,
) -> bool {
    let host    = config["host"].as_str().unwrap_or("");
    let api_key = config["api_key"].as_str().unwrap_or("");

    match fw_type {
        "pfsense"  => pfsense_revoke(host, api_key, rule_id).await,
        "fortinet" => fortinet_revoke(host, api_key, config, src_ip).await,
        "panos"    => panos_revoke(host, api_key, src_ip).await,
        "opnsense" => opnsense_revoke(host, api_key, config, src_ip).await,
        "rest"     => generic_rest_revoke(host, api_key, src_ip, rule_id).await,
        _          => false,
    }
}

// ── pfSense (REST API v2) ──────────────────────────────────────────────────
// Adds src_ip to the NDR_BLOCK alias. API key goes in X-API-Key header.

async fn pfsense_block(host: &str, api_key: &str, src_ip: &str, _duration_hours: u64) -> FirewallResult {
    let fw = "pfsense";
    let client = insecure_client();

    // Ensure NDR_BLOCK alias exists (idempotent)
    let alias_url = format!("https://{}/api/v2/firewall/alias", host);
    let _ = client
        .post(&alias_url)
        .header("X-API-Key", api_key)
        .json(&json!({"name":"NDR_BLOCK","type":"host","descr":"NDR auto-block","address":[]}))
        .timeout(Duration::from_secs(8))
        .send().await;

    // Add IP to alias
    let entry_url = format!("https://{}/api/v2/firewall/alias/entry", host);
    match client
        .post(&entry_url)
        .header("X-API-Key", api_key)
        .json(&json!({"name":"NDR_BLOCK","address":src_ip}))
        .timeout(Duration::from_secs(8))
        .send().await
    {
        Ok(r) if r.status().is_success() => {
            // Apply changes
            let _ = client.post(format!("https://{}/api/v2/firewall/apply", host))
                .header("X-API-Key", api_key).timeout(Duration::from_secs(5)).send().await;
            FirewallResult::ok(fw, format!("pfsense:NDR_BLOCK:{}", src_ip),
                format!("IP {} added to NDR_BLOCK alias on {}", src_ip, host))
        }
        Ok(r) => {
            warn!("[FIREWALL] pfSense alias entry failed: {}", r.status());
            FirewallResult::err(fw, format!("pfSense error: {}", r.status()))
        }
        Err(e) => FirewallResult::err(fw, format!("pfSense unreachable: {}", e)),
    }
}

async fn pfsense_revoke(host: &str, api_key: &str, rule_id: &str) -> bool {
    // rule_id format: "pfsense:NDR_BLOCK:<ip>"
    let parts: Vec<&str> = rule_id.split(':').collect();
    let ip = parts.get(2).copied().unwrap_or("");
    if ip.is_empty() { return false; }

    let client = insecure_client();
    let url    = format!("https://{}/api/v2/firewall/alias/entry", host);
    match client
        .delete(&url)
        .header("X-API-Key", api_key)
        .json(&json!({"name":"NDR_BLOCK","address":ip}))
        .timeout(Duration::from_secs(8))
        .send().await
    {
        Ok(r) if r.status().is_success() => {
            let _ = client.post(format!("https://{}/api/v2/firewall/apply", host))
                .header("X-API-Key", api_key).timeout(Duration::from_secs(5)).send().await;
            true
        }
        _ => false,
    }
}

// ── Fortinet FortiGate (REST API) ─────────────────────────────────────────
// Creates a named address object, adds it to NDR_BLOCK group, policy blocks group.

async fn fortinet_block(host: &str, api_key: &str, config: &Value, src_ip: &str) -> FirewallResult {
    let fw   = "fortinet";
    let vdom = config["vdom"].as_str().unwrap_or("root");
    let name = format!("NDR_BLOCK_{}", src_ip.replace('.', "_").replace(':', "_"));
    let client = insecure_client();

    let url = format!("https://{}/api/v2/cmdb/firewall/address?vdom={}", host, vdom);
    let body = json!({
        "name": name,
        "type": "ipmask",
        "subnet": format!("{}/32", src_ip),
        "comment": "NDR auto-block"
    });

    match client.post(&url)
        .header("Authorization", format!("Bearer {}", api_key))
        .json(&body).timeout(Duration::from_secs(8)).send().await
    {
        Ok(r) if r.status().is_success() || r.status().as_u16() == 409 => {
            // Add to NDR_BLOCK group (idempotent)
            let grp_url = format!("https://{}/api/v2/cmdb/firewall/addrgrp/NDR_BLOCK?vdom={}&action=add", host, vdom);
            let _ = client.put(&grp_url)
                .header("Authorization", format!("Bearer {}", api_key))
                .json(&json!({"member":[{"name":&name}]}))
                .timeout(Duration::from_secs(8)).send().await;

            FirewallResult::ok(fw, &name, format!("FortiGate: {} added to NDR_BLOCK group on {}", src_ip, host))
        }
        Ok(r) => FirewallResult::err(fw, format!("FortiGate error: {}", r.status())),
        Err(e) => FirewallResult::err(fw, format!("FortiGate unreachable: {}", e)),
    }
}

async fn fortinet_revoke(host: &str, api_key: &str, config: &Value, src_ip: &str) -> bool {
    let vdom = config["vdom"].as_str().unwrap_or("root");
    let name = format!("NDR_BLOCK_{}", src_ip.replace('.', "_").replace(':', "_"));
    let client = insecure_client();

    let url = format!("https://{}/api/v2/cmdb/firewall/address/{}?vdom={}", host, name, vdom);
    client.delete(&url)
        .header("Authorization", format!("Bearer {}", api_key))
        .timeout(Duration::from_secs(8)).send().await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

// ── Palo Alto PAN-OS (XML API) ────────────────────────────────────────────
// Adds IP to a dynamic address group tag "NDR_BLOCK". API key in X-API-Key.

async fn panos_block(host: &str, api_key: &str, src_ip: &str) -> FirewallResult {
    let fw     = "panos";
    let client = insecure_client();
    let cmd    = format!(
        "<request><user-id><payload><register><entry ip=\"{}\"><tag><member>NDR_BLOCK</member></tag></entry></register></payload></user-id></request>",
        src_ip
    );
    let url = format!("https://{}/api/?type=op&cmd={}&key={}", host, urlencoding::encode(&cmd), api_key);

    match client.get(&url).timeout(Duration::from_secs(8)).send().await {
        Ok(r) if r.status().is_success() => {
            let body = r.text().await.unwrap_or_default();
            if body.contains("success") {
                FirewallResult::ok(fw, format!("panos:{}", src_ip),
                    format!("PAN-OS: {} tagged NDR_BLOCK on {}", src_ip, host))
            } else {
                FirewallResult::err(fw, format!("PAN-OS response: {}", &body[..body.len().min(120)]))
            }
        }
        Ok(r) => FirewallResult::err(fw, format!("PAN-OS error: {}", r.status())),
        Err(e) => FirewallResult::err(fw, format!("PAN-OS unreachable: {}", e)),
    }
}

async fn panos_revoke(host: &str, api_key: &str, src_ip: &str) -> bool {
    let client = insecure_client();
    let cmd = format!(
        "<request><user-id><payload><unregister><entry ip=\"{}\"><tag><member>NDR_BLOCK</member></tag></entry></unregister></payload></user-id></request>",
        src_ip
    );
    let url = format!("https://{}/api/?type=op&cmd={}&key={}", host, urlencoding::encode(&cmd), api_key);
    client.get(&url).timeout(Duration::from_secs(8)).send().await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

// ── OPNsense (REST API) ────────────────────────────────────────────────────
// Adds IP to a firewall alias. api_key = "api_key:api_secret" joined with colon.

async fn opnsense_block(host: &str, api_key: &str, config: &Value, src_ip: &str) -> FirewallResult {
    let fw    = "opnsense";
    let alias = config["alias"].as_str().unwrap_or("NDR_BLOCK");
    let (key, secret) = api_key.split_once(':').unwrap_or((api_key, ""));
    let client = insecure_client();

    let url  = format!("https://{}/api/firewall/alias/addHost/{}", host, alias);
    let body = json!({"address": src_ip});

    match client.post(&url)
        .basic_auth(key, Some(secret))
        .json(&body).timeout(Duration::from_secs(8)).send().await
    {
        Ok(r) if r.status().is_success() => {
            // Apply changes
            let _ = client.post(format!("https://{}/api/firewall/alias/reconfigure", host))
                .basic_auth(key, Some(secret)).timeout(Duration::from_secs(5)).send().await;
            FirewallResult::ok(fw, format!("opnsense:{}:{}", alias, src_ip),
                format!("OPNsense: {} added to alias {} on {}", src_ip, alias, host))
        }
        Ok(r) => FirewallResult::err(fw, format!("OPNsense error: {}", r.status())),
        Err(e) => FirewallResult::err(fw, format!("OPNsense unreachable: {}", e)),
    }
}

async fn opnsense_revoke(host: &str, api_key: &str, config: &Value, src_ip: &str) -> bool {
    let alias = config["alias"].as_str().unwrap_or("NDR_BLOCK");
    let (key, secret) = api_key.split_once(':').unwrap_or((api_key, ""));
    let client = insecure_client();

    let url = format!("https://{}/api/firewall/alias/delHost/{}", host, alias);
    let ok = client.post(&url)
        .basic_auth(key, Some(secret))
        .json(&json!({"address": src_ip}))
        .timeout(Duration::from_secs(8)).send().await
        .map(|r| r.status().is_success())
        .unwrap_or(false);

    if ok {
        let _ = client.post(format!("https://{}/api/firewall/alias/reconfigure", host))
            .basic_auth(key, Some(secret)).timeout(Duration::from_secs(5)).send().await;
    }
    ok
}

// ── Generic REST webhook ───────────────────────────────────────────────────
// POST {"action":"block","ip":"...","duration_hours":N} to host URL.

async fn generic_rest_block(host: &str, api_key: &str, src_ip: &str, duration_hours: u64) -> FirewallResult {
    let fw     = "rest";
    let client = Client::new();
    let body   = json!({"action":"block","ip":src_ip,"duration_hours":duration_hours});

    match client.post(host)
        .header("X-API-Key", api_key)
        .json(&body).timeout(Duration::from_secs(8)).send().await
    {
        Ok(r) if r.status().is_success() => {
            let resp = r.json::<Value>().await.unwrap_or_default();
            let rule_id = resp["rule_id"].as_str().unwrap_or(src_ip).to_string();
            FirewallResult::ok(fw, rule_id, format!("Generic REST: {} blocked", src_ip))
        }
        Ok(r) => FirewallResult::err(fw, format!("REST error: {}", r.status())),
        Err(e) => FirewallResult::err(fw, format!("REST unreachable: {}", e)),
    }
}

async fn generic_rest_revoke(host: &str, api_key: &str, src_ip: &str, rule_id: &str) -> bool {
    let client = Client::new();
    client.post(host)
        .header("X-API-Key", api_key)
        .json(&json!({"action":"unblock","ip":src_ip,"rule_id":rule_id}))
        .timeout(Duration::from_secs(8)).send().await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

// ── Helper ─────────────────────────────────────────────────────────────────

fn insecure_client() -> Client {
    Client::builder()
        .danger_accept_invalid_certs(true)  // firewalls often use self-signed certs
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_default()
}
