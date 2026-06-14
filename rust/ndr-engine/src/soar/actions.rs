use crate::api::AppState;
use crate::correlator::CorrelationHit;
use crate::scoring::RiskResult;
use crate::enrichment::EnrichmentData;
use crate::soar::{SoarNativePlaybook, SoarPlaybookRun};
use serde_json::{json, Value};
use std::time::Duration;
use tracing::info;
use uuid::Uuid;
use chrono::Utc;
use lettre::{Message, SmtpTransport, Transport};
use lettre::transport::smtp::authentication::Credentials;
use reqwest::Client;

pub async fn execute_action(
    state: &AppState,
    pb: &SoarNativePlaybook,
    hit: &CorrelationHit,
    risk: &RiskResult,
    enrichment: &EnrichmentData,
) {
    let config: Value = serde_json::from_str(&pb.action_config).unwrap_or(json!({}));
    
    let (src, dst) = match hit.source.as_str() {
        "zeek" => (
            hit.zeek.source_ip.as_deref().unwrap_or("-"),
            hit.zeek.dest_ip.as_deref().unwrap_or("-"),
        ),
        "suricata" => (
            hit.suricata.source_ip.as_deref().unwrap_or("-"),
            hit.suricata.dest_ip.as_deref().unwrap_or("-"),
        ),
        _ => (
            hit.zeek.source_ip.as_deref().or(hit.suricata.source_ip.as_deref()).unwrap_or("-"),
            hit.zeek.dest_ip.as_deref().or(hit.suricata.dest_ip.as_deref()).unwrap_or("-"),
        ),
    };

    let mut status = "failed".to_string();
    let mut detail = String::new();

    match pb.action_type.as_str() {
        "slack" | "discord" => {
            if let Some(url) = config["webhook_url"].as_str() {
                let msg = json!({
                    "text": format!(
                        "🚨 *NDR Native Alert* | *{}*\n\
                        Source: `{}` → Dest: `{}`\n\
                        Score: *{}/100* | Threat Intel: {}\n\
                        Tags: {}",
                        risk.severity.as_str(),
                        src, dst,
                        risk.score as u32,
                        if enrichment.is_malicious { "⚠️ YES" } else { "No" },
                        risk.tags.join(", ")
                    )
                });
                match Client::new().post(url).json(&msg).timeout(Duration::from_secs(5)).send().await {
                    Ok(r) if r.status().is_success() => {
                        status = "success".to_string();
                        detail = "Slack/Discord webhook sent".to_string();
                    }
                    Ok(r) => detail = format!("HTTP error: {}", r.status()),
                    Err(e) => detail = format!("Request failed: {}", e),
                }
            } else {
                detail = "Missing webhook_url".to_string();
            }
        }
        "teams" => {
            if let Some(url) = config["webhook_url"].as_str() {
                let msg = json!({
                    "@type": "MessageCard",
                    "@context": "http://schema.org/extensions",
                    "summary": "NDR Native Alert",
                    "themeColor": "FF0000",
                    "title": format!("🚨 NDR Alert: {}", risk.severity.as_str()),
                    "sections": [{
                        "facts": [
                            {"name": "Source", "value": src},
                            {"name": "Destination", "value": dst},
                            {"name": "Score", "value": format!("{}/100", risk.score as u32)},
                            {"name": "Tags", "value": risk.tags.join(", ")}
                        ]
                    }]
                });
                match Client::new().post(url).json(&msg).timeout(Duration::from_secs(5)).send().await {
                    Ok(r) if r.status().is_success() => {
                        status = "success".to_string();
                        detail = "Teams webhook sent".to_string();
                    }
                    Ok(r) => detail = format!("HTTP error: {}", r.status()),
                    Err(e) => detail = format!("Request failed: {}", e),
                }
            } else {
                detail = "Missing webhook_url".to_string();
            }
        }
        "webhook" => {
            if let Some(url) = config["webhook_url"].as_str() {
                let msg = json!({
                    "alert_type": "ndr_threat",
                    "src_ip": src,
                    "dst_ip": dst,
                    "score": risk.score,
                    "severity": risk.severity.as_str(),
                    "threat_intel": enrichment.is_malicious,
                    "tags": risk.tags,
                    "timestamp": Utc::now().to_rfc3339(),
                });
                match Client::new().post(url).json(&msg).timeout(Duration::from_secs(5)).send().await {
                    Ok(r) if r.status().is_success() => {
                        status = "success".to_string();
                        detail = "Webhook sent".to_string();
                    }
                    Ok(r) => detail = format!("HTTP error: {}", r.status()),
                    Err(e) => detail = format!("Request failed: {}", e),
                }
            } else {
                detail = "Missing webhook_url".to_string();
            }
        }
        "email" => {
            // Need integration details. For email, config might reference an integration id
            // or contain the email directly, and we look up smtp config.
            // Simplified: we will look up the SMTP integration to send this.
            let integrations = state.ch_storage.get_integrations_by_tenant(&pb.tenant_id).await.unwrap_or_default();
            let mut smtp_config = None;
            for i in integrations {
                if i["type"].as_str().unwrap_or("") == "smtp" && i["enabled"] == true {
                    smtp_config = Some(i["config"].clone());
                    break;
                }
            }

            if let Some(sc) = smtp_config {
                let to_addr = config["to_addr"].as_str()
                    .or(sc["to_addr"].as_str())
                    .unwrap_or("");
                let from_addr = sc["from_addr"].as_str().unwrap_or("ndr@localhost");
                let host = sc["smtp_host"].as_str().unwrap_or("localhost");
                let port = sc["smtp_port"].as_u64().unwrap_or(587) as u16;
                let user = sc["smtp_user"].as_str().unwrap_or("");
                let pass = sc["smtp_pass"].as_str().unwrap_or("");

                let email = Message::builder()
                    .from(from_addr.parse().unwrap())
                    .to(to_addr.parse().unwrap())
                    .subject(format!("NDR Alert: {}", risk.severity.as_str()))
                    .body(format!("Alert for {} -> {}. Score: {}", src, dst, risk.score))
                    .unwrap();

                let mut mailer_builder = SmtpTransport::builder_dangerous(host).port(port);
                if !user.is_empty() {
                    mailer_builder = mailer_builder.credentials(Credentials::new(user.to_string(), pass.to_string()));
                }
                
                let mailer = mailer_builder.build();
                match mailer.send(&email) {
                    Ok(_) => {
                        status = "success".to_string();
                        detail = "Email sent".to_string();
                    }
                    Err(e) => {
                        detail = format!("SMTP error: {}", e);
                    }
                }
            } else {
                detail = "No active SMTP integration found".to_string();
            }
        }
        "create_case" => {
            let case_id = Uuid::new_v4().to_string();
            let title = format!("Automated Case: {} -> {} ({})", src, dst, risk.severity.as_str());
            let description = format!("Playbook {} generated this case.", pb.name);
            
            // Note: In Phase 2 we are adding the ClickHouse method for insert_soar_case
            match state.ch_storage.insert_soar_case(
                &case_id,
                &title,
                &description,
                risk.severity.as_str(),
                "New",
                src,
                dst,
                &hit.community_id,
                &risk.tags,
                &pb.tenant_id,
            ).await {
                Ok(_) => {
                    status = "success".to_string();
                    detail = format!("Case {} created", case_id);
                }
                Err(e) => {
                    detail = format!("Failed to create case: {}", e);
                }
            }
        }
        _ => {
            detail = format!("Unknown action_type: {}", pb.action_type);
        }
    }

    info!("SOAR Action [{}] for Playbook {}: {} - {}", pb.action_type, pb.name, status, detail);

    // Log the run
    let run = SoarPlaybookRun {
        id: Uuid::new_v4().to_string(),
        playbook_id: pb.id.clone(),
        playbook_name: pb.name.clone(),
        hit_id: hit.community_id.clone(),
        status,
        detail,
        created_at: Utc::now().to_rfc3339(),
        tenant_id: pb.tenant_id.clone(),
    };

    let _ = state.ch_storage.insert_soar_playbook_run(&run).await;
}
