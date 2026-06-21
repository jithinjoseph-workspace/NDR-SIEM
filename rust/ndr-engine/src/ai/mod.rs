//! ARIA — AI SOC Assistant
//! Handles OpenAI Chat Completions API calls with live NDR context.

use serde_json::{json, Value};

/// Build the system prompt with live NDR context
/// injected so Claude knows current threat state.
pub fn build_system_prompt(
    username: &str,
    tenant_id: &str,
    critical_count: u64,
    high_count: u64,
    bundle_count: u64,
    recent_alerts: &[Value],
) -> String {
    let alerts_json = serde_json::to_string(
        recent_alerts
    ).unwrap_or_default();

    format!(r#"You are ARIA (Autonomous Response &
Intelligence Assistant), a SOC assistant built
into the NDR (Network Detection & Response)
platform.

You are talking to analyst: {username}
Tenant: {tenant_id}

LIVE SYSTEM STATUS RIGHT NOW:
- Critical alerts (last 24h): {critical_count}
- High alerts (last 24h): {high_count}
- Evidence bundles auto-captured: {bundle_count}
- Recent alerts: {alerts_json}

YOUR PERSONALITY:
- Professional but friendly and approachable
- Direct and concise — analysts are busy
- Proactive — always suggest next steps
- Use security terminology naturally
- Explain alerts in BOTH plain English AND
  technical terms
- Show genuine concern when threats are real

YOUR CAPABILITIES (mention when relevant):
- Show alert details and evidence bundles
- Explain what a community_id or IP means
- Navigate user to evidence, alerts, timeline
- Trigger evidence download
- Explain attack narratives from Zeek/Suricata
- Check if an IP is in threat intel
- Show related alerts and lateral movement
- Explain conn_state codes (OTH, SF, REJ etc)

NDR PLATFORM CONTEXT:
- Alerts come from Zeek + Suricata via Kafka
- Community ID links Zeek conn + Suricata alert
- Evidence bundles have 15 files: PCAP, Zeek
  conn, DNS queries, SSL cert, Suricata alerts,
  attack narrative (SHA256 verified)
- HIGH/CRITICAL alerts auto-capture evidence
- Chain of custody logged for all evidence

RESPONSE FORMAT:
- Keep under 120 words unless explaining attack
- Use plain text, no markdown formatting
- End with a suggested action when relevant
- Reference previous messages when relevant
- When discussing an IP or CID, give both
  technical detail AND plain English meaning

EMOTION HINTS (for UI — include these tags
at the very END of your response when relevant,
the UI will strip them):
[EMO:alert] — when reporting new threats
[EMO:cheer] — when threat resolved
[EMO:think] — when analyzing/processing
[EMO:sad]   — when worried about patterns
[EMO:wave]  — when greeting
[EMO:idle]  — default calm state
"#)
}

/// Parse emotion hint from Claude response
pub fn extract_emotion(text: &str) 
    -> (String, String) 
{
    // Returns (clean_text, emotion)
    let emotions = [
        "[EMO:alert]", "[EMO:cheer]",
        "[EMO:think]", "[EMO:sad]",
        "[EMO:wave]",  "[EMO:idle]",
    ];
    for tag in &emotions {
        if text.contains(tag) {
            let clean = text.replace(tag, "")
                .trim().to_string();
            let emo = tag
                .trim_start_matches("[EMO:")
                .trim_end_matches(']')
                .to_string();
            return (clean, emo);
        }
    }
    (text.to_string(), "idle".to_string())
}

/// Call Claude API and return (reply, emotion)
#[allow(dead_code)]
pub async fn call_claude(
    api_key: &str,
    system_prompt: &str,
    history: &[Value],
    user_message: &str,
) -> anyhow::Result<(String, String)> {
    if api_key.is_empty() {
        return Ok((
            "ANTHROPIC_API_KEY not set in .env — \
             please add it to enable AI responses."
                .to_string(),
            "sad".to_string(),
        ));
    }

    let mut messages: Vec<Value> = history
        .iter()
        .filter(|m| {
            m["role"].as_str()
                .map(|r| r == "user" 
                      || r == "assistant")
                .unwrap_or(false)
        })
        .cloned()
        .collect();

    messages.push(json!({
        "role": "user",
        "content": user_message
    }));

    // Keep last 20 messages max
    if messages.len() > 20 {
        let len = messages.len();
        messages = messages[len - 20..].to_vec();
    }

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let resp = http
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", api_key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .json(&json!({
            "model": "claude-sonnet-4-6",
            "max_tokens": 300,
            "system": system_prompt,
            "messages": messages
        }))
        .send()
        .await?;

    let data = resp.json::<Value>().await?;

    let raw = data["content"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|c| c["text"].as_str())
        .unwrap_or(
            "I'm having trouble connecting. \
             Check ANTHROPIC_API_KEY in .env."
        )
        .to_string();

    Ok(extract_emotion(&raw))
}

/// Call OpenAI Chat Completions API and return (reply, emotion)
pub async fn call_openai(
    api_key: &str,
    system_prompt: &str,
    history: &[Value],
    user_message: &str,
) -> anyhow::Result<(String, String)> {
    if api_key.is_empty() {
        return Ok((
            "OPENAI_API_KEY not set in .env — \
             please add it to enable AI responses."
                .to_string(),
            "sad".to_string(),
        ));
    }

    // Build messages: system first, then history, then new user turn
    let mut messages: Vec<Value> = vec![
        json!({ "role": "system", "content": system_prompt })
    ];

    for m in history {
        let role = m["role"].as_str().unwrap_or("");
        if role == "user" || role == "assistant" {
            messages.push(m.clone());
        }
    }

    messages.push(json!({
        "role": "user",
        "content": user_message
    }));

    // Keep system + last 20 conversation turns
    if messages.len() > 21 {
        let system_msg = messages.remove(0);
        let keep = messages.split_off(messages.len() - 20);
        messages = std::iter::once(system_msg)
            .chain(keep)
            .collect();
    }

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let resp = http
        .post("https://api.openai.com/v1/chat/completions")
        .header("Authorization", format!("Bearer {api_key}"))
        .header("Content-Type", "application/json")
        .json(&json!({
            "model": "gpt-4o-mini",
            "max_tokens": 350,
            "messages": messages
        }))
        .send()
        .await?;

    let data = resp.json::<Value>().await?;

    let raw = data["choices"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|c| c["message"]["content"].as_str())
        .unwrap_or(
            "I'm having trouble connecting. \
             Check OPENAI_API_KEY in .env."
        )
        .to_string();

    Ok(extract_emotion(&raw))
}