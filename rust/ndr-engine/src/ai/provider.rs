use tracing::{error, warn};

#[allow(dead_code)]
pub enum UseCase {
    ThreatPrediction,
    AriaChatResponse,
}

impl UseCase {
    pub fn tag(&self) -> &'static str {
        match self {
            UseCase::ThreatPrediction => "threat",
            UseCase::AriaChatResponse => "chat",
        }
    }
}

/// One row from ndr.ai_providers.
#[derive(clickhouse::Row, serde::Deserialize, Clone, Debug)]
pub struct AiProvider {
    pub name:          String,
    pub provider_type: String,
    pub api_key:       String,
    pub model:         String,
    pub base_url:      String,
    pub endpoint_path: String,
    pub msg_format:    String,
    pub priority:      u8,
}

// ─── Threat-module entry point ──────────────────────────────────────────────

/// Called by correlator / chain_matcher / predictor.
/// Loads providers from DB for this use case, tries in priority order,
/// then falls back to env vars (GROQ → OPENAI → ANTHROPIC).
pub async fn generate(
    storage: &crate::storage::ClickhouseStorage,
    use_case: UseCase,
    system: &str,
    prompt: &str,
) -> String {
    let providers = storage.get_ai_providers(use_case.tag()).await
        .unwrap_or_default();

    for p in &providers {
        if p.api_key.is_empty() { continue; }
        let result = call_provider_simple(p, system, prompt).await;
        if !result.is_empty() { return result; }
        warn!("AI provider '{}' returned empty, trying next", p.name);
    }

    env_fallback_simple(system, prompt).await
}

// ─── ARIA-chat entry point ──────────────────────────────────────────────────

/// Called by ARIA chat handler — passes full conversation history.
pub async fn generate_chat(
    storage: &crate::storage::ClickhouseStorage,
    system: &str,
    history: &[serde_json::Value],
    user_msg: &str,
) -> anyhow::Result<(String, String)> {
    let providers = storage.get_ai_providers("chat").await
        .unwrap_or_default();

    for p in &providers {
        if p.api_key.is_empty() { continue; }
        let result = call_provider_chat(p, system, history, user_msg).await;
        if let Ok((ref text, _)) = result {
            if !text.is_empty() { return result; }
        }
        warn!("Chat provider '{}' returned empty", p.name);
    }

    env_fallback_chat(system, history, user_msg).await
}

// ─── Provider dispatch ──────────────────────────────────────────────────────

pub async fn call_provider_simple(p: &AiProvider, system: &str, prompt: &str) -> String {
    if p.provider_type == "anthropic" {
        return call_anthropic_simple(&p.api_key, &p.model, system, prompt).await;
    }
    let (base, path, model) = resolve_openai_params(p);
    call_openai_compat(&p.api_key, &model, &format!("{base}{path}"), system, prompt).await
}

async fn call_provider_chat(
    p: &AiProvider,
    system: &str,
    history: &[serde_json::Value],
    user_msg: &str,
) -> anyhow::Result<(String, String)> {
    if p.provider_type == "anthropic" {
        return call_claude_chat(&p.api_key, &p.model, system, history, user_msg).await;
    }
    let (base, path, model) = resolve_openai_params(p);
    call_openai_chat(&p.api_key, &model, &format!("{base}{path}"), system, history, user_msg).await
}

fn resolve_openai_params(p: &AiProvider) -> (String, String, String) {
    let base = if p.base_url.is_empty() {
        "https://api.openai.com".to_string()
    } else {
        p.base_url.trim_end_matches('/').to_string()
    };
    let path = if p.endpoint_path.is_empty() {
        "/v1/chat/completions".to_string()
    } else {
        p.endpoint_path.clone()
    };
    let model = if p.model.is_empty() {
        "gpt-4o-mini".to_string()
    } else {
        p.model.clone()
    };
    (base, path, model)
}

// ─── HTTP call implementations ──────────────────────────────────────────────

/// OpenAI-compatible: simple system+prompt, returns plain text.
pub async fn call_openai_compat(key: &str, model: &str, endpoint: &str, system: &str, prompt: &str) -> String {
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .unwrap_or_default();

    let body = serde_json::json!({
        "model": model,
        "temperature": 0.1,
        "max_tokens": 1024,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user",   "content": prompt}
        ]
    });

    let resp = match http.post(endpoint).bearer_auth(key).json(&body).send().await {
        Ok(r)  => r,
        Err(e) => { error!("AI request to {} failed: {}", endpoint, e); return String::new(); }
    };

    let data: serde_json::Value = match resp.json().await {
        Ok(d)  => d,
        Err(e) => { error!("AI response parse failed: {}", e); return String::new(); }
    };

    if let Some(err) = data["error"]["message"].as_str() {
        error!("AI API error from {}: {}", endpoint, err);
        return String::new();
    }

    data["choices"][0]["message"]["content"]
        .as_str().unwrap_or("").trim().to_string()
}

/// OpenAI-compatible: with conversation history, returns (text, emotion).
pub async fn call_openai_chat(
    key: &str,
    model: &str,
    endpoint: &str,
    system: &str,
    history: &[serde_json::Value],
    user_msg: &str,
) -> anyhow::Result<(String, String)> {
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()?;

    let mut messages = vec![serde_json::json!({"role": "system", "content": system})];
    messages.extend_from_slice(history);
    messages.push(serde_json::json!({"role": "user", "content": user_msg}));

    let body = serde_json::json!({
        "model": model,
        "temperature": 0.7,
        "max_tokens": 1024,
        "messages": messages
    });

    let resp = http.post(endpoint).bearer_auth(key).json(&body).send().await?;
    let data: serde_json::Value = resp.json().await?;

    if let Some(err) = data["error"]["message"].as_str() {
        anyhow::bail!("API error: {}", err);
    }

    let text = data["choices"][0]["message"]["content"]
        .as_str().unwrap_or("").trim().to_string();

    let (clean, emotion) = crate::ai::extract_emotion(&text);
    Ok((clean, emotion))
}

/// Anthropic: simple system+prompt.
pub async fn call_anthropic_simple(key: &str, model: &str, system: &str, prompt: &str) -> String {
    let model = if model.is_empty() { "claude-sonnet-4-6" } else { model };
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .unwrap_or_default();

    let resp = match http.post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", key)
        .header("anthropic-version", "2023-06-01")
        .json(&serde_json::json!({
            "model": model,
            "max_tokens": 1024,
            "system": system,
            "messages": [{"role": "user", "content": prompt}]
        })).send().await
    {
        Ok(r)  => r,
        Err(e) => { error!("Anthropic request failed: {}", e); return String::new(); }
    };

    let data: serde_json::Value = match resp.json().await {
        Ok(d)  => d,
        Err(_) => return String::new(),
    };

    data["content"][0]["text"].as_str().unwrap_or("").trim().to_string()
}

/// Anthropic: with conversation history.
pub async fn call_claude_chat(
    key: &str,
    model: &str,
    system: &str,
    history: &[serde_json::Value],
    user_msg: &str,
) -> anyhow::Result<(String, String)> {
    let model = if model.is_empty() { "claude-sonnet-4-6" } else { model };
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()?;

    let mut messages: Vec<serde_json::Value> = history.to_vec();
    messages.push(serde_json::json!({"role": "user", "content": user_msg}));

    let resp = http.post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", key)
        .header("anthropic-version", "2023-06-01")
        .json(&serde_json::json!({
            "model": model,
            "max_tokens": 1024,
            "system": system,
            "messages": messages
        })).send().await?;

    let data: serde_json::Value = resp.json().await?;
    if let Some(err) = data["error"]["message"].as_str() {
        anyhow::bail!("Anthropic error: {}", err);
    }

    let text = data["content"][0]["text"].as_str().unwrap_or("").trim().to_string();
    let (clean, emotion) = crate::ai::extract_emotion(&text);
    Ok((clean, emotion))
}

// ─── Env-var fallbacks ──────────────────────────────────────────────────────

/// Fallback chain: GROQ_API_KEY → OPENAI_API_KEY → ANTHROPIC_API_KEY
async fn env_fallback_simple(system: &str, prompt: &str) -> String {
    if let Ok(key) = std::env::var("GROQ_API_KEY") {
        if !key.is_empty() {
            let model = std::env::var("GROQ_MODEL")
                .unwrap_or_else(|_| "llama-3.3-70b-versatile".to_string());
            let r = call_openai_compat(
                &key, &model,
                "https://api.groq.com/openai/v1/chat/completions",
                system, prompt,
            ).await;
            if !r.is_empty() { return r; }
        }
    }
    if let Ok(key) = std::env::var("OPENAI_API_KEY") {
        if !key.is_empty() {
            let r = call_openai_compat(
                &key, "gpt-4o-mini",
                "https://api.openai.com/v1/chat/completions",
                system, prompt,
            ).await;
            if !r.is_empty() { return r; }
        }
    }
    if let Ok(key) = std::env::var("ANTHROPIC_API_KEY") {
        if !key.is_empty() {
            return call_anthropic_simple(&key, "", system, prompt).await;
        }
    }
    warn!("No AI provider configured or all failed");
    String::new()
}

async fn env_fallback_chat(
    system: &str,
    history: &[serde_json::Value],
    user_msg: &str,
) -> anyhow::Result<(String, String)> {
    if let Ok(key) = std::env::var("GROQ_API_KEY") {
        if !key.is_empty() {
            let model = std::env::var("GROQ_MODEL")
                .unwrap_or_else(|_| "llama-3.3-70b-versatile".to_string());
            if let Ok(r) = call_openai_chat(
                &key, &model,
                "https://api.groq.com/openai/v1/chat/completions",
                system, history, user_msg,
            ).await {
                if !r.0.is_empty() { return Ok(r); }
            }
        }
    }
    if let Ok(key) = std::env::var("OPENAI_API_KEY") {
        if !key.is_empty() {
            if let Ok(r) = call_openai_chat(
                &key, "gpt-4o-mini",
                "https://api.openai.com/v1/chat/completions",
                system, history, user_msg,
            ).await {
                if !r.0.is_empty() { return Ok(r); }
            }
        }
    }
    if let Ok(key) = std::env::var("ANTHROPIC_API_KEY") {
        if !key.is_empty() {
            return call_claude_chat(&key, "", system, history, user_msg).await;
        }
    }
    Ok(("AI not configured — add a provider in Settings > AI Configuration.".to_string(), "sad".to_string()))
}
