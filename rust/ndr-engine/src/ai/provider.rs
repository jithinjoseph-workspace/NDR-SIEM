use std::sync::Arc;
use tracing::{error, warn};

// Process-level cache: use_case_tag → (providers, populated_at)
// TTL = 5 min. Serialised behind a Mutex so only one CH query fires per miss.
static PROVIDER_CACHE: std::sync::OnceLock<
    Arc<tokio::sync::Mutex<std::collections::HashMap<String, (Vec<AiProvider>, std::time::Instant)>>>
> = std::sync::OnceLock::new();

fn provider_cache() -> Arc<tokio::sync::Mutex<std::collections::HashMap<String, (Vec<AiProvider>, std::time::Instant)>>> {
    PROVIDER_CACHE
        .get_or_init(|| Arc::new(tokio::sync::Mutex::new(Default::default())))
        .clone()
}

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
    let providers = cached_providers(storage, use_case.tag()).await;

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
    let providers = cached_providers(storage, "chat").await;

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

/// Returns providers from cache if fresh (< 5 min), otherwise queries CH once
/// and updates cache. Callers that arrive during a refresh wait on the Mutex
/// and immediately read the freshly populated result — no thundering herd.
async fn cached_providers(
    storage: &crate::storage::ClickhouseStorage,
    tag: &str,
) -> Vec<AiProvider> {
    let cache = provider_cache();
    let mut guard = cache.lock().await;
    let needs_refresh = guard.get(tag)
        .map(|(_, ts)| ts.elapsed() > std::time::Duration::from_secs(300))
        .unwrap_or(true);
    if needs_refresh {
        let fresh = storage.get_ai_providers(tag).await.unwrap_or_default();
        guard.insert(tag.to_string(), (fresh.clone(), std::time::Instant::now()));
        fresh
    } else {
        guard[tag].0.clone()
    }
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

// ─── No env-var fallback — DB only ─────────────────────────────────────────

async fn env_fallback_simple(_system: &str, _prompt: &str) -> String {
    warn!("No AI provider configured in DB — add one in Settings > AI Configuration");
    String::new()
}

async fn env_fallback_chat(
    _system: &str,
    _history: &[serde_json::Value],
    _user_msg: &str,
) -> anyhow::Result<(String, String)> {
    Ok(("AI not configured — add a provider in Settings > AI Configuration.".to_string(), "sad".to_string()))
}
