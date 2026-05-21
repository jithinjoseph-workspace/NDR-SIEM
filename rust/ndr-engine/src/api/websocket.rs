use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{State, Query};
use crate::api::AppState;
use std::collections::HashMap;
use futures_util::StreamExt;

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> axum::response::Response {
    // Extract token from query string: /ws?token=xxx
    let tenant_id = params.get("token")
        .and_then(|token| {
            let secret = std::env::var("JWT_SECRET")
                .unwrap_or_else(|_| "ndr-secret-key-2026".to_string());
            use jsonwebtoken::{decode, DecodingKey, Validation};
            use crate::api::AuthClaims;
            decode::<AuthClaims>(
                token,
                &DecodingKey::from_secret(secret.as_bytes()),
                &Validation::default()
            ).ok().map(|d| d.claims.tenant_id)
        })
        .unwrap_or_else(|| "default".to_string());

    ws.on_upgrade(move |socket| handle_ws(socket, state, tenant_id))
}

async fn handle_ws(
    mut socket: WebSocket,
    state: AppState,
    tenant_id: String,
) {
    let agent = std::env::var("NDR_AGENT_URL")
        .unwrap_or_else(|_| "http://172.25.86.150:3001".to_string());
    let client = reqwest::Client::new();

    // Push interfaces only to default tenant
    if tenant_id == "default" {
        if let Ok(resp) = client.get(
            format!("{}/agent/interfaces", agent)
        ).send().await {
            if let Ok(ifaces) = resp.json::<serde_json::Value>().await {
                let msg = serde_json::json!({
                    "type": "interfaces",
                    "interfaces": ifaces
                });
                let _ = socket.send(Message::Text(msg.to_string())).await;
            }
        }
    }

    // Push agent status only to default tenant (local sensor)
    if tenant_id == "default" {
        if let Ok(resp) = client.get(
            format!("{}/agent/status", agent)
        ).send().await {
            if let Ok(data) = resp.json::<serde_json::Value>().await {
                let msg = serde_json::json!({
                    "type": "agent_status",
                    "zeek": data.get("zeek")
                        .and_then(|v| v.as_str())
                        .unwrap_or("stopped"),
                    "suricata": data.get("suricata")
                        .and_then(|v| v.as_str())
                        .unwrap_or("stopped"),
                    "interface": data.get("interface")
                        .and_then(|v| v.as_str())
                        .unwrap_or("eth0"),
                });
                let _ = socket.send(Message::Text(msg.to_string())).await;
            }
        }
    }

    // Try Redis subscription first
    let channel = format!("tenant:{}", tenant_id);
    if let Ok(conn) = state.redis.get_async_connection().await {
        let mut pubsub = conn.into_pubsub();
        if pubsub.subscribe(&channel).await.is_ok() {
            let mut stream = pubsub.on_message();
            loop {
                tokio::select! {
                    msg = stream.next() => {
                        match msg {
                            Some(m) => {
                                if let Ok(payload) = m.get_payload::<String>() {
                                    if socket.send(Message::Text(payload)).await.is_err() {
                                        break;
                                    }
                                }
                            }
                            None => break
                        }
                    }
                }
            }
            return;
        }
    }

    // Fallback to local broadcast channel — filter by tenant_id
    let mut rx = state.tx.subscribe();
    loop {
        match rx.recv().await {
            Ok(msg) => {
                // Filter messages by tenant_id
                let should_send = if tenant_id == "default" {
                    true // admin sees all
                } else {
                    // Check if message contains tenant_id
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&msg) {
                        parsed.get("tenant_id")
                            .and_then(|t| t.as_str())
                            .map(|t| t == tenant_id)
                            .unwrap_or(false)
                    } else {
                        false
                    }
                };

                if should_send {
                    if socket.send(Message::Text(msg)).await.is_err() {
                        break;
                    }
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                tracing::warn!(
                    "WebSocket client lagged, dropped {} messages", n
                );
            }
            Err(_) => break,
        }
    }
}