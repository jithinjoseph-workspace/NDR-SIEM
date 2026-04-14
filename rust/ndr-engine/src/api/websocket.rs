use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use crate::api::AppState;

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> axum::response::Response {
    ws.on_upgrade(move |socket| handle_ws(socket, state))
}

async fn handle_ws(mut socket: WebSocket, state: AppState) {
    // ── On connect: immediately push interfaces + agent status ────────────
    let agent = std::env::var("NDR_AGENT_URL")
        .unwrap_or_else(|_| "http://172.25.86.150:3001".to_string());

    let client = reqwest::Client::new();

    // Push interfaces immediately
    if let Ok(resp) = client.get(format!("{}/agent/interfaces", agent)).send().await {
        if let Ok(ifaces) = resp.json::<serde_json::Value>().await {
            let msg = serde_json::json!({
                "type": "interfaces",
                "interfaces": ifaces
            });
            let _ = socket.send(Message::Text(msg.to_string())).await;
        }
    }

    // Push agent status immediately
    if let Ok(resp) = client.get(format!("{}/agent/status", agent)).send().await {
        if let Ok(data) = resp.json::<serde_json::Value>().await {
            let msg = serde_json::json!({
                "type": "agent_status",
                "zeek": data.get("zeek").and_then(|v| v.as_str()).unwrap_or("stopped"),
                "suricata": data.get("suricata").and_then(|v| v.as_str()).unwrap_or("stopped"),
                "interface": data.get("interface").and_then(|v| v.as_str()).unwrap_or("eth0"),
            });
            let _ = socket.send(Message::Text(msg.to_string())).await;
        }
    }

    // ── Then listen to broadcast channel for ongoing events ───────────────
    let mut rx = state.tx.subscribe();
    loop {
        match rx.recv().await {
            Ok(msg) => {
                if socket.send(Message::Text(msg)).await.is_err() {
                    break; // client disconnected
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                tracing::warn!("WebSocket client lagged, dropped {} messages", n);
            }
            Err(_) => break,
        }
    }
}