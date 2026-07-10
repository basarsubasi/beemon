use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::response::IntoResponse;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use prost::Message as ProstMessage;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tokio_stream::wrappers::BroadcastStream;
use tracing::warn;

use crate::http::AppState;
use crate::pb::EventBatch;

pub async fn ws_events(
    ws: WebSocketUpgrade,
    Path(pid): Path<u32>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, axum::http::StatusCode> {
    if pid == 0 || pid == std::process::id() {
        return Err(axum::http::StatusCode::BAD_REQUEST);
    }
    Ok(ws.on_upgrade(move |socket| handle_ws(socket, state, pid)))
}

async fn handle_ws(socket: WebSocket, state: AppState, pid: u32) {
    let sub = match state.registry.subscribe(pid, state.event_limit) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "ws subscribe failed");
            return;
        }
    };

    let (mut ws_tx, mut ws_rx) = socket.split();

    let cancel = Arc::new(tokio::sync::Notify::new());
    let cancel_clone = cancel.clone();
    tokio::spawn(async move {
        while let Some(result) = ws_rx.next().await {
            if result.is_err() {
                cancel_clone.notify_one();
                return;
            }
        }
    });

    let (tx, mut rx) = mpsc::channel::<Message>(256);

    let boot_offset = Arc::new(AtomicI64::new(0));
    let boot_offset_clone = boot_offset.clone();
    let tx_clone = tx.clone();
    let cancel_for_stream = cancel.clone();
    let mut stream = BroadcastStream::new(sub.rx);

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel_for_stream.notified() => return,
                batch = stream.next() => {
                    match batch {
                        Some(Ok(event)) => {
                            if event.timestamp_ns > 0 && boot_offset_clone.load(Ordering::Relaxed) == 0 {
                                let bt = read_boot_time().unwrap_or(0);
                                boot_offset_clone.store(bt, Ordering::Relaxed);
                            }
                            let batch = EventBatch { events: vec![event] };
                            let bytes = batch.encode_to_vec();
                            if tx_clone.send(Message::Binary(Bytes::from(bytes))).await.is_err() {
                                return;
                            }
                        }
                        Some(Err(_)) => continue,
                        None => return,
                    }
                }
            }
        }
    });

    let _guard = sub.guard;

    let mut ticker = interval(Duration::from_secs(2));

    loop {
        tokio::select! {
            _ = cancel.notified() => break,
            _ = ticker.tick() => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis();
                let ping = serde_json::json!({"type": "ping", "timestamp": now});
                if ws_tx.send(Message::Text(ping.to_string().into())).await.is_err() {
                    break;
                }
            }
            msg = rx.recv() => {
                match msg {
                    Some(m) => {
                        if ws_tx.send(m).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
        }
    }
}

fn read_boot_time() -> Option<i64> {
    let stat = std::fs::read_to_string("/proc/stat").ok()?;
    for line in stat.lines() {
        if let Some(rest) = line.strip_prefix("btime ") {
            return rest.trim().parse::<i64>().ok().map(|s| s * 1000);
        }
    }
    None
}
