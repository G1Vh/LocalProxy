//! Connection events from the proxy to the window, in batches, plus
//! per-rule hit counters.

use std::collections::HashMap;
use std::time::Duration;

use proxy_core::ConnEvent;
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};
use tokio::sync::broadcast::Receiver;
use tokio::sync::broadcast::error::{RecvError, TryRecvError};
use uuid::Uuid;

use crate::state::AppState;

/// Event name; payload is `Vec<ConnEvent>`.
pub const CONN_EVENTS: &str = "conn-events";
/// Collect events this long before sending, so a page load is one message, not hundreds.
const BATCH_WINDOW: Duration = Duration::from_millis(250);
const MAX_BATCH: usize = 500;

#[derive(Debug, Clone, Copy, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleStat {
    pub hits: u64,
    pub last_ms: u64,
}

pub type RuleStats = HashMap<Uuid, RuleStat>;

/// Forwards events until the server that owns the channel is gone.
pub fn forward(app: AppHandle, mut rx: Receiver<ConnEvent>) {
    tauri::async_runtime::spawn(async move {
        loop {
            let first = match rx.recv().await {
                Ok(event) => event,
                Err(RecvError::Lagged(_)) => continue,
                Err(RecvError::Closed) => break,
            };
            let mut batch = vec![first];
            tokio::time::sleep(BATCH_WINDOW).await;
            loop {
                match rx.try_recv() {
                    Ok(event) => batch.push(event),
                    Err(TryRecvError::Lagged(_)) => continue,
                    Err(_) => break,
                }
            }
            if batch.len() > MAX_BATCH {
                batch.drain(..batch.len() - MAX_BATCH);
            }
            if let Some(state) = app.try_state::<AppState>() {
                record(&mut state.rule_stats(), &batch);
            }
            crate::health::observe(&app, &batch);
            let _ = app.emit(CONN_EVENTS, &batch);
        }
    });
}

fn record(stats: &mut RuleStats, batch: &[ConnEvent]) {
    for event in batch {
        if let Some(id) = event.rule_id {
            let stat = stats.entry(id).or_default();
            stat.hits += 1;
            stat.last_ms = stat.last_ms.max(event.at_ms);
        }
    }
}
