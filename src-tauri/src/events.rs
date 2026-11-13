//! Connection events from the proxy to the window, in batches, plus
//! per-rule hit counters. Entries the user hid are dropped here, after
//! health and rule counters have seen them, and counted apart.

use std::collections::HashMap;
use std::time::Duration;

use proxy_core::ConnEvent;
use proxy_core::config::HiddenEvent;
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};
use tokio::sync::broadcast::Receiver;
use tokio::sync::broadcast::error::{RecvError, TryRecvError};
use uuid::Uuid;

use crate::state::AppState;

/// Event name; payload is `Vec<ConnEvent>`.
pub const CONN_EVENTS: &str = "conn-events";
/// Event name; payload is hits per hidden entry ([`RuleStats`]).
pub const HIDDEN_STATS: &str = "hidden-stats";
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
            crate::health::observe(&app, &batch);
            if let Some(state) = app.try_state::<AppState>() {
                record(&mut state.rule_stats(), &batch);
                let hidden = state.config().hidden_events.clone();
                let mut stats = state.hidden_stats();
                if drop_hidden(&hidden, &mut batch, &mut stats) {
                    let _ = app.emit(HIDDEN_STATS, &*stats);
                }
            }
            if !batch.is_empty() {
                let _ = app.emit(CONN_EVENTS, &batch);
            }
        }
    });
}

/// Removes hidden entries from `batch`, counting them by hidden entry;
/// true if any was removed.
fn drop_hidden(hidden: &[HiddenEvent], batch: &mut Vec<ConnEvent>, stats: &mut RuleStats) -> bool {
    if hidden.is_empty() {
        return false;
    }
    let before = batch.len();
    batch.retain(|e| {
        let Some(h) = hidden.iter().find(|h| hides(h, e)) else {
            return true;
        };
        let stat = stats.entry(h.id).or_default();
        stat.hits += 1;
        stat.last_ms = stat.last_ms.max(e.at_ms);
        false
    });
    batch.len() != before
}

fn hides(h: &HiddenEvent, e: &ConnEvent) -> bool {
    if h.errors_only && e.error.is_none() {
        return false;
    }
    let program = e.process.as_deref().map(proxy_core::process::file_name);
    h.process
        .as_deref()
        .is_none_or(|p| program.is_some_and(|name| name.eq_ignore_ascii_case(p)))
        && h.host
            .as_deref()
            .is_none_or(|host| host.eq_ignore_ascii_case(&e.host))
        && h.port.is_none_or(|port| port == e.port)
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

#[cfg(test)]
mod tests {
    use super::*;
    use proxy_core::{Inbound, RouteKind};

    fn event(process: Option<&str>, host: &str, port: u16, error: bool) -> ConnEvent {
        ConnEvent {
            at_ms: 7,
            inbound: Inbound::Socks5,
            host: host.into(),
            port,
            route: if error {
                RouteKind::Failed
            } else {
                RouteKind::Direct
            },
            rule_id: None,
            outbound_id: None,
            process: process.map(str::to_owned),
            error: error.then(|| "отказ".into()),
        }
    }

    #[test]
    fn hides_by_program_host_and_port() {
        let rustdesk = HiddenEvent {
            id: Uuid::new_v4(),
            process: Some("rustdesk.exe".into()),
            host: Some("access.g1vh.tw1.ru".into()),
            port: Some(21114),
            errors_only: true,
        };
        let any_port = HiddenEvent {
            id: Uuid::new_v4(),
            process: None,
            host: Some("telemetry.example".into()),
            port: None,
            errors_only: false,
        };
        let app = r"C:\Program Files\RustDesk\RustDesk.exe";
        let mut batch = vec![
            event(Some(app), "access.g1vh.tw1.ru", 21114, true),
            event(Some(app), "Access.G1vh.Tw1.Ru", 21114, true),
            event(Some(app), "access.g1vh.tw1.ru", 21114, false), // not an error
            event(Some(app), "access.g1vh.tw1.ru", 21116, true),  // other port
            event(Some(r"C:\other.exe"), "access.g1vh.tw1.ru", 21114, true),
            event(None, "access.g1vh.tw1.ru", 21114, true), // program unknown
            event(None, "telemetry.example", 443, false),
        ];
        let mut stats = RuleStats::new();
        assert!(drop_hidden(
            &[rustdesk.clone(), any_port.clone()],
            &mut batch,
            &mut stats
        ));
        let left: Vec<_> = batch
            .iter()
            .map(|e| (e.port, e.error.is_some(), e.process.is_some()))
            .collect();
        assert_eq!(
            left,
            [
                (21114, false, true),
                (21116, true, true),
                (21114, true, true),
                (21114, true, false)
            ]
        );
        assert_eq!(stats[&rustdesk.id].hits, 2);
        assert_eq!(stats[&any_port.id].hits, 1);
        assert_eq!(stats[&rustdesk.id].last_ms, 7);

        let mut quiet = vec![event(None, "x.com", 443, true)];
        assert!(!drop_hidden(&[rustdesk], &mut quiet, &mut stats));
        assert_eq!(quiet.len(), 1);
    }
}
