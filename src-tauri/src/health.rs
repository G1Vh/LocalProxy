//! Is the active outbound alive? Checked every 30 s and right after config
//! changes, and inferred from real traffic in between. Changes show in the
//! tray icon and tooltip, in the window, and as a Windows notification.

use std::sync::Arc;
use std::time::Duration;

use proxy_core::config::{OnOutboundDown, ProxyEndpoint};
use proxy_core::outbound::Upstream;
use proxy_core::probe::health_check;
use proxy_core::{ConnEvent, Inbound, RouteKind};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_notification::NotificationExt;
use tokio::sync::Notify;

use crate::commands;
use crate::state::AppState;
use crate::tray;

/// Event name; payload is [`Health`].
pub const OUTBOUND_HEALTH: &str = "outbound-health";
const INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", tag = "state")]
pub enum Health {
    /// Routing is switched off.
    Off,
    /// Routing is on but no outbound is selected.
    NoOutbound,
    Up,
    Down {
        reason: String,
    },
}

impl Health {
    fn same_kind(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

/// Wakes the monitor for an immediate check (after a config change).
pub fn poke(app: &AppHandle) {
    if let Some(state) = app.try_state::<AppState>() {
        state.health_poke.notify_one();
    }
}

pub fn spawn_monitor(app: AppHandle, poke: Arc<Notify>) {
    tauri::async_runtime::spawn(async move {
        loop {
            let health = check(&app).await;
            set(&app, health);
            tokio::select! {
                _ = tokio::time::sleep(INTERVAL) => {}
                _ = poke.notified() => {}
            }
        }
    });
}

async fn check(app: &AppHandle) -> Health {
    let state = app.state::<AppState>();
    let config = state.config().clone();
    if !config.enabled {
        return Health::Off;
    }
    let Some(outbound) = config.active_outbound() else {
        return Health::NoOutbound;
    };
    let upstream = if outbound.kind.is_tunnel() {
        let mut endpoint = running_tunnel(&state).await;
        if endpoint.is_none() {
            commands::revive_tunnel(app, &state).await;
            endpoint = running_tunnel(&state).await;
        }
        match endpoint {
            Some(endpoint) => Upstream::Socks5(endpoint),
            None => {
                return Health::Down {
                    reason: state
                        .tunnel_error()
                        .unwrap_or_else(|| "туннель не подключён".into()),
                };
            }
        }
    } else {
        Upstream::from_kind(&outbound.kind)
    };
    if upstream.points_to(config.port) {
        return Health::Down {
            reason: proxy_core::router::SELF_LOOP.into(),
        };
    }
    match health_check(&upstream).await {
        Ok(()) => Health::Up,
        Err(reason) => Health::Down { reason },
    }
}

/// SOCKS5 endpoint of the tunnel process, if it is alive.
async fn running_tunnel(state: &AppState) -> Option<ProxyEndpoint> {
    let mut slot = state.tunnel.lock().await;
    let tunnel = slot.as_mut()?;
    tunnel.is_alive().then(|| tunnel.endpoint.clone())
}

/// Real traffic between checks: a connection through the outbound proves it
/// up, a blocked or bypassed one proves it down. UDP is ignored: an HTTP
/// outbound refusing UDP is alive.
pub fn observe(app: &AppHandle, batch: &[ConnEvent]) {
    if let Some(health) = verdict(batch) {
        set(app, health);
    }
}

fn verdict(batch: &[ConnEvent]) -> Option<Health> {
    // The newest event tells the current state.
    batch
        .iter()
        .rev()
        .filter(|e| e.inbound != Inbound::Udp)
        .find_map(|e| match e.route {
            RouteKind::Proxy => Some(Health::Up),
            RouteKind::Blocked | RouteKind::Fallback => Some(Health::Down {
                reason: e.error.clone().unwrap_or_default(),
            }),
            _ => None,
        })
}

pub fn set(app: &AppHandle, new: Health) {
    let Some(state) = app.try_state::<AppState>() else {
        return;
    };
    let previous = {
        let mut current = state.health();
        if *current == new {
            return;
        }
        std::mem::replace(&mut *current, new.clone())
    };
    tray::show_health(app, &new);
    let _ = app.emit(OUTBOUND_HEALTH, &new);
    if !new.same_kind(&previous) {
        tracing::info!(?previous, ?new, "outbound health changed");
        notify(app, &state, &previous, &new);
    }
}

fn notify(app: &AppHandle, state: &AppState, previous: &Health, new: &Health) {
    let config = state.config().clone();
    if !config.notifications {
        return;
    }
    let name = config
        .active_outbound()
        .map(|o| o.name.clone())
        .unwrap_or_default();
    let body = match (previous, new) {
        (Health::Up | Health::Off, Health::Down { reason }) => {
            let policy = match config.on_outbound_down {
                OnOutboundDown::Block => "Домены из правил заблокированы, пока он не вернётся.",
                OnOutboundDown::Direct => "Домены из правил пока идут напрямую.",
            };
            format!("Outbound «{name}» недоступен: {reason}\n{policy}")
        }
        (Health::Down { .. }, Health::Up) => format!("Outbound «{name}» снова работает."),
        _ => return,
    };
    if let Err(e) = app
        .notification()
        .builder()
        .title("LocalProxy")
        .body(body)
        .show()
    {
        tracing::warn!("notification: {e}");
    }
}

#[tauri::command]
pub fn get_health(state: tauri::State<'_, AppState>) -> Health {
    state.health().clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(inbound: Inbound, route: RouteKind) -> ConnEvent {
        ConnEvent {
            at_ms: 0,
            inbound,
            host: "x".into(),
            port: 443,
            route,
            rule_id: None,
            error: (route == RouteKind::Blocked).then(|| "outbound недоступен".into()),
        }
    }

    #[test]
    fn newest_tcp_event_decides() {
        use Inbound::*;
        use RouteKind::*;
        assert_eq!(verdict(&[]), None);
        assert_eq!(
            verdict(&[event(Connect, Direct)]),
            None,
            "direct says nothing about the outbound"
        );
        assert_eq!(
            verdict(&[event(Connect, Blocked), event(Http, Proxy)]),
            Some(Health::Up)
        );
        assert!(matches!(
            verdict(&[event(Connect, Proxy), event(Socks5, Blocked)]),
            Some(Health::Down { .. })
        ));
        assert_eq!(
            verdict(&[event(Connect, Proxy), event(Udp, Blocked)]),
            Some(Health::Up),
            "UDP refused by an HTTP outbound does not mean it is down"
        );
    }
}
