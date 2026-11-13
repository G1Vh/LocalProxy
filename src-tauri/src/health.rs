//! Do the outbounds in use work? Each one (the default and those rules name)
//! is checked every 30 s and right after config changes, and inferred from
//! real traffic in between. Changes show in the tray icon and tooltip, in
//! the window, and as a Windows notification per outbound.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use proxy_core::config::{Config, OnOutboundDown, Outbound, ProxyEndpoint};
use proxy_core::outbound::Upstream;
use proxy_core::probe::health_check;
use proxy_core::{ConnEvent, Inbound, RouteKind};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_notification::NotificationExt;
use tokio::sync::Notify;
use tokio::task::JoinSet;
use uuid::Uuid;

use crate::commands;
use crate::state::AppState;
use crate::tray;

/// Event name; payload is [`HealthState`].
pub const OUTBOUND_HEALTH: &str = "outbound-health";
const INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", tag = "state")]
pub enum Health {
    /// Routing is switched off.
    Off,
    /// Routing is on but no outbound is in use (none selected by default).
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

/// The whole picture: one verdict for the tray and the header, plus one per
/// outbound in use (only `Up` and `Down` there).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthState {
    pub overall: Health,
    pub outbounds: BTreeMap<Uuid, Health>,
}

impl Default for HealthState {
    fn default() -> Self {
        Self {
            overall: Health::Off,
            outbounds: BTreeMap::new(),
        }
    }
}

impl HealthState {
    fn new(config: &Config, outbounds: BTreeMap<Uuid, Health>) -> Self {
        Self {
            overall: overall(config, &outbounds),
            outbounds,
        }
    }
}

/// Up when every outbound in use is; otherwise down, naming the broken ones.
fn overall(config: &Config, outbounds: &BTreeMap<Uuid, Health>) -> Health {
    let down: Vec<String> = outbounds
        .iter()
        .filter_map(|(id, h)| match h {
            Health::Down { reason } => Some(match config.outbound(*id) {
                Some(o) if outbounds.len() > 1 => format!("«{}»: {reason}", o.name),
                _ => reason.clone(),
            }),
            _ => None,
        })
        .collect();
    if down.is_empty() {
        Health::Up
    } else {
        Health::Down {
            reason: down.join("; "),
        }
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

async fn check(app: &AppHandle) -> HealthState {
    let state = app.state::<AppState>();
    let config = state.config().clone();
    if !config.enabled {
        return HealthState::default();
    }
    if config.tun_enabled && !tun_alive(&state).await {
        // The service ended the session (crash, stopped by hand): start it
        // again; if that fails, the TUN mode is switched off with a message.
        tracing::warn!("tun session gone, restarting");
        let _ = commands::apply_config(app, &state, config.clone()).await;
    }
    let effective = crate::presets::effective(&config, &state.presets().file);
    let used: Vec<Outbound> = effective.used_outbounds().into_iter().cloned().collect();
    if used.is_empty() {
        return HealthState {
            overall: Health::NoOutbound,
            outbounds: BTreeMap::new(),
        };
    }

    let mut tunnels = running_tunnels(&state).await;
    let missing = used
        .iter()
        .any(|o| o.kind.is_tunnel() && !tunnels.contains_key(&o.id));
    if missing {
        // Died, or never came up (no network yet at logon): try again.
        crate::runtime::revive_tunnels(app, &state).await;
        tunnels = running_tunnels(&state).await;
    }

    let mut checks = JoinSet::new();
    for outbound in used {
        let upstream = if outbound.kind.is_tunnel() {
            match tunnels.get(&outbound.id) {
                Some(endpoint) => Upstream::Socks5(endpoint.clone()),
                None => {
                    let reason = state
                        .tunnel_error(outbound.id)
                        .unwrap_or_else(|| "туннель не подключён".into());
                    checks.spawn(async move { (outbound.id, Health::Down { reason }) });
                    continue;
                }
            }
        } else {
            Upstream::from_kind(&outbound.kind)
        };
        let port = config.port;
        checks.spawn(async move {
            let health = if upstream.points_to(port) {
                Health::Down {
                    reason: proxy_core::router::SELF_LOOP.into(),
                }
            } else {
                match health_check(&upstream).await {
                    Ok(()) => Health::Up,
                    Err(reason) => Health::Down { reason },
                }
            };
            (outbound.id, health)
        });
    }
    let mut outbounds = BTreeMap::new();
    while let Some(Ok((id, health))) = checks.join_next().await {
        outbounds.insert(id, health);
    }
    HealthState::new(&config, outbounds)
}

async fn tun_alive(state: &AppState) -> bool {
    state
        .tun
        .lock()
        .await
        .as_ref()
        .is_some_and(|t| t.is_alive())
}

/// SOCKS5 endpoints of the tunnel processes that are alive.
async fn running_tunnels(state: &AppState) -> HashMap<Uuid, ProxyEndpoint> {
    let mut tunnels = state.tunnels.lock().await;
    tunnels
        .iter_mut()
        .filter_map(|(id, t)| t.is_alive().then(|| (*id, t.endpoint.clone())))
        .collect()
}

/// Real traffic between checks: a connection through an outbound proves it
/// up, a blocked or bypassed one proves it down. UDP is ignored: an HTTP
/// outbound refusing UDP is alive.
pub fn observe(app: &AppHandle, batch: &[ConnEvent]) {
    let Some(state) = app.try_state::<AppState>() else {
        return;
    };
    let verdicts = verdicts(batch);
    if verdicts.is_empty() {
        return;
    }
    let mut next = state.health().clone();
    if next.overall == Health::Off {
        return;
    }
    for (id, health) in verdicts {
        // Only outbounds in use; the next check sorts out the rest.
        if let Some(current) = next.outbounds.get_mut(&id) {
            *current = health;
        }
    }
    let config = state.config().clone();
    next.overall = overall(&config, &next.outbounds);
    set(app, next);
}

/// The newest event per outbound tells its current state.
fn verdicts(batch: &[ConnEvent]) -> HashMap<Uuid, Health> {
    let mut out = HashMap::new();
    for event in batch.iter().filter(|e| e.inbound != Inbound::Udp) {
        let Some(id) = event.outbound_id else {
            continue;
        };
        let health = match event.route {
            RouteKind::Proxy => Health::Up,
            RouteKind::Blocked | RouteKind::Fallback => Health::Down {
                reason: event.error.clone().unwrap_or_default(),
            },
            _ => continue,
        };
        out.insert(id, health);
    }
    out
}

pub fn set(app: &AppHandle, new: HealthState) {
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
    tray::show_health(app, &new.overall);
    let _ = app.emit(OUTBOUND_HEALTH, &new);
    for (id, health) in &new.outbounds {
        let before = previous.outbounds.get(id).unwrap_or(&Health::Off);
        if !health.same_kind(before) {
            tracing::info!(%id, ?before, ?health, "outbound health changed");
            notify(app, &state, *id, before, health);
        }
    }
}

fn notify(app: &AppHandle, state: &AppState, id: Uuid, previous: &Health, new: &Health) {
    let config = state.config().clone();
    if !config.notifications {
        return;
    }
    let name = config
        .outbound(id)
        .map(|o| o.name.clone())
        .unwrap_or_default();
    let body = match (previous, new) {
        (Health::Up | Health::Off, Health::Down { reason }) => {
            let policy = match config.on_outbound_down {
                OnOutboundDown::Block => "Домены блокируются.",
                OnOutboundDown::Direct => "Домены идут напрямую.",
            };
            format!("«{name}» недоступен: {reason}\n{policy}")
        }
        (Health::Down { .. }, Health::Up) => format!("«{name}» снова работает."),
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
pub fn get_health(state: tauri::State<'_, AppState>) -> HealthState {
    state.health().clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(inbound: Inbound, route: RouteKind, outbound: Uuid) -> ConnEvent {
        ConnEvent {
            at_ms: 0,
            inbound,
            host: "x".into(),
            port: 443,
            route,
            rule_id: None,
            outbound_id: (route != RouteKind::Direct).then_some(outbound),
            process: None,
            error: (route == RouteKind::Blocked).then(|| "канал недоступен".into()),
        }
    }

    #[test]
    fn newest_tcp_event_per_outbound_decides() {
        use Inbound::*;
        use RouteKind::*;
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        assert!(verdicts(&[]).is_empty());
        assert!(
            verdicts(&[event(Connect, Direct, a)]).is_empty(),
            "direct says nothing about outbounds"
        );
        let v = verdicts(&[
            event(Connect, Blocked, a),
            event(Http, Proxy, a),
            event(Socks5, Proxy, b),
            event(Connect, Blocked, b),
            event(Udp, Proxy, b),
        ]);
        assert_eq!(v[&a], Health::Up);
        assert!(
            matches!(v[&b], Health::Down { .. }),
            "UDP does not count, the TCP failure stands"
        );
    }

    #[test]
    fn overall_names_the_broken_outbounds() {
        let mk = |name: &str| Outbound {
            id: Uuid::new_v4(),
            name: name.into(),
            kind: proxy_core::config::OutboundKind::Http(ProxyEndpoint::default()),
        };
        let (office, vpn) = (mk("Офис"), mk("VPN"));
        let config = Config {
            outbounds: vec![office.clone(), vpn.clone()],
            ..Config::default()
        };
        let down = |r: &str| Health::Down { reason: r.into() };
        let all_up = BTreeMap::from([(office.id, Health::Up), (vpn.id, Health::Up)]);
        assert_eq!(overall(&config, &all_up), Health::Up);
        let one_down = BTreeMap::from([(office.id, Health::Up), (vpn.id, down("таймаут"))]);
        assert_eq!(overall(&config, &one_down), down("«VPN»: таймаут"));
        let single = BTreeMap::from([(vpn.id, down("таймаут"))]);
        assert_eq!(overall(&config, &single), down("таймаут"), "no name needed");
    }
}
