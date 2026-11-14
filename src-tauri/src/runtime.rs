//! Keeps the running parts in line with the config: the proxy server, the
//! tunnel processes of the channels in use, the TUN session and the Windows
//! proxy settings.

use std::collections::HashMap;

use proxy_core::config::{OutboundKind, ProxyEndpoint};
use proxy_core::{Config, ProxyServer};
use tauri::{AppHandle, Emitter};
use tokio::task::JoinSet;
use uuid::Uuid;

use crate::commands::APP_ERROR;
use crate::state::AppState;
use crate::system::Desired;

/// Brings the proxy and the Windows settings in line with `config`.
///
/// Order matters: on enable the proxy starts before Windows is pointed at it;
/// on disable Windows is restored before the proxy stops, so the system never
/// points at a port nobody listens on. If anything fails, routing is switched
/// off (`config.enabled = false`) and the message is returned.
pub async fn sync_runtime(
    app: &AppHandle,
    state: &AppState,
    config: &mut Config,
) -> Option<String> {
    // The TUN catches console programs by itself. Variables would outlive
    // LocalProxy in every program started meanwhile, pointing it at a port
    // nobody listens on until it is restarted.
    if config.tun_enabled {
        config.set_env_vars = false;
    }
    let mut slot = state.proxy.lock().await;

    if !config.enabled {
        sync_tun(app, state, config).await;
        let error = apply_system(state, Desired::default()).await.err();
        if let Some(server) = slot.take() {
            server.stop().await;
        }
        sync_tunnels(app, state, Vec::new()).await;
        return error;
    }

    // TUN first: our sockets must be pinned before tunnels start.
    let tun_error = sync_tun(app, state, config).await;
    let with_presets = crate::presets::effective(config, &state.presets().file);
    let tunnels = sync_tunnels(app, state, crate::tunnel::wanted(&with_presets)).await;
    let mut effective = with_tunnels(with_presets, &tunnels);
    // The TUN hands every connection to our SOCKS5 port.
    effective.socks5_enabled |= config.tun_enabled;
    let restart = slot.as_ref().is_none_or(|s| s.port() != config.port);
    if restart {
        if let Some(server) = slot.take() {
            server.stop().await;
        }
        match ProxyServer::start_with_traffic(&effective, state.traffic.clone()).await {
            Ok(server) => {
                crate::events::forward(app.clone(), server.subscribe());
                *slot = Some(server);
            }
            Err(e) => {
                tracing::error!("proxy did not start: {e}");
                config.enabled = false;
                let _ = apply_system(state, Desired::default()).await;
                return Some(format!("Прокси не запущен: {e}"));
            }
        }
    }
    let server = slot.as_ref().expect("started above");
    server.update(&effective);

    let tun_error = tun_error.or(activate_tun(app, state, config).await);
    // Windows is pointed at us only without the TUN (or when it failed to
    // start): with it, a kill leaves nothing behind in the system.
    let desired = if config.tun_enabled {
        Desired::default()
    } else {
        Desired {
            pac_url: Some(server.pac_url()),
            env_port: config.set_env_vars.then_some(server.port()),
        }
    };
    if let Err(e) = apply_system(state, desired).await {
        config.enabled = false;
        let _ = apply_system(state, Desired::default()).await;
        sync_tun(app, state, config).await;
        if let Some(server) = slot.take() {
            server.stop().await;
        }
        return Some(e);
    }
    // Kept for the window, which may open only after this (at logon).
    state.set_start_error(tun_error);
    None
}

/// Starts or stops the TUN session to match the config. A start that fails
/// (UAC declined, no adapter) switches the TUN mode off, not routing.
async fn sync_tun(app: &AppHandle, state: &AppState, config: &mut Config) -> Option<String> {
    let wanted = config.enabled && config.tun_enabled;
    let mut slot = state.tun.lock().await;
    let keep = slot.as_ref().is_some_and(|s| wanted && s.is_alive());
    if !keep && let Some(session) = slot.take() {
        session.stop().await;
        proxy_core::bind::set_interface(0, 0);
    }
    if !wanted || slot.is_some() {
        return None;
    }
    match crate::tun::TunSession::start(config.port).await {
        Ok(session) => {
            proxy_core::bind::set_interface(session.physical.0, session.physical.1);
            *slot = Some(session);
            None
        }
        Err(e) => {
            tracing::error!("tun: {e}");
            config.tun_enabled = false;
            let _ = app.emit(APP_ERROR, &e);
            Some(e)
        }
    }
}

/// The proxy runs and our sockets are pinned: let the adapter take the routes.
async fn activate_tun(app: &AppHandle, state: &AppState, config: &mut Config) -> Option<String> {
    let mut slot = state.tun.lock().await;
    let session = slot.as_mut().filter(|s| !s.active)?;
    if let Err(e) = session.take_traffic(app).await {
        tracing::error!("tun: {e}");
        if let Some(session) = slot.take() {
            session.stop().await;
        }
        proxy_core::bind::set_interface(0, 0);
        config.tun_enabled = false;
        let _ = app.emit(APP_ERROR, &e);
        return Some(e);
    }
    None
}

/// The proxy runs on the user's rules plus the entries of selected presets
/// (`with_presets`), with each tunnel outbound (WireGuard, SSTP) replaced by
/// its running tunnel.
fn with_tunnels(mut with_presets: Config, tunnels: &HashMap<Uuid, ProxyEndpoint>) -> Config {
    for outbound in &mut with_presets.outbounds {
        if let Some(endpoint) = tunnels.get(&outbound.id) {
            outbound.kind = OutboundKind::Socks5(endpoint.clone());
        }
    }
    with_presets
}

/// Starts, restarts or stops tunnel processes so that exactly the wanted
/// ones run (the tunnel outbounds in use, while routing is on). Returns the
/// SOCKS5 endpoint of each running tunnel by outbound id.
///
/// A tunnel that fails to start does not switch routing off: its outbound
/// then counts as down (block or go direct, per policy), the reason is shown
/// in the window, and the health monitor keeps trying.
async fn sync_tunnels(
    app: &AppHandle,
    state: &AppState,
    wanted: Vec<crate::tunnel::Wanted>,
) -> HashMap<Uuid, ProxyEndpoint> {
    let mut running = state.tunnels.lock().await;

    let stale: Vec<Uuid> = running
        .iter_mut()
        .filter_map(|(id, t)| {
            let keep = t.is_alive()
                && t.bind == proxy_core::bind::interface()
                && wanted.iter().any(|w| w.id == *id && w.spec == t.spec);
            (!keep).then_some(*id)
        })
        .collect();
    for id in stale {
        if let Some(tunnel) = running.remove(&id) {
            tunnel.stop().await;
        }
    }

    // All missing tunnels start at once: SSTP alone may take seconds.
    let mut starting = JoinSet::new();
    for w in wanted
        .iter()
        .filter(|w| !running.contains_key(&w.id))
        .cloned()
    {
        starting.spawn(async move {
            let result = crate::tunnel::TunnelProcess::start(w.id, &w.spec).await;
            (w, result)
        });
    }
    while let Some(joined) = starting.join_next().await {
        let Ok((w, result)) = joined else { continue };
        match result {
            Ok(tunnel) => {
                running.insert(w.id, tunnel);
                state.set_tunnel_error(w.id, None);
            }
            Err(e) => {
                tracing::error!(outbound = %w.name, "tunnel: {e}");
                // Retries repeat the same error: show it once.
                if state.set_tunnel_error(w.id, Some(e.clone())) {
                    let _ = app.emit(APP_ERROR, format!("Канал «{}»: {e}", w.name));
                }
            }
        }
    }
    state.keep_tunnel_errors(&wanted.iter().map(|w| w.id).collect::<Vec<_>>());
    running
        .iter()
        .map(|(id, t)| (*id, t.endpoint.clone()))
        .collect()
}

/// Brings back tunnels that died or never came up (no network yet at
/// logon, server down, a new address after a reconnect) and points the
/// running proxy at them. Called by the health monitor.
pub async fn revive_tunnels(app: &AppHandle, state: &AppState) {
    let config = state.config().clone();
    let slot = state.proxy.lock().await;
    let Some(server) = slot.as_ref() else {
        return;
    };
    let with_presets = crate::presets::effective(&config, &state.presets().file);
    let tunnels = sync_tunnels(app, state, crate::tunnel::wanted(&with_presets)).await;
    server.update(&with_tunnels(with_presets, &tunnels));
}

async fn apply_system(state: &AppState, desired: Desired) -> Result<(), String> {
    let system = state.system.clone();
    tauri::async_runtime::spawn_blocking(move || system.apply(&desired))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| {
            tracing::error!("system proxy: {e:#}");
            format!("Не удалось изменить настройки прокси Windows: {e:#}")
        })
}
