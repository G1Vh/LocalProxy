use std::collections::HashMap;

use proxy_core::config::{OutboundKind, ProxyEndpoint};
use proxy_core::{Config, ProxyServer};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};

use tauri_plugin_autostart::ManagerExt;
use tokio::task::JoinSet;
use uuid::Uuid;

use crate::state::AppState;
use crate::system::Desired;
use crate::tray;

/// Event the UI listens to; payload is the new [`Config`].
pub const CONFIG_CHANGED: &str = "config-changed";
/// Errors from actions the UI did not start (e.g. the tray toggle); payload is the message.
pub const APP_ERROR: &str = "app-error";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInfo {
    version: String,
    config_path: String,
    warnings: Vec<String>,
    start_error: Option<String>,
}

#[tauri::command]
pub fn get_app_info(app: AppHandle, state: State<'_, AppState>) -> AppInfo {
    AppInfo {
        version: app.package_info().version.to_string(),
        config_path: state.config_path.display().to_string(),
        warnings: state.warnings.clone(),
        start_error: state.start_error(),
    }
}

#[tauri::command]
pub fn get_config(state: State<'_, AppState>) -> Config {
    state.config().clone()
}

#[tauri::command]
pub async fn save_config(
    app: AppHandle,
    state: State<'_, AppState>,
    config: Config,
) -> Result<Config, String> {
    apply_config(&app, &state, config).await
}

#[tauri::command]
pub async fn set_enabled(
    app: AppHandle,
    state: State<'_, AppState>,
    enabled: bool,
) -> Result<Config, String> {
    set_enabled_inner(&app, &state, enabled).await
}

pub async fn set_enabled_inner(
    app: &AppHandle,
    state: &AppState,
    enabled: bool,
) -> Result<Config, String> {
    let mut config = state.config().clone();
    config.enabled = enabled;
    apply_config(app, state, config).await
}

/// Toggle from outside the UI (tray); errors go to the window as an event.
pub fn toggle_in_background(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let state = app.state::<AppState>();
        let enabled = !state.config().enabled;
        if let Err(e) = set_enabled_inner(&app, &state, enabled).await {
            tracing::error!("cannot toggle: {e}");
            let _ = app.emit(APP_ERROR, e);
        }
    });
}

/// Single entry point for every config change: bring the proxy in line,
/// persist, swap in memory, sync the tray and notify the UI.
///
/// If the proxy cannot start (e.g. the port is busy) the config is still
/// saved, with routing switched off, and the error is returned.
pub async fn apply_config(
    app: &AppHandle,
    state: &AppState,
    mut config: Config,
) -> Result<Config, String> {
    config.forget_missing_outbounds();
    let start_error = sync_runtime(app, state, &mut config).await;
    config.save(&state.config_path).map_err(|e| e.to_string())?;
    *state.config() = config.clone();
    tray::refresh(app, &config);
    crate::health::poke(app);
    if let Err(e) = app.emit(CONFIG_CHANGED, &config) {
        tracing::warn!("cannot emit {CONFIG_CHANGED}: {e}");
    }
    match start_error {
        Some(e) => Err(e),
        None => Ok(config),
    }
}

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
    let mut slot = state.proxy.lock().await;

    if !config.enabled {
        let error = apply_system(state, Desired::default()).await.err();
        if let Some(server) = slot.take() {
            server.stop().await;
        }
        sync_tunnels(app, state, Vec::new()).await;
        return error;
    }

    let with_presets = crate::presets::effective(config, &state.presets().file);
    let tunnels = sync_tunnels(app, state, crate::tunnel::wanted(&with_presets)).await;
    let effective = with_tunnels(with_presets, &tunnels);
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

    let desired = Desired {
        pac_url: Some(server.pac_url()),
        env_port: config.set_env_vars.then_some(server.port()),
    };
    if let Err(e) = apply_system(state, desired).await {
        config.enabled = false;
        let _ = apply_system(state, Desired::default()).await;
        if let Some(server) = slot.take() {
            server.stop().await;
        }
        return Some(e);
    }
    state.set_start_error(None);
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
            let keep = t.is_alive() && wanted.iter().any(|w| w.id == *id && w.spec == t.spec);
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

#[tauri::command]
pub fn get_autostart(app: AppHandle) -> Result<bool, String> {
    app.autolaunch().is_enabled().map_err(|e| e.to_string())
}

#[tauri::command]
pub fn set_autostart(app: AppHandle, enabled: bool) -> Result<bool, String> {
    let launcher = app.autolaunch();
    let result = if enabled {
        launcher.enable()
    } else {
        launcher
            .disable()
            .inspect(|_| crate::system::remove_startup_approved(&app.package_info().name))
    };
    result.map_err(|e| format!("Не удалось изменить автозагрузку: {e}"))?;
    launcher.is_enabled().map_err(|e| e.to_string())
}
