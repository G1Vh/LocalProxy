use proxy_core::config::{OutboundKind, ProxyEndpoint};
use proxy_core::{Config, ProxyServer};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};

use tauri_plugin_autostart::ManagerExt;

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
        sync_tunnel(app, state, config).await;
        return error;
    }

    let tunnel = sync_tunnel(app, state, config).await;
    let effective = effective_config(state, config, tunnel);
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

/// The proxy runs on the user's rules plus the entries of selected presets,
/// with a tunnel outbound (WireGuard, SSTP) replaced by its running tunnel.
fn effective_config(
    state: &AppState,
    config: &Config,
    tunnel: Option<(uuid::Uuid, ProxyEndpoint)>,
) -> Config {
    let mut effective = crate::presets::effective(config, &state.presets().file);
    if let Some((id, endpoint)) = tunnel {
        effective
            .outbounds
            .iter_mut()
            .filter(|o| o.id == id)
            .for_each(|o| o.kind = OutboundKind::Socks5(endpoint.clone()));
    }
    effective
}

/// Starts, restarts or stops the tunnel process so that it runs exactly
/// when routing is on and the active outbound is a tunnel. Returns the
/// outbound id and the tunnel's SOCKS5 endpoint while it runs.
///
/// A tunnel that fails to start does not switch routing off: the outbound
/// then counts as down (block or go direct, per policy), the reason is shown
/// in the window, and the health monitor keeps trying.
async fn sync_tunnel(
    app: &AppHandle,
    state: &AppState,
    config: &Config,
) -> Option<(uuid::Uuid, ProxyEndpoint)> {
    let wanted = config
        .enabled
        .then(|| crate::tunnel::wanted(config))
        .flatten();
    let mut slot = state.tunnel.lock().await;

    let keep = match (&mut *slot, &wanted) {
        (Some(running), Some((id, spec))) => {
            running.outbound_id == *id && running.spec == *spec && running.is_alive()
        }
        _ => false,
    };
    if !keep && let Some(old) = slot.take() {
        old.stop().await;
    }
    let Some((id, spec)) = wanted else {
        state.set_tunnel_error(None);
        return None;
    };
    if slot.is_none() {
        match crate::tunnel::TunnelProcess::start(id, &spec).await {
            Ok(tunnel) => {
                *slot = Some(tunnel);
                state.set_tunnel_error(None);
            }
            Err(e) => {
                tracing::error!("tunnel: {e}");
                // Retries repeat the same error: show it once.
                if state.set_tunnel_error(Some(e.clone())) {
                    let _ = app.emit(APP_ERROR, e);
                }
                return None;
            }
        }
    }
    slot.as_ref().map(|t| (t.outbound_id, t.endpoint.clone()))
}

/// Brings back a tunnel that died or never came up (no network yet at
/// logon, server down, a new address after a reconnect) and points the
/// running proxy at it. Called by the health monitor.
pub async fn revive_tunnel(app: &AppHandle, state: &AppState) {
    let config = state.config().clone();
    let slot = state.proxy.lock().await;
    let Some(server) = slot.as_ref() else {
        return;
    };
    let tunnel = sync_tunnel(app, state, &config).await;
    server.update(&effective_config(state, &config, tunnel));
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
