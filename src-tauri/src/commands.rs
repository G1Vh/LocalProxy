use proxy_core::{Config, ProxyServer};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};

use crate::state::AppState;
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
    let start_error = sync_proxy(state, &mut config).await;
    config.save(&state.config_path).map_err(|e| e.to_string())?;
    *state.config() = config.clone();
    tray::refresh(app, &config);
    if let Err(e) = app.emit(CONFIG_CHANGED, &config) {
        tracing::warn!("cannot emit {CONFIG_CHANGED}: {e}");
    }
    match start_error {
        Some(e) => Err(e),
        None => Ok(config),
    }
}

/// Starts, updates, restarts or stops the proxy to match `config`.
/// On a start failure switches `config.enabled` off and returns the message.
pub async fn sync_proxy(state: &AppState, config: &mut Config) -> Option<String> {
    let mut slot = state.proxy.lock().await;
    if !config.enabled {
        if let Some(server) = slot.take() {
            server.stop().await;
        }
        return None;
    }
    if let Some(server) = slot.as_ref()
        && server.port() == config.port
    {
        server.update(config);
        return None;
    }
    if let Some(server) = slot.take() {
        server.stop().await;
    }
    match ProxyServer::start(config).await {
        Ok(server) => {
            *slot = Some(server);
            state.set_start_error(None);
            None
        }
        Err(e) => {
            tracing::error!("proxy did not start: {e}");
            config.enabled = false;
            Some(format!("Прокси не запущен: {e}"))
        }
    }
}
