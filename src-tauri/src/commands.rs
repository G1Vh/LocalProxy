use proxy_core::Config;
use proxy_core::config::Theme;
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};

use tauri_plugin_autostart::ManagerExt;

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
    config.forget_missing_outbounds();
    let start_error = crate::runtime::sync_runtime(app, state, &mut config).await;
    config.save(&state.config_path).map_err(|e| e.to_string())?;
    *state.config() = config.clone();
    apply_theme(app, config.theme);
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

/// Light or dark window frame and page. On Windows the webview takes its
/// color scheme from the window, so the page's `light-dark()` colors follow.
pub fn apply_theme(app: &AppHandle, theme: Theme) {
    let Some(window) = app.get_webview_window("main") else {
        return;
    };
    let theme = match theme {
        Theme::System => None,
        Theme::Light => Some(tauri::Theme::Light),
        Theme::Dark => Some(tauri::Theme::Dark),
    };
    if let Err(e) = window.set_theme(theme) {
        tracing::warn!("cannot set theme: {e}");
    }
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
