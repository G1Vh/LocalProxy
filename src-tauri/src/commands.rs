use proxy_core::Config;
use serde::Serialize;
use tauri::{AppHandle, Emitter, State};

use crate::state::AppState;
use crate::tray;

/// Event the UI listens to; payload is the new [`Config`].
pub const CONFIG_CHANGED: &str = "config-changed";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInfo {
    version: String,
    config_path: String,
    load_warning: Option<String>,
}

#[tauri::command]
pub fn get_app_info(app: AppHandle, state: State<'_, AppState>) -> AppInfo {
    AppInfo {
        version: app.package_info().version.to_string(),
        config_path: state.config_path.display().to_string(),
        load_warning: state.load_warning.clone(),
    }
}

#[tauri::command]
pub fn get_config(state: State<'_, AppState>) -> Config {
    state.config().clone()
}

#[tauri::command]
pub fn save_config(
    app: AppHandle,
    state: State<'_, AppState>,
    config: Config,
) -> Result<Config, String> {
    apply_config(&app, &state, config)
}

#[tauri::command]
pub fn set_enabled(
    app: AppHandle,
    state: State<'_, AppState>,
    enabled: bool,
) -> Result<Config, String> {
    set_enabled_inner(&app, &state, enabled)
}

pub fn set_enabled_inner(
    app: &AppHandle,
    state: &AppState,
    enabled: bool,
) -> Result<Config, String> {
    let mut config = state.config().clone();
    config.enabled = enabled;
    apply_config(app, state, config)
}

/// Single entry point for every config change: persist, swap in memory,
/// sync the tray and notify the UI.
pub fn apply_config(app: &AppHandle, state: &AppState, config: Config) -> Result<Config, String> {
    config.save(&state.config_path).map_err(|e| e.to_string())?;
    *state.config() = config.clone();
    tray::refresh(app, &config);
    if let Err(e) = app.emit(CONFIG_CHANGED, &config) {
        tracing::warn!("cannot emit {CONFIG_CHANGED}: {e}");
    }
    Ok(config)
}
