// Hide the console window in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod state;
mod tray;

use tauri::Manager;
use tracing_subscriber::EnvFilter;

/// Passed by the autostart entry so the app starts straight into the tray.
const MINIMIZED_ARG: &str = "--minimized";

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,localproxy=debug,proxy_core=debug")),
        )
        .init();

    let start_minimized = std::env::args().any(|a| a == MINIMIZED_ARG);

    tauri::Builder::default()
        // Must be the first plugin: a second launch just brings up the running window.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            tray::show_main_window(app);
        }))
        .setup(move |app| {
            let state = state::AppState::load()?;
            start_proxy_if_enabled(&state);
            app.manage(state);
            tray::create(app.handle())?;
            if !start_minimized {
                tray::show_main_window(app.handle());
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the window keeps the app running in the tray.
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_app_info,
            commands::get_config,
            commands::save_config,
            commands::set_enabled,
        ])
        .run(tauri::generate_context!())
        .expect("error while running LocalProxy");
}

/// Restores routing after a restart. If the proxy cannot start, routing is
/// switched off in the saved config and the reason is shown in the window.
fn start_proxy_if_enabled(state: &state::AppState) {
    let mut config = state.config().clone();
    if !config.enabled {
        return;
    }
    let Some(error) = tauri::async_runtime::block_on(commands::sync_proxy(state, &mut config))
    else {
        return;
    };
    if let Err(e) = config.save(&state.config_path) {
        tracing::error!("cannot save config: {e}");
    }
    *state.config() = config;
    state.set_start_error(Some(error));
}
