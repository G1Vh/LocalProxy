// Hide the console window in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod browsers;
mod commands;
mod events;
mod health;
mod presets;
mod rules;
mod runtime;
mod state;
mod system;
mod tray;
mod tun;
mod tunnel;
mod ui_commands;
mod updates;

use tauri::{Manager, RunEvent};
use tracing_subscriber::EnvFilter;

/// Passed by the autostart entry so the app starts straight into the tray.
const MINIMIZED_ARG: &str = "--minimized";
/// Run by the uninstaller: put the Windows settings back and exit.
const RESTORE_SYSTEM_ARG: &str = "--restore-system";

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,localproxy=debug,proxy_core=debug")),
        )
        .init();

    // Handled before the single-instance plugin, which would otherwise hand
    // the request to a running copy and exit without doing anything.
    if std::env::args().any(|a| a == RESTORE_SYSTEM_ARG) {
        restore_system_and_exit();
    }
    let start_minimized = std::env::args().any(|a| a == MINIMIZED_ARG);

    let app = tauri::Builder::default()
        // Must be the first plugin: a second launch just brings up the running window.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            tray::show_main_window(app);
        }))
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec![MINIMIZED_ARG]),
        ))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(move |app| {
            let state = state::AppState::load()?;
            sync_at_startup(app.handle(), &state);
            commands::apply_theme(app.handle(), state.config().theme);
            let poke = state.health_poke.clone();
            app.manage(state);
            app.manage(updates::Updates::default());
            tray::create(app.handle())?;
            health::spawn_monitor(app.handle().clone(), poke);
            updates::spawn_checker(app.handle().clone());
            if !start_minimized {
                tray::show_main_window(app.handle());
            }
            // Fresh preset list from GitHub, in the background.
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                ui_commands::refresh_presets_inner(&handle).await;
            });
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
            commands::get_autostart,
            commands::set_autostart,
            ui_commands::normalize_rule_pattern,
            ui_commands::check_host,
            ui_commands::test_outbound,
            ui_commands::get_presets,
            ui_commands::refresh_presets,
            ui_commands::get_rule_stats,
            ui_commands::get_hidden_stats,
            ui_commands::add_rule_lines,
            ui_commands::set_preset_selected,
            ui_commands::export_rules,
            ui_commands::import_rules,
            ui_commands::get_browser_warnings,
            ui_commands::get_tunnel_status,
            ui_commands::get_forward_status,
            ui_commands::get_tun_status,
            ui_commands::get_traffic,
            ui_commands::reset_traffic,
            health::get_health,
            updates::check_update,
            updates::get_pending_update,
            updates::install_update,
        ])
        .build(tauri::generate_context!())
        .expect("error while building LocalProxy");

    app.run(|app, event| {
        if let RunEvent::Exit = event {
            // Leave Windows as we found it; `enabled` stays in the config so the
            // next start switches routing back on.
            let state = app.state::<state::AppState>();
            // The adapter goes first, so nothing is left routed into it.
            if let Some(tun) = tauri::async_runtime::block_on(state.tun.lock()).take() {
                tauri::async_runtime::block_on(tun.stop());
            }
            if let Err(e) = state.system.restore() {
                tracing::error!("cannot restore system proxy on exit: {e:#}");
            }
        }
    });
}

/// Restores routing after a restart, or cleans up after a crash: if the last
/// run died with Windows pointed at our PAC, the backup puts it back.
fn sync_at_startup(app: &tauri::AppHandle, state: &state::AppState) {
    let mut config = state.config().clone();
    let error = tauri::async_runtime::block_on(runtime::sync_runtime(app, state, &mut config));
    // Routing or the TUN mode may have been switched off by a failed start.
    if config != *state.config() {
        if let Err(e) = config.save(&state.config_path) {
            tracing::error!("cannot save config: {e}");
        }
        *state.config() = config;
    }
    if error.is_some() {
        state.set_start_error(error);
    }
}

fn restore_system_and_exit() -> ! {
    let code = match state::config_dir().map(|dir| system::SystemProxy::new(&dir).restore()) {
        Ok(Ok(())) => 0,
        Ok(Err(e)) | Err(e) => {
            tracing::error!("restore failed: {e:#}");
            1
        }
    };
    std::process::exit(code);
}
