use proxy_core::Config;
use tauri::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, Wry};

use crate::commands;
use crate::state::AppState;

const TRAY_ID: &str = "main";
const MENU_OPEN: &str = "open";
const MENU_TOGGLE: &str = "toggle";
const MENU_QUIT: &str = "quit";

/// Menu items that have to follow the config.
struct TrayItems {
    toggle: CheckMenuItem<Wry>,
}

pub fn create(app: &AppHandle) -> tauri::Result<()> {
    let enabled = app.state::<AppState>().config().enabled;

    let open = MenuItem::with_id(app, MENU_OPEN, "Открыть LocalProxy", true, None::<&str>)?;
    let toggle = CheckMenuItem::with_id(
        app,
        MENU_TOGGLE,
        "Проксирование включено",
        true,
        enabled,
        None::<&str>,
    )?;
    let quit = MenuItem::with_id(app, MENU_QUIT, "Выход", true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let menu = Menu::with_items(app, &[&open, &toggle, &separator, &quit])?;

    let mut builder = TrayIconBuilder::with_id(TRAY_ID)
        .tooltip(tooltip(enabled))
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            MENU_OPEN => show_main_window(app),
            MENU_TOGGLE => {
                let state = app.state::<AppState>();
                let enabled = !state.config().enabled;
                if let Err(e) = commands::set_enabled_inner(app, &state, enabled) {
                    tracing::error!("cannot toggle from tray: {e}");
                }
            }
            MENU_QUIT => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }
    builder.build(app)?;

    app.manage(TrayItems { toggle });
    Ok(())
}

/// Brings the tray state in line with the config.
pub fn refresh(app: &AppHandle, config: &Config) {
    if let Some(items) = app.try_state::<TrayItems>() {
        let _ = items.toggle.set_checked(config.enabled);
    }
    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        let _ = tray.set_tooltip(Some(tooltip(config.enabled)));
    }
}

pub fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn tooltip(enabled: bool) -> &'static str {
    if enabled {
        "LocalProxy — включён"
    } else {
        "LocalProxy — выключен"
    }
}
