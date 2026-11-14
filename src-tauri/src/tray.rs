use proxy_core::Config;
use tauri::image::Image;
use tauri::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, Wry};

use crate::commands;
use crate::health::Health;
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
    let health = app.state::<AppState>().health().overall.clone();

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

    TrayIconBuilder::with_id(TRAY_ID)
        .tooltip(tooltip(&health))
        .icon(icon(&health))
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            MENU_OPEN => show_main_window(app),
            MENU_TOGGLE => commands::toggle_in_background(app),
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
        })
        .build(app)?;

    app.manage(TrayItems { toggle });
    Ok(())
}

/// Brings the tray menu in line with the config (the icon follows the health).
pub fn refresh(app: &AppHandle, config: &Config) {
    if let Some(items) = app.try_state::<TrayItems>() {
        let _ = items.toggle.set_checked(config.enabled);
    }
}

/// Icon colour and tooltip for the outbound state.
pub fn show_health(app: &AppHandle, health: &Health) {
    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        let _ = tray.set_icon(Some(icon(health)));
        let _ = tray.set_tooltip(Some(tooltip(health)));
    }
}

/// Shrinks the window to the screen it is on if it does not fit (the
/// default size on a small or highly scaled screen) and centers it then.
pub fn fit_main_window(app: &AppHandle) {
    let Some(window) = app.get_webview_window("main") else {
        return;
    };
    let (Ok(Some(monitor)), Ok(outer), Ok(inner)) = (
        window.current_monitor(),
        window.outer_size(),
        window.inner_size(),
    ) else {
        return;
    };
    let area = monitor.work_area().size;
    if outer.width <= area.width && outer.height <= area.height {
        return;
    }
    // The frame (title bar, borders) comes on top of the inner size.
    let frame_w = outer.width.saturating_sub(inner.width);
    let frame_h = outer.height.saturating_sub(inner.height);
    let size = tauri::PhysicalSize::new(
        inner.width.min(area.width.saturating_sub(frame_w)),
        inner.height.min(area.height.saturating_sub(frame_h)),
    );
    let _ = window.set_size(size);
    let _ = window.center();
}

pub fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn icon(health: &Health) -> Image<'static> {
    let bytes: &[u8] = match health {
        Health::Off => include_bytes!("../icons/tray-off.png"),
        Health::Up => include_bytes!("../icons/tray-on.png"),
        Health::NoOutbound | Health::Down { .. } => include_bytes!("../icons/tray-down.png"),
    };
    Image::from_bytes(bytes).expect("tray icons are valid PNG")
}

fn tooltip(health: &Health) -> String {
    // Windows cuts tray tooltips at 127 characters.
    let text = match health {
        Health::Off => "LocalProxy — выключен".to_owned(),
        Health::Up => "LocalProxy — включён, каналы работают".to_owned(),
        Health::NoOutbound => "LocalProxy — канал не выбран".to_owned(),
        Health::Down { reason } => format!("LocalProxy — недоступно: {reason}"),
    };
    text.chars().take(120).collect()
}
