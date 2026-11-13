//! New versions from GitHub releases: `latest.json` signed with our key. Checked
//! shortly after start and every few hours (unless switched off), or on demand
//! from Settings. Installing runs the NSIS installer, which restarts the app.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_notification::NotificationExt;
use tauri_plugin_updater::{Update, UpdaterExt};

use crate::state::AppState;

/// Event name; payload is [`UpdateInfo`].
pub const UPDATE_AVAILABLE: &str = "update-available";
/// Event name; payload is [`Progress`].
pub const UPDATE_PROGRESS: &str = "update-progress";

const FIRST_CHECK: Duration = Duration::from_secs(20);
const INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

#[derive(Default)]
pub struct Updates {
    pending: Mutex<Option<Update>>,
    /// The version we already showed a notification for.
    notified: Mutex<Option<String>>,
    installing: AtomicBool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInfo {
    pub version: String,
    pub current_version: String,
    pub notes: Option<String>,
}

impl From<&Update> for UpdateInfo {
    fn from(u: &Update) -> Self {
        Self {
            version: u.version.clone(),
            current_version: u.current_version.clone(),
            notes: u.body.clone().filter(|b| !b.trim().is_empty()),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Progress {
    pub downloaded: u64,
    pub total: Option<u64>,
}

pub fn spawn_checker(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(FIRST_CHECK).await;
        loop {
            if app.state::<AppState>().config().check_updates {
                match check(&app).await {
                    Ok(Some(info)) => notify_once(&app, &info),
                    Ok(None) => {}
                    Err(e) => tracing::warn!("update check: {e}"),
                }
            }
            tokio::time::sleep(INTERVAL).await;
        }
    });
}

async fn check(app: &AppHandle) -> Result<Option<UpdateInfo>, String> {
    let handle = app.clone();
    let updater = app
        .updater_builder()
        // The installer ends the process with `exit(0)`: no RunEvent::Exit,
        // so put Windows back here. `enabled` stays in the config, and the
        // restarted app switches routing on again.
        .on_before_exit(move || before_exit(&handle))
        .build()
        .map_err(|e| e.to_string())?;
    let update = updater
        .check()
        .await
        .map_err(|e| format!("не удалось проверить обновления: {e}"))?;
    let info = update.as_ref().map(UpdateInfo::from);
    *app.state::<Updates>().pending.lock().unwrap() = update;
    if let Some(info) = &info {
        tracing::info!(version = info.version, "update available");
        let _ = app.emit(UPDATE_AVAILABLE, info);
    }
    Ok(info)
}

fn before_exit(app: &AppHandle) {
    let state = app.state::<AppState>();
    if let Err(e) = state.system.restore() {
        tracing::error!("cannot restore system proxy before update: {e:#}");
    }
    // The installer replaces awg-bridge.exe too: stop it (kill on drop).
    if let Ok(mut awg) = state.awg.try_lock() {
        awg.take();
    }
}

fn notify_once(app: &AppHandle, info: &UpdateInfo) {
    let state = app.state::<AppState>();
    if !state.config().notifications {
        return;
    }
    let updates = app.state::<Updates>();
    {
        let mut notified = updates.notified.lock().unwrap();
        if notified.as_deref() == Some(info.version.as_str()) {
            return;
        }
        *notified = Some(info.version.clone());
    }
    let body = format!(
        "Доступна версия {}. Установить можно в окне программы.",
        info.version
    );
    if let Err(e) = app
        .notification()
        .builder()
        .title("LocalProxy")
        .body(body)
        .show()
    {
        tracing::warn!("notification: {e}");
    }
}

#[tauri::command]
pub async fn check_update(app: AppHandle) -> Result<Option<UpdateInfo>, String> {
    check(&app).await
}

#[tauri::command]
pub fn get_pending_update(updates: tauri::State<'_, Updates>) -> Option<UpdateInfo> {
    updates
        .pending
        .lock()
        .unwrap()
        .as_ref()
        .map(UpdateInfo::from)
}

/// Downloads, checks the signature and runs the installer; on success the
/// process exits and never returns here.
#[tauri::command]
pub async fn install_update(app: AppHandle) -> Result<(), String> {
    let updates = app.state::<Updates>();
    let Some(update) = updates.pending.lock().unwrap().clone() else {
        return Err("Обновление не найдено: проверьте ещё раз".into());
    };
    if updates.installing.swap(true, Ordering::SeqCst) {
        return Err("Обновление уже скачивается".into());
    }
    let mut downloaded = 0u64;
    let result = update
        .download_and_install(
            |chunk, total| {
                downloaded += chunk as u64;
                let _ = app.emit(UPDATE_PROGRESS, Progress { downloaded, total });
            },
            || {},
        )
        .await;
    updates.installing.store(false, Ordering::SeqCst);
    result.map_err(|e| format!("Не удалось установить обновление: {e}"))
}
