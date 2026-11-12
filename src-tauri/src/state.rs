use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

use anyhow::Context;
use proxy_core::{Config, ProxyServer};

use crate::system::SystemProxy;

pub struct AppState {
    pub config_path: PathBuf,
    config: Mutex<Config>,
    /// The running proxy; `None` while routing is off.
    pub proxy: tokio::sync::Mutex<Option<ProxyServer>>,
    /// Windows proxy settings and environment variables.
    pub system: SystemProxy,
    /// Lasting problems found at startup (e.g. a broken config file).
    pub warnings: Vec<String>,
    /// Why the proxy could not start; cleared once it starts.
    start_error: Mutex<Option<String>>,
}

impl AppState {
    pub fn load() -> anyhow::Result<Self> {
        let dir = config_dir()?;
        let path = dir.join("config.json");
        let (config, err) = Config::load_or_recover(&path);
        let mut warnings = Vec::new();
        if let Some(err) = err {
            tracing::warn!("config was unreadable, starting with defaults: {err}");
            warnings.push(format!(
                "Файл настроек был повреждён и переименован в config.json.broken, \
                 загружены настройки по умолчанию. {err}"
            ));
        }
        tracing::info!(path = %path.display(), "config loaded");
        Ok(Self {
            config_path: path,
            config: Mutex::new(config),
            proxy: tokio::sync::Mutex::new(None),
            system: SystemProxy::new(&dir),
            warnings,
            start_error: Mutex::new(None),
        })
    }

    pub fn config(&self) -> MutexGuard<'_, Config> {
        // A panic while holding the lock must not brick the app.
        self.config.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn start_error(&self) -> Option<String> {
        self.start_error
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn set_start_error(&self, error: Option<String>) {
        *self.start_error.lock().unwrap_or_else(|e| e.into_inner()) = error;
    }
}

/// `%APPDATA%\LocalProxy`
pub fn config_dir() -> anyhow::Result<PathBuf> {
    let appdata = std::env::var_os("APPDATA").context("APPDATA is not set")?;
    Ok(PathBuf::from(appdata).join("LocalProxy"))
}
