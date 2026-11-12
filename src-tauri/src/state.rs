use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

use anyhow::Context;
use proxy_core::Config;

pub struct AppState {
    pub config_path: PathBuf,
    config: Mutex<Config>,
    /// Set when the config file was broken and had to be replaced with defaults.
    pub load_warning: Option<String>,
}

impl AppState {
    pub fn load() -> anyhow::Result<Self> {
        let path = config_dir()?.join("config.json");
        let (config, err) = Config::load_or_recover(&path);
        if let Some(err) = &err {
            tracing::warn!("config was unreadable, starting with defaults: {err}");
        }
        tracing::info!(path = %path.display(), "config loaded");
        Ok(Self {
            config_path: path,
            config: Mutex::new(config),
            load_warning: err.map(|e| e.to_string()),
        })
    }

    pub fn config(&self) -> MutexGuard<'_, Config> {
        // A panic while holding the lock must not brick the app.
        self.config.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// `%APPDATA%\LocalProxy`
fn config_dir() -> anyhow::Result<PathBuf> {
    let appdata = std::env::var_os("APPDATA").context("APPDATA is not set")?;
    Ok(PathBuf::from(appdata).join("LocalProxy"))
}
