use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

use anyhow::Context;
use proxy_core::{Config, ProxyServer};

use crate::events::RuleStats;
use crate::presets::{self, PresetsFile, Source};
use crate::system::SystemProxy;

/// The preset list in use and where it came from.
pub struct PresetsState {
    pub file: PresetsFile,
    pub source: Source,
    /// Last download problem, if the newest attempt failed.
    pub last_error: Option<String>,
}

pub struct AppState {
    /// `%APPDATA%\LocalProxy`
    pub dir: PathBuf,
    pub config_path: PathBuf,
    config: Mutex<Config>,
    /// The running proxy; `None` while routing is off.
    pub proxy: tokio::sync::Mutex<Option<ProxyServer>>,
    /// Windows proxy settings and environment variables.
    pub system: SystemProxy,
    /// The WireGuard/AmneziaWG bridge, while the active outbound needs it.
    pub awg: tokio::sync::Mutex<Option<crate::awg::AwgProcess>>,
    /// Lasting problems found at startup (e.g. a broken config file).
    pub warnings: Vec<String>,
    /// Why the proxy could not start; cleared once it starts.
    start_error: Mutex<Option<String>>,
    /// Hits per rule since the app started.
    rule_stats: Mutex<RuleStats>,
    presets: Mutex<PresetsState>,
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
        let (file, source) = presets::load(&dir);
        Ok(Self {
            presets: Mutex::new(PresetsState {
                file,
                source,
                last_error: None,
            }),
            config_path: path,
            config: Mutex::new(config),
            proxy: tokio::sync::Mutex::new(None),
            system: SystemProxy::new(&dir),
            awg: tokio::sync::Mutex::new(None),
            warnings,
            start_error: Mutex::new(None),
            rule_stats: Mutex::new(RuleStats::new()),
            dir,
        })
    }

    pub fn presets(&self) -> MutexGuard<'_, PresetsState> {
        self.presets.lock().unwrap_or_else(|e| e.into_inner())
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

    pub fn rule_stats(&self) -> MutexGuard<'_, RuleStats> {
        self.rule_stats.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// `%APPDATA%\LocalProxy`
pub fn config_dir() -> anyhow::Result<PathBuf> {
    let appdata = std::env::var_os("APPDATA").context("APPDATA is not set")?;
    Ok(PathBuf::from(appdata).join("LocalProxy"))
}
