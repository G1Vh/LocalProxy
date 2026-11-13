use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

use anyhow::Context;
use proxy_core::traffic::Traffic;
use proxy_core::{Config, ProxyServer};
use tokio::sync::Notify;
use uuid::Uuid;

use crate::events::RuleStats;
use crate::health::HealthState;
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
    /// TUN mode session, while it runs.
    pub tun: tokio::sync::Mutex<Option<crate::tun::TunSession>>,
    /// Tunnel processes by outbound id, for the tunnel outbounds in use.
    pub tunnels: tokio::sync::Mutex<HashMap<Uuid, crate::tunnel::TunnelProcess>>,
    /// Lasting problems found at startup (e.g. a broken config file).
    pub warnings: Vec<String>,
    /// Why the proxy could not start; cleared once it starts.
    start_error: Mutex<Option<String>>,
    /// Why a tunnel could not start, by outbound id; cleared once it runs.
    tunnel_errors: Mutex<HashMap<Uuid, String>>,
    /// Hits per rule since the app started.
    rule_stats: Mutex<RuleStats>,
    /// Feed entries hidden since the app started, per hidden entry.
    hidden_stats: Mutex<RuleStats>,
    presets: Mutex<PresetsState>,
    /// Whether the outbounds in use work; see [`crate::health`].
    health: Mutex<HealthState>,
    /// Wakes the health monitor for an immediate check.
    pub health_poke: Arc<Notify>,
    /// Bytes per host since the app started; survives proxy restarts.
    pub traffic: Arc<Traffic>,
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
            tun: tokio::sync::Mutex::default(),
            tunnels: tokio::sync::Mutex::default(),
            warnings,
            start_error: Mutex::new(None),
            tunnel_errors: Mutex::default(),
            rule_stats: Mutex::new(RuleStats::new()),
            hidden_stats: Mutex::new(RuleStats::new()),
            health: Mutex::default(),
            health_poke: Arc::new(Notify::new()),
            traffic: Arc::default(),
            dir,
        })
    }

    pub fn health(&self) -> MutexGuard<'_, HealthState> {
        self.health.lock().unwrap_or_else(|e| e.into_inner())
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

    pub fn tunnel_error(&self, id: Uuid) -> Option<String> {
        self.tunnel_errors
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&id)
            .cloned()
    }

    /// Returns whether the error changed.
    pub fn set_tunnel_error(&self, id: Uuid, error: Option<String>) -> bool {
        let mut errors = self.tunnel_errors.lock().unwrap_or_else(|e| e.into_inner());
        let previous = match error {
            Some(e) => errors.insert(id, e.clone()).filter(|p| *p == e),
            None => return errors.remove(&id).is_some(),
        };
        previous.is_none()
    }

    /// Forgets errors of tunnels no longer wanted.
    pub fn keep_tunnel_errors(&self, wanted: &[Uuid]) {
        self.tunnel_errors
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|id, _| wanted.contains(id));
    }

    pub fn rule_stats(&self) -> MutexGuard<'_, RuleStats> {
        self.rule_stats.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn hidden_stats(&self) -> MutexGuard<'_, RuleStats> {
        self.hidden_stats.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// `%APPDATA%\LocalProxy`
pub fn config_dir() -> anyhow::Result<PathBuf> {
    let appdata = std::env::var_os("APPDATA").context("APPDATA is not set")?;
    Ok(PathBuf::from(appdata).join("LocalProxy"))
}
