//! Registers LocalProxy in Windows and puts everything back.
//!
//! Before the first change the original settings are written to
//! `system-backup.json`; the file lives until they are restored. So a crash,
//! a kill on shutdown or an uninstall never strands the system on a dead PAC:
//! the next start (or `--restore-system` from the uninstaller) restores them.

pub mod env;
pub mod wininet;

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};

/// Removes the Task Manager "startup approved" mark that the autostart
/// library leaves behind when autostart is switched off.
pub fn remove_startup_approved(app_name: &str) {
    use windows_sys::Win32::System::Registry::{HKEY_CURRENT_USER, RegDeleteKeyValueW};
    let key =
        wininet::wide(r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run");
    let value = wininet::wide(app_name);
    // SAFETY: both strings are NUL-terminated; a missing value is fine.
    unsafe { RegDeleteKeyValueW(HKEY_CURRENT_USER, key.as_ptr(), value.as_ptr()) };
}

/// What the system should look like right now.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Desired {
    /// `Some` while routing is on: register this PAC URL.
    pub pac_url: Option<String>,
    /// `Some(port)` to set HTTP_PROXY / HTTPS_PROXY / NO_PROXY.
    pub env_port: Option<u16>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Backup {
    wininet: Option<wininet::ProxySettings>,
    env: Option<env::EnvBackup>,
}

#[derive(Debug, Clone)]
pub struct SystemProxy {
    backup_path: PathBuf,
}

impl SystemProxy {
    pub fn new(config_dir: &Path) -> Self {
        Self {
            backup_path: config_dir.join("system-backup.json"),
        }
    }

    /// Brings the system in line with `desired`, saving originals first and
    /// restoring them for whatever is no longer wanted.
    pub fn apply(&self, desired: &Desired) -> anyhow::Result<()> {
        let mut backup = self.load()?;

        match &desired.pac_url {
            Some(url) => {
                if backup.wininet.is_none() {
                    let mut current = wininet::query().context("чтение настроек прокси Windows")?;
                    if current.is_localproxy_pac() {
                        // Our own leftover (backup lost): the honest original is "no proxy".
                        current = wininet::ProxySettings::direct();
                    }
                    backup.wininet = Some(current);
                    self.save(&backup)?;
                }
                wininet::use_pac(url).context("установка PAC в настройки Windows")?;
                tracing::info!(%url, "system proxy set to PAC");
            }
            None => {
                if let Some(original) = &backup.wininet {
                    wininet::restore(original).context("восстановление настроек прокси Windows")?;
                    tracing::info!("system proxy restored");
                    backup.wininet = None;
                    self.save(&backup)?;
                } else if let Ok(current) = wininet::query()
                    && current.is_localproxy_pac()
                {
                    // No backup but the system still points at us: switch it off.
                    wininet::restore(&wininet::ProxySettings::direct())
                        .context("сброс оставшегося PAC LocalProxy")?;
                    tracing::warn!("removed a stale LocalProxy PAC without a backup");
                }
            }
        }

        match desired.env_port {
            Some(port) => {
                if backup.env.is_none() {
                    backup.env = Some(env::read().context("чтение переменных среды")?);
                    self.save(&backup)?;
                }
                env::set(port).context("установка HTTP_PROXY / HTTPS_PROXY")?;
            }
            None => {
                if let Some(original) = &backup.env {
                    env::restore(original).context("восстановление переменных среды")?;
                    backup.env = None;
                    self.save(&backup)?;
                }
            }
        }
        Ok(())
    }

    /// Restores everything LocalProxy changed.
    pub fn restore(&self) -> anyhow::Result<()> {
        self.apply(&Desired::default())
    }

    fn load(&self) -> anyhow::Result<Backup> {
        match fs::read_to_string(&self.backup_path) {
            Ok(text) => serde_json::from_str(&text)
                .with_context(|| format!("повреждён {}", self.backup_path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Backup::default()),
            Err(e) => Err(e).with_context(|| format!("чтение {}", self.backup_path.display())),
        }
    }

    /// Writes the backup, or deletes the file once there is nothing to restore.
    fn save(&self, backup: &Backup) -> anyhow::Result<()> {
        if backup.wininet.is_none() && backup.env.is_none() {
            return match fs::remove_file(&self.backup_path) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                    Err(e).context("удаление резервной копии настроек")
                }
                _ => Ok(()),
            };
        }
        if let Some(dir) = self.backup_path.parent() {
            fs::create_dir_all(dir)?;
        }
        let tmp = self.backup_path.with_extension("json.tmp");
        fs::write(&tmp, serde_json::to_vec_pretty(backup)?)?;
        fs::rename(&tmp, &self.backup_path).context("запись резервной копии настроек")
    }
}
