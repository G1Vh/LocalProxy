//! Application configuration: model, defaults, load and atomic save.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Current on-disk schema version.
pub const CONFIG_VERSION: u32 = 1;

/// Default local listening port (HTTP and SOCKS5 share it).
pub const DEFAULT_PORT: u16 = 3128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Config {
    pub version: u32,
    /// Whether routing is switched on (PAC registered in the system).
    pub enabled: bool,
    pub port: u16,
    /// Accept SOCKS5 clients on the same port.
    pub socks5_enabled: bool,
    /// Also set user-level HTTP_PROXY / HTTPS_PROXY / NO_PROXY for console tools.
    pub set_env_vars: bool,
    /// What to do with matched traffic when the outbound is unreachable.
    pub on_outbound_down: OnOutboundDown,
    /// Show tray notifications when the outbound goes down or comes back.
    pub notifications: bool,
    pub active_outbound_id: Option<Uuid>,
    pub outbounds: Vec<Outbound>,
    pub rules: Vec<Rule>,
    /// Ids of the domain presets the user subscribed to. Their entries are
    /// added to the rules at runtime from the current preset list, so preset
    /// updates apply by themselves; they are never copied into `rules`.
    pub presets: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: CONFIG_VERSION,
            enabled: false,
            port: DEFAULT_PORT,
            socks5_enabled: true,
            set_env_vars: false,
            on_outbound_down: OnOutboundDown::Block,
            notifications: true,
            active_outbound_id: None,
            outbounds: Vec::new(),
            rules: Vec::new(),
            presets: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum OnOutboundDown {
    /// Refuse the connection: matched domains never leak to the direct route.
    #[default]
    Block,
    /// Fall back to a direct connection.
    Direct,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Outbound {
    pub id: Uuid,
    pub name: String,
    #[serde(flatten)]
    pub kind: OutboundKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum OutboundKind {
    /// Upstream HTTP proxy (CONNECT for tunnels, absolute-form for plain HTTP).
    Http(ProxyEndpoint),
    /// Upstream SOCKS5 proxy.
    Socks5(ProxyEndpoint),
    /// WireGuard / AmneziaWG tunnel; `config` is the full `.conf` text.
    /// Plain WireGuard configs work as is (AmneziaWG with obfuscation off).
    Awg { config: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ProxyEndpoint {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rule {
    pub id: Uuid,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub pattern: String,
    #[serde(default)]
    pub match_type: MatchType,
    #[serde(default)]
    pub action: RuleAction,
    #[serde(default)]
    pub comment: String,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MatchType {
    /// `example.com` matches only `example.com`.
    Exact,
    /// `example.com` matches `example.com` and every `*.example.com`.
    #[default]
    DomainAndSubdomains,
    /// Glob over the whole host name: `*` is any run of characters, `?` one character.
    Mask,
    /// IP network such as `149.154.160.0/20` or `2001:b28:f23d::/48`; matches
    /// connections made to an IP address (apps like Telegram Desktop do that).
    Cidr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RuleAction {
    /// Route through the active outbound.
    #[default]
    Proxy,
    /// Exception: go direct even if a broader rule says proxy.
    Direct,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("cannot parse {path}: {source}")]
    Parse {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("cannot write {path}: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("config schema version {found} is newer than supported {supported}")]
    UnsupportedVersion { found: u32, supported: u32 },
}

impl Config {
    /// Reads the config; a missing file yields the defaults.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(source) => {
                return Err(ConfigError::Read {
                    path: path.to_owned(),
                    source,
                });
            }
        };
        let config: Self = serde_json::from_str(&text).map_err(|source| ConfigError::Parse {
            path: path.to_owned(),
            source,
        })?;
        if config.version > CONFIG_VERSION {
            return Err(ConfigError::UnsupportedVersion {
                found: config.version,
                supported: CONFIG_VERSION,
            });
        }
        Ok(config)
    }

    /// Like [`Config::load`], but a broken file is moved aside to
    /// `<name>.broken` and the defaults are returned together with the error,
    /// so the app still starts and can tell the user what happened.
    pub fn load_or_recover(path: &Path) -> (Self, Option<ConfigError>) {
        match Self::load(path) {
            Ok(config) => (config, None),
            Err(err) => {
                let mut broken = path.as_os_str().to_owned();
                broken.push(".broken");
                let _ = fs::rename(path, PathBuf::from(broken));
                (Self::default(), Some(err))
            }
        }
    }

    /// Writes the config atomically: temp file in the same directory, then rename.
    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        let write_err = |source| ConfigError::Write {
            path: path.to_owned(),
            source,
        };
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).map_err(write_err)?;
        }
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);

        let json = serde_json::to_vec_pretty(self).expect("config is always serializable");
        {
            let mut file = fs::File::create(&tmp).map_err(write_err)?;
            file.write_all(&json).map_err(write_err)?;
            file.sync_all().map_err(write_err)?;
        }
        fs::rename(&tmp, path).map_err(write_err)
    }

    pub fn active_outbound(&self) -> Option<&Outbound> {
        let id = self.active_outbound_id?;
        self.outbounds.iter().find(|o| o.id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Config {
        let office = Outbound {
            id: Uuid::new_v4(),
            name: "Office".into(),
            kind: OutboundKind::Http(ProxyEndpoint {
                host: "10.20.0.5".into(),
                port: 8080,
                username: "user".into(),
                password: "p@ss".into(),
            }),
        };
        let awg = Outbound {
            id: Uuid::new_v4(),
            name: "VPS".into(),
            kind: OutboundKind::Awg {
                config: "[Interface]\nPrivateKey = x\n".into(),
            },
        };
        Config {
            enabled: true,
            active_outbound_id: Some(office.id),
            outbounds: vec![office, awg],
            rules: vec![Rule {
                id: Uuid::new_v4(),
                enabled: true,
                pattern: "openai.com".into(),
                match_type: MatchType::DomainAndSubdomains,
                action: RuleAction::Proxy,
                comment: String::new(),
            }],
            presets: vec!["youtube".into()],
            ..Config::default()
        }
    }

    #[test]
    fn missing_file_gives_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::load(&dir.path().join("config.json")).unwrap();
        assert_eq!(config, Config::default());
        assert_eq!(config.port, DEFAULT_PORT);
        assert!(config.socks5_enabled);
        assert_eq!(config.on_outbound_down, OnOutboundDown::Block);
    }

    #[test]
    fn save_then_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("config.json");
        let config = sample();
        config.save(&path).unwrap();
        assert_eq!(Config::load(&path).unwrap(), config);
        assert_eq!(config.active_outbound().unwrap().name, "Office");
    }

    #[test]
    fn json_shape_is_stable() {
        let json = serde_json::to_value(sample()).unwrap();
        assert_eq!(json["onOutboundDown"], "block");
        assert_eq!(json["outbounds"][0]["type"], "http");
        assert_eq!(json["outbounds"][0]["host"], "10.20.0.5");
        assert_eq!(json["outbounds"][1]["type"], "awg");
        assert_eq!(json["rules"][0]["matchType"], "domainAndSubdomains");
        assert_eq!(json["rules"][0]["action"], "proxy");
    }

    #[test]
    fn partial_file_fills_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        fs::write(&path, r#"{"port": 8888, "rules": [{"id": "6f1c1a8e-0000-4000-8000-000000000001", "pattern": "github.com"}]}"#).unwrap();
        let config = Config::load(&path).unwrap();
        assert_eq!(config.port, 8888);
        assert!(config.socks5_enabled);
        let rule = &config.rules[0];
        assert!(rule.enabled);
        assert_eq!(rule.match_type, MatchType::DomainAndSubdomains);
        assert_eq!(rule.action, RuleAction::Proxy);
    }

    #[test]
    fn broken_file_is_moved_aside() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        fs::write(&path, "{ not json").unwrap();
        let (config, err) = Config::load_or_recover(&path);
        assert_eq!(config, Config::default());
        assert!(matches!(err, Some(ConfigError::Parse { .. })));
        assert!(!path.exists());
        assert!(dir.path().join("config.json.broken").exists());
    }

    #[test]
    fn newer_schema_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        fs::write(&path, r#"{"version": 999}"#).unwrap();
        assert!(matches!(
            Config::load(&path),
            Err(ConfigError::UnsupportedVersion { found: 999, .. })
        ));
    }
}
