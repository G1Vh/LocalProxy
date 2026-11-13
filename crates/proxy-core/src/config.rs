//! Application configuration: model, defaults, load and atomic save.

use std::collections::BTreeMap;
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
    /// Look for a new version on GitHub at start and every few hours.
    pub check_updates: bool,
    /// TUN mode (the default): the whole system's traffic goes through
    /// LocalProxy via a virtual adapter. Off: system proxy (PAC) only, no
    /// administrator rights needed.
    pub tun_enabled: bool,
    pub active_outbound_id: Option<Uuid>,
    pub outbounds: Vec<Outbound>,
    pub rules: Vec<Rule>,
    /// Local ports passed through an outbound to a fixed address, for
    /// programs that cannot use a proxy (database clients, RDP, SSH).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub forwards: Vec<PortForward>,
    /// Outbound per selected preset; a preset not listed uses the default.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub preset_outbounds: BTreeMap<String, Uuid>,
    /// Entries hidden from the connections feed (a program knocking on a
    /// closed port, say). Only the feed: routing, channel health and
    /// statistics still see them.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub hidden_events: Vec<HiddenEvent>,
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
            check_updates: true,
            tun_enabled: true,
            active_outbound_id: None,
            outbounds: Vec::new(),
            rules: Vec::new(),
            presets: Vec::new(),
            preset_outbounds: BTreeMap::new(),
            forwards: Vec::new(),
            hidden_events: Vec::new(),
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
    /// SSTP VPN (Windows RRAS, MikroTik, SoftEther...): PPP inside HTTPS.
    Sstp(SstpEndpoint),
}

impl OutboundKind {
    /// Runs through a userspace tunnel process rather than a proxy server.
    pub fn is_tunnel(&self) -> bool {
        matches!(self, Self::Awg { .. } | Self::Sstp(_))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SstpEndpoint {
    /// `host` or `host:port` (443 by default).
    pub server: String,
    pub username: String,
    pub password: String,
    /// SHA-256 of the server certificate to trust (a self-signed one); empty
    /// means the Windows certificate store decides.
    pub cert_sha256: String,
    /// Do not check the certificate at all.
    pub insecure: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ProxyEndpoint {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
}

/// Feed entries to hide: by program, host and port; an absent part matches
/// any.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HiddenEvent {
    pub id: Uuid,
    /// Program file name, e.g. `rustdesk.exe`; case does not matter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Hide only failed connections; successful ones stay in the feed.
    #[serde(default = "default_true")]
    pub errors_only: bool,
}

/// `127.0.0.1:local_port` leads to `target_host:target_port` through an outbound.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortForward {
    pub id: Uuid,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub local_port: u16,
    pub target_host: String,
    pub target_port: u16,
    /// `None` means the default outbound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound: Option<Uuid>,
    #[serde(default)]
    pub comment: String,
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
    /// Where a proxy rule sends traffic; `None` means the default outbound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound: Option<Uuid>,
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
    /// A program: `discord.exe` (file name, `*` and `?` allowed) or a full
    /// path. Its whole traffic follows the rule, whatever the address; wins
    /// over address rules. Known for every connection in TUN mode, and for
    /// programs that use LocalProxy as their proxy.
    Process,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RuleAction {
    /// Through the rule's own channel, or the default one.
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

    /// The default outbound: for proxy rules without one of their own.
    pub fn active_outbound(&self) -> Option<&Outbound> {
        let id = self.active_outbound_id?;
        self.outbounds.iter().find(|o| o.id == id)
    }

    pub fn outbound(&self, id: Uuid) -> Option<&Outbound> {
        self.outbounds.iter().find(|o| o.id == id)
    }

    /// Outbounds traffic can go to: the default one and those named by
    /// enabled proxy rules and port forwards. Call it on the config with
    /// presets expanded.
    pub fn used_outbounds(&self) -> Vec<&Outbound> {
        let mut ids: Vec<Uuid> = self.active_outbound().map(|o| o.id).into_iter().collect();
        let rules = self
            .rules
            .iter()
            .filter(|r| r.enabled && r.action == RuleAction::Proxy)
            .filter_map(|r| r.outbound);
        let forwards = self
            .forwards
            .iter()
            .filter(|f| f.enabled)
            .filter_map(|f| f.outbound);
        for id in rules.chain(forwards) {
            if !ids.contains(&id) {
                ids.push(id);
            }
        }
        ids.into_iter().filter_map(|id| self.outbound(id)).collect()
    }

    /// Rules and presets pointing at a deleted outbound go back to the
    /// default one; returns how many were changed.
    pub fn forget_missing_outbounds(&mut self) -> usize {
        let known: Vec<Uuid> = self.outbounds.iter().map(|o| o.id).collect();
        let mut changed = 0;
        for rule in &mut self.rules {
            if rule.outbound.is_some_and(|id| !known.contains(&id)) {
                rule.outbound = None;
                changed += 1;
            }
        }
        for forward in &mut self.forwards {
            if forward.outbound.is_some_and(|id| !known.contains(&id)) {
                forward.outbound = None;
                changed += 1;
            }
        }
        let before = self.preset_outbounds.len();
        let presets = &self.presets;
        self.preset_outbounds
            .retain(|preset, id| known.contains(id) && presets.contains(preset));
        changed + before - self.preset_outbounds.len()
    }
}

#[cfg(test)]
mod tests;
