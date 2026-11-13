//! The tunnel process (`localproxy-tunnel.exe`, see the `tunnel` folder): a
//! userspace VPN (WireGuard / AmneziaWG, SSTP) exposed as SOCKS5 on loopback.
//!
//! The core never deals with VPN protocols: while a tunnel runs, its outbound
//! is handed to the core as a SOCKS5 outbound pointing at the tunnel.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use proxy_core::config::{Config, Outbound, OutboundKind, ProxyEndpoint};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::time::timeout;
use uuid::Uuid;

/// Resolving the server, the TLS and PPP handshakes of SSTP: the tunnel
/// gives up after 20 s itself.
const START_TIMEOUT: Duration = Duration::from_secs(25);
const STOP_TIMEOUT: Duration = Duration::from_secs(3);
const TUNNEL_EXE: &str = "localproxy-tunnel.exe";

/// What the tunnel process is asked to run; serialized as its start request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TunnelSpec {
    Awg { conf: String },
    Sstp(SstpSpec),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SstpSpec {
    server: String,
    user: String,
    password: String,
    cert_sha256: String,
    insecure: bool,
}

impl TunnelSpec {
    /// `None` for outbounds served by a proxy server rather than a tunnel.
    pub fn of(outbound: &Outbound) -> Option<Self> {
        match &outbound.kind {
            OutboundKind::Awg { config } => Some(Self::Awg {
                conf: config.clone(),
            }),
            OutboundKind::Sstp(e) => Some(Self::Sstp(SstpSpec {
                server: e.server.clone(),
                user: e.username.clone(),
                password: e.password.clone(),
                cert_sha256: e.cert_sha256.clone(),
                insecure: e.insecure,
            })),
            OutboundKind::Http(_) | OutboundKind::Socks5(_) => None,
        }
    }

    /// Prefix for messages about this tunnel.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Awg { .. } => "WireGuard/AmneziaWG",
            Self::Sstp(_) => "SSTP",
        }
    }
}

pub struct TunnelProcess {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Lines<BufReader<ChildStdout>>,
    /// SOCKS5 endpoint of the tunnel, with its one-time credentials.
    pub endpoint: ProxyEndpoint,
    /// What it was started for, to tell whether a restart is needed.
    pub outbound_id: Uuid,
    pub spec: TunnelSpec,
    /// Interface pin (TUN mode) it was started with; a change restarts it.
    pub bind: (u32, u32),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Event {
    event: String,
    port: Option<u16>,
    message: Option<String>,
    last_handshake: Option<i64>,
    rx: Option<i64>,
    tx: Option<i64>,
}

#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelStatus {
    /// Unix seconds of the last sign of life from the server (WireGuard: the
    /// last handshake); 0 if it never answered.
    pub last_handshake: i64,
    pub rx: i64,
    pub tx: i64,
}

fn tunnel_path() -> Result<PathBuf, String> {
    // Tests run from target\debug\deps and point at the built tunnel explicitly.
    if let Some(path) = std::env::var_os("LOCALPROXY_TUNNEL") {
        return Ok(PathBuf::from(path));
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let path = exe.with_file_name(TUNNEL_EXE);
    if path.exists() {
        Ok(path)
    } else {
        Err(format!("не найден {TUNNEL_EXE} рядом с программой"))
    }
}

impl TunnelProcess {
    pub async fn start(outbound_id: Uuid, spec: &TunnelSpec) -> Result<Self, String> {
        let label = spec.label();
        let path = tunnel_path()?;
        let user = "localproxy".to_owned();
        let pass = Uuid::new_v4().simple().to_string();

        let mut command = Command::new(&path);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        // No console window flashing up.
        command.creation_flags(0x0800_0000);
        let mut child = command
            .spawn()
            .map_err(|e| format!("не удалось запустить {}: {e}", path.display()))?;

        let mut stdin = child.stdin.take().expect("piped");
        let stdout = child.stdout.take().expect("piped");
        if let Some(stderr) = child.stderr.take() {
            tokio::spawn(async move {
                let mut lines = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    tracing::warn!("tunnel: {line}");
                }
            });
        }

        let mut request = serde_json::to_value(spec).map_err(|e| e.to_string())?;
        request["user"] = user.clone().into();
        request["pass"] = pass.clone().into();
        let bind = proxy_core::bind::interface();
        request["bind"] = serde_json::json!({ "v4": bind.0, "v6": bind.1 });
        stdin
            .write_all(format!("{request}\n").as_bytes())
            .await
            .map_err(|e| format!("{label}: туннель не принял параметры: {e}"))?;

        let mut stdout = BufReader::new(stdout).lines();
        let first = timeout(START_TIMEOUT, stdout.next_line())
            .await
            .map_err(|_| format!("{label}: туннель не запустился вовремя"))?
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("{label}: туннель завершился, ничего не сообщив"))?;
        let event: Event = serde_json::from_str(&first)
            .map_err(|_| format!("{label}: непонятный ответ туннеля: {first}"))?;
        match (event.event.as_str(), event.port) {
            ("ready", Some(port)) => {
                tracing::info!(port, label, "tunnel ready");
                Ok(Self {
                    child,
                    stdin: Some(stdin),
                    stdout,
                    endpoint: ProxyEndpoint {
                        host: "127.0.0.1".into(),
                        port,
                        username: user,
                        password: pass,
                    },
                    outbound_id,
                    spec: spec.clone(),
                    bind,
                })
            }
            _ => Err(format!("{label}: {}", event.message.unwrap_or(first))),
        }
    }

    /// Last sign of life and traffic counters, straight from the tunnel.
    pub async fn status(&mut self) -> Result<TunnelStatus, String> {
        let stdin = self.stdin.as_mut().ok_or("остановлен")?;
        stdin
            .write_all(b"status\n")
            .await
            .map_err(|e| e.to_string())?;
        let line = timeout(Duration::from_secs(5), self.stdout.next_line())
            .await
            .map_err(|_| "туннель не ответил".to_owned())?
            .map_err(|e| e.to_string())?
            .ok_or("туннель завершился")?;
        let e: Event = serde_json::from_str(&line).map_err(|e| e.to_string())?;
        Ok(TunnelStatus {
            last_handshake: e.last_handshake.unwrap_or_default(),
            rx: e.rx.unwrap_or_default(),
            tx: e.tx.unwrap_or_default(),
        })
    }

    pub fn is_alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// Closing stdin asks the tunnel to shut down; killed if it lingers.
    pub async fn stop(mut self) {
        self.stdin.take();
        if timeout(STOP_TIMEOUT, self.child.wait()).await.is_err() {
            let _ = self.child.kill().await;
        }
    }
}

/// A tunnel the routing needs.
#[derive(Debug, Clone)]
pub struct Wanted {
    pub id: Uuid,
    pub name: String,
    pub spec: TunnelSpec,
}

/// Tunnels of the outbounds in use (the default one and those rules name);
/// `effective` is the config with presets expanded.
pub fn wanted(effective: &Config) -> Vec<Wanted> {
    effective
        .used_outbounds()
        .into_iter()
        .filter_map(|o| {
            TunnelSpec::of(o).map(|spec| Wanted {
                id: o.id,
                name: o.name.clone(),
                spec,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests;
