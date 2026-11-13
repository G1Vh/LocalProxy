//! The WireGuard / AmneziaWG bridge process (`awg-bridge.exe`, see the
//! `awg-bridge` folder): a userspace tunnel exposed as SOCKS5 on loopback.
//!
//! The core never deals with WireGuard: while a bridge runs, the AWG outbound
//! is handed to it as a SOCKS5 outbound pointing at the bridge.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use proxy_core::config::{Config, OutboundKind, ProxyEndpoint};
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::time::timeout;
use uuid::Uuid;

/// Resolving the server name and building the tunnel takes a moment.
const START_TIMEOUT: Duration = Duration::from_secs(20);
const STOP_TIMEOUT: Duration = Duration::from_secs(3);
const BRIDGE_EXE: &str = "awg-bridge.exe";

pub struct AwgProcess {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Lines<BufReader<ChildStdout>>,
    /// SOCKS5 endpoint of the bridge, with its one-time credentials.
    pub endpoint: ProxyEndpoint,
    /// What it was started for, to tell whether a restart is needed.
    pub outbound_id: Uuid,
    pub conf: String,
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
pub struct BridgeStatus {
    /// Unix seconds of the last handshake; 0 if the server never answered.
    pub last_handshake: i64,
    pub rx: i64,
    pub tx: i64,
}

fn bridge_path() -> Result<PathBuf, String> {
    // Tests run from targetdebugdeps and point at the built bridge explicitly.
    if let Some(path) = std::env::var_os("LOCALPROXY_AWG_BRIDGE") {
        return Ok(PathBuf::from(path));
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let path = exe.with_file_name(BRIDGE_EXE);
    if path.exists() {
        Ok(path)
    } else {
        Err(format!("не найден {} рядом с программой", BRIDGE_EXE))
    }
}

impl AwgProcess {
    pub async fn start(outbound_id: Uuid, conf: &str) -> Result<Self, String> {
        let path = bridge_path()?;
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
                    tracing::warn!("awg-bridge: {line}");
                }
            });
        }

        let request = serde_json::json!({ "conf": conf, "user": user, "pass": pass });
        stdin
            .write_all(format!("{request}\n").as_bytes())
            .await
            .map_err(|e| format!("awg-bridge не принял параметры: {e}"))?;

        let mut stdout = BufReader::new(stdout).lines();
        let first = timeout(START_TIMEOUT, stdout.next_line())
            .await
            .map_err(|_| "WireGuard/AmneziaWG: туннель не запустился вовремя".to_owned())?
            .map_err(|e| e.to_string())?
            .ok_or("awg-bridge завершился, ничего не сообщив")?;
        let event: Event = serde_json::from_str(&first)
            .map_err(|_| format!("непонятный ответ awg-bridge: {first}"))?;
        match (event.event.as_str(), event.port) {
            ("ready", Some(port)) => {
                tracing::info!(port, "awg-bridge ready");
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
                    conf: conf.to_owned(),
                })
            }
            _ => Err(format!(
                "WireGuard/AmneziaWG: {}",
                event.message.unwrap_or(first)
            )),
        }
    }

    /// Handshake time and traffic counters, straight from the tunnel.
    pub async fn status(&mut self) -> Result<BridgeStatus, String> {
        let stdin = self.stdin.as_mut().ok_or("остановлен")?;
        stdin
            .write_all(b"status\n")
            .await
            .map_err(|e| e.to_string())?;
        let line = timeout(Duration::from_secs(5), self.stdout.next_line())
            .await
            .map_err(|_| "awg-bridge не ответил".to_owned())?
            .map_err(|e| e.to_string())?
            .ok_or("awg-bridge завершился")?;
        let e: Event = serde_json::from_str(&line).map_err(|e| e.to_string())?;
        Ok(BridgeStatus {
            last_handshake: e.last_handshake.unwrap_or_default(),
            rx: e.rx.unwrap_or_default(),
            tx: e.tx.unwrap_or_default(),
        })
    }

    pub fn is_alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// Closing stdin asks the bridge to shut down; killed if it lingers.
    pub async fn stop(mut self) {
        self.stdin.take();
        if timeout(STOP_TIMEOUT, self.child.wait()).await.is_err() {
            let _ = self.child.kill().await;
        }
    }
}

/// The active outbound's AWG config, if the active outbound is WireGuard/AmneziaWG.
pub fn wanted(config: &Config) -> Option<(Uuid, &str)> {
    let outbound = config.active_outbound()?;
    match &outbound.kind {
        OutboundKind::Awg { config } => Some((outbound.id, config.as_str())),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONF: &str = "[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.8.1.2/32
Jc = 3
Jmin = 10
Jmax = 30

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = 127.0.0.1:9
AllowedIPs = 0.0.0.0/0
";

    /// Points the code at the bridge built by `pnpm build:bridge`.
    fn use_built_bridge() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("binaries")
            .join("awg-bridge-x86_64-pc-windows-msvc.exe");
        assert!(
            path.exists(),
            "{} is missing: run `pnpm build:bridge` first",
            path.display()
        );
        // SAFETY: every test here sets the same value.
        unsafe { std::env::set_var("LOCALPROXY_AWG_BRIDGE", path) };
    }

    #[tokio::test]
    async fn bridge_starts_reports_status_and_stops() {
        use_built_bridge();
        let id = Uuid::new_v4();
        let mut bridge = AwgProcess::start(id, CONF).await.unwrap();
        assert!(bridge.endpoint.port > 0);
        assert_eq!(bridge.endpoint.host, "127.0.0.1");
        assert!(!bridge.endpoint.password.is_empty());
        let status = bridge.status().await.unwrap();
        assert_eq!(status.last_handshake, 0, "nobody listens on 127.0.0.1:9");
        assert!(bridge.is_alive());
        let port = bridge.endpoint.port;
        bridge.stop().await;
        assert!(
            tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_err(),
            "the bridge must be gone after stop"
        );
    }

    #[tokio::test]
    async fn bad_config_is_reported() {
        use_built_bridge();
        let err = AwgProcess::start(Uuid::new_v4(), "[Interface]\nAddress = 10.0.0.2/32\n")
            .await
            .err()
            .unwrap();
        assert!(err.contains("PrivateKey"), "{err}");
    }
}
