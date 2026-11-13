//! Ways out: direct TCP, upstream HTTP proxy (CONNECT), upstream SOCKS5 proxy.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::config::{OutboundKind, ProxyEndpoint};
use crate::stream::{BoxIo, Prefixed, TargetAddr};

/// TCP connect timeout, for both targets and upstream proxies.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long an upstream proxy may take to answer a handshake.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_RESPONSE_HEAD: usize = 16 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    /// The outbound itself cannot be used: unreachable, timed out, bad credentials,
    /// broken handshake or not configured. Subject to the on-outbound-down policy.
    #[error("outbound недоступен: {0}")]
    OutboundDown(String),
    /// The outbound works but could not reach the target.
    #[error("outbound не смог подключиться к {target}: {reason}")]
    Rejected { target: String, reason: String },
    /// Direct connection to the target failed.
    #[error("не удалось подключиться к {target}: {source}")]
    Target {
        target: String,
        #[source]
        source: io::Error,
    },
}

impl ConnectError {
    pub fn is_outbound_down(&self) -> bool {
        matches!(self, Self::OutboundDown(_))
    }

    /// The I/O error kind behind a failure, for protocol-specific error codes.
    pub fn io_kind(&self) -> Option<io::ErrorKind> {
        match self {
            Self::Target { source, .. } => Some(source.kind()),
            _ => None,
        }
    }
}

/// Opens a TCP connection straight to the target.
pub async fn connect_direct(target: &TargetAddr) -> Result<TcpStream, ConnectError> {
    let err = |source| ConnectError::Target {
        target: target.to_string(),
        source,
    };
    let stream = timeout(
        CONNECT_TIMEOUT,
        TcpStream::connect((target.host.as_str(), target.port)),
    )
    .await
    .map_err(|_| err(io::ErrorKind::TimedOut.into()))?
    .map_err(err)?;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

/// A configured upstream that tunnels TCP for us.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Upstream {
    Http(ProxyEndpoint),
    Socks5(ProxyEndpoint),
    /// A tunnel outbound (WireGuard, SSTP) whose tunnel process is not
    /// running: every attempt reports the outbound as down. While it runs,
    /// the app hands the core a SOCKS5 outbound pointing at it instead.
    Tunnel,
}

impl Upstream {
    pub fn from_kind(kind: &OutboundKind) -> Self {
        match kind {
            OutboundKind::Http(ep) => Self::Http(ep.clone()),
            OutboundKind::Socks5(ep) => Self::Socks5(ep.clone()),
            OutboundKind::Awg { .. } | OutboundKind::Sstp(_) => Self::Tunnel,
        }
    }

    /// True if this upstream is a loopback address on `port`, i.e. our own listener.
    pub fn points_to(&self, port: u16) -> bool {
        let (Self::Http(ep) | Self::Socks5(ep)) = self else {
            return false;
        };
        let host = ep.host.trim().trim_start_matches('[').trim_end_matches(']');
        ep.port == port
            && (host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback() || ip.is_unspecified()))
    }

    /// A raw TCP tunnel to `target` through this upstream.
    pub async fn connect(&self, target: &TargetAddr) -> Result<BoxIo, ConnectError> {
        match self {
            Self::Http(ep) => {
                let stream = connect_server(ep).await?;
                http_connect(stream, ep, target).await
            }
            Self::Socks5(ep) => {
                let stream = connect_server(ep).await?;
                socks5_connect(stream, ep, target).await
            }
            Self::Tunnel => Err(ConnectError::OutboundDown("туннель не подключён".into())),
        }
    }
}

/// TCP connection to an upstream proxy server itself.
pub async fn connect_server(ep: &ProxyEndpoint) -> Result<TcpStream, ConnectError> {
    let addr = TargetAddr::new(ep.host.clone(), ep.port);
    if ep.host.trim().is_empty() || ep.port == 0 {
        return Err(ConnectError::OutboundDown("не указан адрес".into()));
    }
    connect_direct(&addr).await.map_err(|e| match e {
        ConnectError::Target { target, source } => {
            ConnectError::OutboundDown(format!("{target}: {source}"))
        }
        other => other,
    })
}

/// `Proxy-Authorization` value for an endpoint with credentials.
pub fn basic_auth(ep: &ProxyEndpoint) -> Option<String> {
    if ep.username.is_empty() && ep.password.is_empty() {
        return None;
    }
    let token = base64::engine::general_purpose::STANDARD
        .encode(format!("{}:{}", ep.username, ep.password));
    Some(format!("Basic {token}"))
}

async fn http_connect(
    mut stream: TcpStream,
    ep: &ProxyEndpoint,
    target: &TargetAddr,
) -> Result<BoxIo, ConnectError> {
    let mut request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let Some(auth) = basic_auth(ep) {
        request.push_str(&format!("Proxy-Authorization: {auth}\r\n"));
    }
    request.push_str("\r\n");

    let handshake = async {
        stream.write_all(request.as_bytes()).await?;
        read_response_head(&mut stream).await
    };
    let (head, rest) = timeout(HANDSHAKE_TIMEOUT, handshake)
        .await
        .map_err(|_| ConnectError::OutboundDown("HTTP-прокси не ответил на CONNECT".into()))?
        .map_err(|e| ConnectError::OutboundDown(format!("HTTP-прокси: {e}")))?;

    let status_line = head.lines().next().unwrap_or_default();
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| ConnectError::OutboundDown(format!("непонятный ответ: {status_line}")))?;
    match status {
        200..=299 => Ok(Box::new(Prefixed::new(rest, stream))),
        407 => Err(ConnectError::OutboundDown(
            "HTTP-прокси требует авторизацию или отверг логин/пароль (407)".into(),
        )),
        _ => Err(ConnectError::Rejected {
            target: target.to_string(),
            reason: status_line.to_owned(),
        }),
    }
}

/// Reads up to the end of the response head; returns it and any bytes after it.
async fn read_response_head(stream: &mut TcpStream) -> io::Result<(String, Vec<u8>)> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "соединение закрыто до конца заголовков",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let rest = buf.split_off(end + 4);
            return Ok((String::from_utf8_lossy(&buf).into_owned(), rest));
        }
        if buf.len() > MAX_RESPONSE_HEAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "слишком длинные заголовки ответа",
            ));
        }
    }
}

async fn socks5_connect(
    mut stream: TcpStream,
    ep: &ProxyEndpoint,
    target: &TargetAddr,
) -> Result<BoxIo, ConnectError> {
    socks5_handshake(&mut stream, ep, SOCKS5_CONNECT, target).await?;
    Ok(Box::new(stream))
}

const SOCKS5_CONNECT: u8 = 1;
const SOCKS5_UDP_ASSOCIATE: u8 = 3;

/// Opens a UDP association on an upstream SOCKS5 proxy. Returns the control
/// connection (the association lives while it is open) and the relay address
/// to send datagrams to.
pub async fn socks5_udp_associate(
    ep: &ProxyEndpoint,
) -> Result<(TcpStream, SocketAddr), ConnectError> {
    let mut stream = connect_server(ep).await?;
    let any = TargetAddr::new("0.0.0.0", 0);
    let bound = socks5_handshake(&mut stream, ep, SOCKS5_UDP_ASSOCIATE, &any).await?;
    let relay = match bound {
        // "Same host as the TCP connection" is common for 0.0.0.0.
        Some(addr) if !addr.ip().is_unspecified() => addr,
        Some(addr) => SocketAddr::new(
            stream
                .peer_addr()
                .map_err(|e| ConnectError::OutboundDown(e.to_string()))?
                .ip(),
            addr.port(),
        ),
        None => {
            return Err(ConnectError::OutboundDown(
                "SOCKS5-прокси вернул имя вместо адреса для UDP".into(),
            ));
        }
    };
    Ok((stream, relay))
}

/// SOCKS5 address field (ATYP + address + port). Host names are sent as names,
/// so the far end resolves them. `None` if a name is longer than 255 bytes.
pub fn socks5_addr(host: &str, port: u16) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(4 + host.len() + 2);
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            out.push(1);
            out.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            out.push(4);
            out.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            let name = host.as_bytes();
            out.push(3);
            out.push(u8::try_from(name.len()).ok()?);
            out.extend_from_slice(name);
        }
    }
    out.extend_from_slice(&port.to_be_bytes());
    Some(out)
}

/// Greeting, optional username/password auth and one request. Returns the
/// bound address from the reply (`None` if the server gave a name).
async fn socks5_handshake(
    stream: &mut TcpStream,
    ep: &ProxyEndpoint,
    command: u8,
    target: &TargetAddr,
) -> Result<Option<SocketAddr>, ConnectError> {
    let down = |msg: String| ConnectError::OutboundDown(format!("SOCKS5-прокси: {msg}"));
    let handshake = async {
        let with_auth = !ep.username.is_empty() || !ep.password.is_empty();
        let greeting: &[u8] = if with_auth { &[5, 2, 0, 2] } else { &[5, 1, 0] };
        stream.write_all(greeting).await?;
        let mut reply = [0u8; 2];
        stream.read_exact(&mut reply).await?;
        if reply[0] != 5 {
            return Ok(Err(down("не SOCKS5-сервер".into())));
        }
        match reply[1] {
            0 => {}
            2 => {
                let (user, pass) = (ep.username.as_bytes(), ep.password.as_bytes());
                if user.len() > 255 || pass.len() > 255 {
                    return Ok(Err(down("логин или пароль длиннее 255 байт".into())));
                }
                let mut auth = vec![1, user.len() as u8];
                auth.extend_from_slice(user);
                auth.push(pass.len() as u8);
                auth.extend_from_slice(pass);
                stream.write_all(&auth).await?;
                let mut status = [0u8; 2];
                stream.read_exact(&mut status).await?;
                if status[1] != 0 {
                    return Ok(Err(down("неверный логин или пароль".into())));
                }
            }
            _ => return Ok(Err(down("сервер не принял способ авторизации".into()))),
        }

        let Some(addr) = socks5_addr(&target.host, target.port) else {
            return Ok(Err(ConnectError::Rejected {
                target: target.to_string(),
                reason: "имя хоста длиннее 255 байт".into(),
            }));
        };
        let mut request = vec![5, command, 0];
        request.extend_from_slice(&addr);
        stream.write_all(&request).await?;

        let mut head = [0u8; 4];
        stream.read_exact(&mut head).await?;
        let bound = match head[3] {
            1 => {
                let mut ip = [0u8; 4];
                stream.read_exact(&mut ip).await?;
                let port = stream.read_u16().await?;
                Some(SocketAddr::from((ip, port)))
            }
            4 => {
                let mut ip = [0u8; 16];
                stream.read_exact(&mut ip).await?;
                let port = stream.read_u16().await?;
                Some(SocketAddr::from((ip, port)))
            }
            3 => {
                let len = stream.read_u8().await? as usize;
                let mut skip = vec![0u8; len + 2];
                stream.read_exact(&mut skip).await?;
                None
            }
            other => return Ok(Err(down(format!("неизвестный тип адреса {other}")))),
        };
        if head[1] != 0 {
            return Ok(Err(ConnectError::Rejected {
                target: target.to_string(),
                reason: socks5_reply_text(head[1]).into(),
            }));
        }
        Ok::<Result<Option<SocketAddr>, ConnectError>, io::Error>(Ok(bound))
    };

    timeout(HANDSHAKE_TIMEOUT, handshake)
        .await
        .map_err(|_| down("не ответил вовремя".into()))?
        .map_err(|e: io::Error| match e.kind() {
            // E.g. the WireGuard/AmneziaWG bridge when its server does not answer.
            io::ErrorKind::UnexpectedEof => {
                down("закрыл соединение без ответа (сервер за ним недоступен?)".into())
            }
            _ => down(e.to_string()),
        })?
}

fn socks5_reply_text(code: u8) -> &'static str {
    match code {
        1 => "общая ошибка сервера",
        2 => "запрещено правилами сервера",
        3 => "сеть недоступна",
        4 => "хост недоступен",
        5 => "в соединении отказано",
        6 => "истёк TTL",
        7 => "команда не поддерживается",
        8 => "тип адреса не поддерживается",
        _ => "неизвестная ошибка",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_auth_header() {
        let mut ep = ProxyEndpoint {
            host: "h".into(),
            port: 1,
            ..Default::default()
        };
        assert_eq!(basic_auth(&ep), None);
        ep.username = "user".into();
        ep.password = "p@ss:word".into();
        assert_eq!(basic_auth(&ep).unwrap(), "Basic dXNlcjpwQHNzOndvcmQ=");
    }
}
