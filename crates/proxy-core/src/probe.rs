//! "Check" button: can we get out through this outbound, how fast, and with
//! what external IP.

use std::net::IpAddr;
use std::time::Instant;

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use crate::outbound::{ConnectError, HANDSHAKE_TIMEOUT, Upstream, basic_auth, connect_server};
use crate::stream::{BoxIo, TargetAddr};

/// Plain-HTTP service that answers with the caller's IP as text.
pub const IP_SERVICE_HOST: &str = "api.ipify.org";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Probe {
    /// Time to open a connection through the outbound, handshake included.
    pub latency_ms: u64,
    /// Address the outside world sees; `None` if the IP service gave no usable answer.
    pub external_ip: Option<String>,
}

pub async fn probe(upstream: &Upstream) -> Result<Probe, ConnectError> {
    probe_at(upstream, &TargetAddr::new(IP_SERVICE_HOST, 80), "/").await
}

/// [`probe`] against any plain-HTTP endpoint that returns an IP (used by tests).
pub async fn probe_at(
    upstream: &Upstream,
    target: &TargetAddr,
    path: &str,
) -> Result<Probe, ConnectError> {
    let started = Instant::now();
    let host = &target.host;
    let (mut io, mut request): (BoxIo, String) = match upstream {
        // Absolute-form through an HTTP proxy, like a browser would.
        Upstream::Http(ep) => {
            let stream = connect_server(ep).await?;
            let mut request = format!("GET http://{target}{path} HTTP/1.1\r\nHost: {host}\r\n");
            if let Some(auth) = basic_auth(ep) {
                request.push_str(&format!("Proxy-Authorization: {auth}\r\n"));
            }
            (Box::new(stream), request)
        }
        other => (
            other.connect(target).await?,
            format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n"),
        ),
    };
    let latency_ms = started.elapsed().as_millis() as u64;
    request.push_str("User-Agent: LocalProxy\r\nConnection: close\r\n\r\n");

    let exchange = async {
        io.write_all(request.as_bytes()).await?;
        let mut response = Vec::new();
        io.take(16 * 1024).read_to_end(&mut response).await?;
        Ok::<_, std::io::Error>(response)
    };
    let response = timeout(HANDSHAKE_TIMEOUT, exchange)
        .await
        .map_err(|_| ConnectError::OutboundDown("сервис проверки IP не ответил вовремя".into()))?
        .map_err(|e| ConnectError::OutboundDown(format!("обмен с сервисом проверки IP: {e}")))?;

    let text = String::from_utf8_lossy(&response);
    let status = text.split_whitespace().nth(1).unwrap_or_default();
    if status == "407" {
        return Err(ConnectError::OutboundDown(
            "HTTP-прокси требует авторизацию или отверг логин/пароль (407)".into(),
        ));
    }
    let external_ip = (status == "200")
        .then(|| text.split("\r\n\r\n").nth(1))
        .flatten()
        .map(str::trim)
        .filter(|body| body.parse::<IpAddr>().is_ok())
        .map(str::to_owned);
    Ok(Probe {
        latency_ms,
        external_ip,
    })
}

/// Where the health check connects: a well-known anycast address, so the
/// check needs no DNS and works through any outbound.
pub const HEALTH_TARGET: (&str, u16) = ("1.1.1.1", 443);

/// Light liveness check for the outbound: opens (and drops) one TCP
/// connection through it. Only failures of the outbound itself count; an
/// upstream that answers but refuses this target is alive.
pub async fn health_check(upstream: &Upstream) -> Result<(), String> {
    let target = TargetAddr::new(HEALTH_TARGET.0, HEALTH_TARGET.1);
    match upstream.connect(&target).await {
        Ok(_) => Ok(()),
        Err(e) if e.is_outbound_down() => Err(e.to_string()),
        Err(_) => Ok(()),
    }
}
