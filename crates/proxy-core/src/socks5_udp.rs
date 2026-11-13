//! SOCKS5 UDP ASSOCIATE (RFC 1928, section 7).
//!
//! The client gets a relay socket on 127.0.0.1. Each datagram is routed like a
//! TCP connection: unmatched destinations go direct, matched ones through the
//! outbound, which must speak SOCKS5 (an upstream SOCKS5 proxy or the
//! WireGuard/AmneziaWG bridge). An HTTP proxy cannot carry UDP. The
//! association lives as long as the client's TCP control connection.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use crate::config::{OnOutboundDown, RuleAction};
use crate::outbound::{Upstream, socks5_addr, socks5_udp_associate};
use crate::router::{Inbound, RouteKind, Router, SELF_LOOP, Snapshot};
use crate::stream::TargetAddr;

const MAX_DATAGRAM: usize = 65535;
/// Destinations remembered per association, only to log each one once.
const MAX_SEEN: usize = 1024;

/// Runs one association until the control connection closes.
pub(crate) async fn associate(mut control: TcpStream, router: Arc<Router>) {
    let relay = match UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("cannot bind UDP relay: {e}");
            let _ = control.write_all(&[5, 1, 0, 1, 0, 0, 0, 0, 0, 0]).await;
            return;
        }
    };
    let Ok(bound) = relay.local_addr() else {
        return;
    };
    let mut reply = vec![5, 0, 0];
    reply.extend_from_slice(&udp_header(bound)[3..]);
    if control.write_all(&reply).await.is_err() {
        return;
    }

    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);
    let mut assoc = Association {
        router,
        tx,
        tasks: JoinSet::new(),
        direct: [None, None],
        upstream: None,
        upstream_error: None,
        seen: HashSet::new(),
    };
    let mut client: Option<SocketAddr> = None;
    let mut buf = vec![0u8; MAX_DATAGRAM];
    let mut control_buf = [0u8; 64];
    loop {
        tokio::select! {
            read = control.read(&mut control_buf) => match read {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            },
            received = relay.recv_from(&mut buf) => {
                let Ok((n, from)) = received else { break };
                // The relay is on loopback; anything else is not our client.
                if !from.ip().is_loopback() {
                    continue;
                }
                client = Some(from);
                assoc.handle_client_datagram(&buf[..n]).await;
            }
            Some(datagram) = rx.recv() => {
                if let Some(client) = client {
                    let _ = relay.send_to(&datagram, client).await;
                }
            }
        }
    }
    // Dropping `assoc` aborts its reader tasks and closes the sockets.
}

struct UpstreamAssoc {
    /// The upstream keeps the association while this connection is open.
    _control: TcpStream,
    socket: Arc<UdpSocket>,
    relay: SocketAddr,
}

struct Association {
    router: Arc<Router>,
    /// Datagrams for the client, already wrapped in the SOCKS5 UDP header.
    tx: mpsc::Sender<Vec<u8>>,
    tasks: JoinSet<()>,
    /// Direct sockets: [IPv4, IPv6].
    direct: [Option<Arc<UdpSocket>>; 2],
    upstream: Option<UpstreamAssoc>,
    /// Why the outbound cannot carry UDP; not retried within this association.
    upstream_error: Option<String>,
    seen: HashSet<(String, u16)>,
}

enum Path {
    Direct,
    Upstream,
    Drop,
}

impl Association {
    async fn handle_client_datagram(&mut self, datagram: &[u8]) {
        let Some((target, payload)) = parse_udp_header(datagram) else {
            return;
        };
        let snap = self.router.snapshot();
        let decision = snap.rules.decide(&target.host);
        let (path, route, error) = match decision.action {
            RuleAction::Direct => (Path::Direct, RouteKind::Direct, None),
            RuleAction::Proxy => match self.ensure_upstream(&snap).await {
                Ok(()) => (Path::Upstream, RouteKind::Proxy, None),
                Err(reason) => match snap.on_down {
                    OnOutboundDown::Block => (Path::Drop, RouteKind::Blocked, Some(reason)),
                    OnOutboundDown::Direct => (Path::Direct, RouteKind::Fallback, Some(reason)),
                },
            },
        };

        if self.seen.len() >= MAX_SEEN {
            self.seen.clear();
        }
        if self.seen.insert((target.host.clone(), target.port)) {
            self.router
                .emit(Inbound::Udp, &target, route, decision.rule_id, error);
        }

        match path {
            Path::Direct => self.send_direct(&target, payload).await,
            Path::Upstream => self.send_upstream(&target, payload).await,
            Path::Drop => {}
        }
    }

    async fn ensure_upstream(&mut self, snap: &Snapshot) -> Result<(), String> {
        if self.upstream.is_some() {
            return Ok(());
        }
        if let Some(e) = &self.upstream_error {
            return Err(e.clone());
        }
        let result = match &snap.upstream {
            None => Err("outbound не выбран".to_owned()),
            Some(u) if u.points_to(self.router.port()) => Err(SELF_LOOP.to_owned()),
            Some(Upstream::Socks5(ep)) => match socks5_udp_associate(ep).await {
                Ok((control, relay)) => self.open_upstream(control, relay).await,
                Err(e) => Err(e.to_string()),
            },
            Some(Upstream::Http(_)) => Err("UDP через HTTP-прокси не передаётся".to_owned()),
            Some(Upstream::Awg) => Err("WireGuard/AmneziaWG не подключён".to_owned()),
        };
        if let Err(e) = &result {
            self.upstream_error = Some(e.clone());
        }
        result
    }

    async fn open_upstream(&mut self, control: TcpStream, relay: SocketAddr) -> Result<(), String> {
        let any: SocketAddr = if relay.is_ipv4() {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        };
        let socket = Arc::new(UdpSocket::bind(any).await.map_err(|e| e.to_string())?);
        let reader = socket.clone();
        let tx = self.tx.clone();
        self.tasks.spawn(async move {
            let mut buf = vec![0u8; MAX_DATAGRAM];
            while let Ok((n, from)) = reader.recv_from(&mut buf).await {
                // Replies already carry the SOCKS5 UDP header with the source.
                if from.ip() == relay.ip() && tx.send(buf[..n].to_vec()).await.is_err() {
                    break;
                }
            }
        });
        self.upstream = Some(UpstreamAssoc {
            _control: control,
            socket,
            relay,
        });
        Ok(())
    }

    async fn send_upstream(&mut self, target: &TargetAddr, payload: &[u8]) {
        let Some(up) = &self.upstream else { return };
        let Some(addr) = socks5_addr(&target.host, target.port) else {
            return;
        };
        let mut datagram = Vec::with_capacity(3 + addr.len() + payload.len());
        datagram.extend_from_slice(&[0, 0, 0]);
        datagram.extend_from_slice(&addr);
        datagram.extend_from_slice(payload);
        let _ = up.socket.send_to(&datagram, up.relay).await;
    }

    async fn send_direct(&mut self, target: &TargetAddr, payload: &[u8]) {
        let Some(dest) = resolve(target).await else {
            return;
        };
        let Some(socket) = self.direct_socket(dest.is_ipv6()).await else {
            return;
        };
        let _ = socket.send_to(payload, dest).await;
    }

    async fn direct_socket(&mut self, v6: bool) -> Option<Arc<UdpSocket>> {
        let slot = usize::from(v6);
        if let Some(s) = &self.direct[slot] {
            return Some(s.clone());
        }
        let any: SocketAddr = if v6 {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        };
        let socket = Arc::new(UdpSocket::bind(any).await.ok()?);
        let reader = socket.clone();
        let tx = self.tx.clone();
        self.tasks.spawn(async move {
            let mut buf = vec![0u8; MAX_DATAGRAM];
            while let Ok((n, from)) = reader.recv_from(&mut buf).await {
                let mut datagram = udp_header(from);
                datagram.extend_from_slice(&buf[..n]);
                if tx.send(datagram).await.is_err() {
                    break;
                }
            }
        });
        self.direct[slot] = Some(socket.clone());
        Some(socket)
    }
}

async fn resolve(target: &TargetAddr) -> Option<SocketAddr> {
    if let Ok(ip) = target.host.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, target.port));
    }
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((target.host.as_str(), target.port))
        .await
        .ok()?
        .collect();
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or(addrs.first())
        .copied()
}

/// `RSV RSV FRAG ATYP ADDR PORT` for a source address.
fn udp_header(addr: SocketAddr) -> Vec<u8> {
    let mut h = vec![0, 0, 0];
    match addr.ip().to_canonical() {
        IpAddr::V4(ip) => {
            h.push(1);
            h.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            h.push(4);
            h.extend_from_slice(&ip.octets());
        }
    }
    h.extend_from_slice(&addr.port().to_be_bytes());
    h
}

/// Splits a client datagram into its destination and payload. Fragmented
/// datagrams (FRAG != 0) are not supported and dropped, as the RFC allows.
fn parse_udp_header(d: &[u8]) -> Option<(TargetAddr, &[u8])> {
    if d.len() < 4 || d[2] != 0 {
        return None;
    }
    let (host, rest) = match d[3] {
        1 => {
            let ip: [u8; 4] = d.get(4..8)?.try_into().ok()?;
            (Ipv4Addr::from(ip).to_string(), &d[8..])
        }
        4 => {
            let ip: [u8; 16] = d.get(4..20)?.try_into().ok()?;
            (Ipv6Addr::from(ip).to_string(), &d[20..])
        }
        3 => {
            let len = *d.get(4)? as usize;
            let name = d.get(5..5 + len)?;
            (String::from_utf8_lossy(name).into_owned(), &d[5 + len..])
        }
        _ => return None,
    };
    let port = u16::from_be_bytes(rest.get(..2)?.try_into().ok()?);
    Some((TargetAddr::new(host, port), &rest[2..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let addr: SocketAddr = "203.0.113.7:5353".parse().unwrap();
        let mut d = udp_header(addr);
        d.extend_from_slice(b"hi");
        let (target, payload) = parse_udp_header(&d).unwrap();
        assert_eq!(target, TargetAddr::new("203.0.113.7", 5353));
        assert_eq!(payload, b"hi");

        let mut named = vec![0, 0, 0, 3, 9];
        named.extend_from_slice(b"localhost");
        named.extend_from_slice(&53u16.to_be_bytes());
        named.extend_from_slice(b"q");
        let (target, payload) = parse_udp_header(&named).unwrap();
        assert_eq!(target, TargetAddr::new("localhost", 53));
        assert_eq!(payload, b"q");

        let v6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let (target, _) = parse_udp_header(&udp_header(v6)).unwrap();
        assert_eq!(target, TargetAddr::new("2001:db8::1", 443));
    }

    #[test]
    fn rejects_fragments_and_garbage() {
        assert!(parse_udp_header(&[0, 0, 1, 1, 1, 2, 3, 4, 0, 53]).is_none());
        assert!(parse_udp_header(&[0, 0, 0, 1, 1, 2]).is_none());
        assert!(parse_udp_header(&[0, 0, 0, 3, 20, b'a']).is_none());
        assert!(parse_udp_header(&[0, 0, 0, 9]).is_none());
    }
}
