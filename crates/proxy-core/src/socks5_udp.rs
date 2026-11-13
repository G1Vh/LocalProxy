//! SOCKS5 UDP ASSOCIATE (RFC 1928, section 7).
//!
//! The client gets a relay socket on 127.0.0.1. Each datagram is routed like a
//! TCP connection: unmatched destinations go direct, matched ones through the
//! outbound, which must speak SOCKS5 (an upstream SOCKS5 proxy or the
//! WireGuard / SSTP tunnel). An HTTP proxy cannot carry UDP. The
//! association lives as long as the client's TCP control connection.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use uuid::Uuid;

use crate::config::{OnOutboundDown, RuleAction};
use crate::matcher::Decision;
use crate::outbound::{Upstream, socks5_addr, socks5_udp_associate};
use crate::router::{Inbound, RouteKind, Router, SELF_LOOP, Snapshot};
use crate::stream::TargetAddr;
use crate::traffic::Counters;

const MAX_DATAGRAM: usize = 65535;
/// Destinations remembered per association, only to log each one once.
const MAX_SEEN: usize = 1024;

/// Runs one association until the control connection closes.
pub(crate) async fn associate(
    mut control: TcpStream,
    router: Arc<Router>,
    process: Option<Arc<str>>,
) {
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
        process,
        tx,
        tasks: JoinSet::new(),
        direct: [None, None],
        upstreams: HashMap::new(),
        upstream_errors: HashMap::new(),
        seen: HashSet::new(),
        flows: HashMap::new(),
        replies: Arc::default(),
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
    /// Program behind the association (its control connection).
    process: Option<Arc<str>>,
    /// Datagrams for the client, already wrapped in the SOCKS5 UDP header.
    tx: mpsc::Sender<Vec<u8>>,
    tasks: JoinSet<()>,
    /// Direct sockets: [IPv4, IPv6].
    direct: [Option<Arc<UdpSocket>>; 2],
    /// One association per outbound in use.
    upstreams: HashMap<Uuid, UpstreamAssoc>,
    /// Why the outbound cannot carry UDP; not retried within this association.
    upstream_errors: HashMap<Uuid, String>,
    seen: HashSet<(String, u16)>,
    /// Traffic counters per destination and route.
    flows: HashMap<(String, u16, Option<Uuid>), Arc<Counters>>,
    /// Lets reply readers find whose traffic a reply is.
    replies: Arc<Mutex<Replies>>,
}

/// Replies come from addresses, not from the names the client asked for:
/// remember which counters each destination belongs to.
#[derive(Default)]
struct Replies {
    /// Direct: the resolved address we sent to.
    by_addr: HashMap<SocketAddr, Arc<Counters>>,
    /// Through the upstream: the destination as sent (name or IP).
    by_target: HashMap<(String, u16), Arc<Counters>>,
}

impl Replies {
    /// The upstream reports the source as an address even when we sent a
    /// name; then the port is the best clue, if only one destination has it.
    fn upstream_flow(&self, host: &str, port: u16) -> Option<Arc<Counters>> {
        if let Some(c) = self.by_target.get(&(host.to_owned(), port)) {
            return Some(c.clone());
        }
        let mut same_port = self.by_target.iter().filter(|((_, p), _)| *p == port);
        match (same_port.next(), same_port.next()) {
            (Some((_, c)), None) => Some(c.clone()),
            _ => None,
        }
    }
}

enum Path {
    Direct,
    Upstream(Uuid),
    Drop,
}

impl Association {
    async fn handle_client_datagram(&mut self, datagram: &[u8]) {
        let Some((target, payload)) = parse_udp_header(datagram) else {
            return;
        };
        let snap = self.router.snapshot();
        let decision = snap.rules.decide_for(&target.host, self.process.as_deref());
        let mut outbound_id = None;
        let (path, route, error) = match decision.action {
            RuleAction::Direct => (Path::Direct, RouteKind::Direct, None),
            RuleAction::Proxy => {
                let (id, ready) = self.ensure_upstream(&snap, &decision).await;
                outbound_id = id;
                match (id, ready) {
                    (Some(id), Ok(())) => (Path::Upstream(id), RouteKind::Proxy, None),
                    (_, ready) => {
                        let reason = ready.err().unwrap_or_default();
                        match snap.on_down {
                            OnOutboundDown::Block => (Path::Drop, RouteKind::Blocked, Some(reason)),
                            OnOutboundDown::Direct => {
                                (Path::Direct, RouteKind::Fallback, Some(reason))
                            }
                        }
                    }
                }
            }
        };

        if self.seen.len() >= MAX_SEEN {
            self.seen.clear();
        }
        if self.seen.insert((target.host.clone(), target.port)) {
            self.router.emit(
                Inbound::Udp,
                &target,
                route,
                decision.rule_id,
                outbound_id,
                self.process.as_deref(),
                error,
            );
        }

        if matches!(path, Path::Drop) {
            return;
        }
        let via = match path {
            Path::Upstream(id) => Some(id),
            _ => None,
        };
        if self.flows.len() >= MAX_SEEN {
            self.flows.clear();
        }
        let counters = self
            .flows
            .entry((target.host.clone(), target.port, via))
            .or_insert_with(|| self.router.traffic().open_udp(&target.host, via))
            .clone();
        counters.add_up(payload.len());
        match path {
            Path::Direct => self.send_direct(&target, payload, counters).await,
            Path::Upstream(id) => self.send_upstream(id, &target, payload, counters).await,
            Path::Drop => {}
        }
    }

    /// The decision's outbound, with its association opened if it can be.
    async fn ensure_upstream(
        &mut self,
        snap: &Snapshot,
        decision: &Decision,
    ) -> (Option<Uuid>, Result<(), String>) {
        let (id, upstream) = snap.outbound_for(decision);
        let Some(id) = id else {
            return (None, upstream.map(|_| ()));
        };
        if self.upstreams.contains_key(&id) {
            return (Some(id), Ok(()));
        }
        if let Some(e) = self.upstream_errors.get(&id) {
            return (Some(id), Err(e.clone()));
        }
        let result = match upstream {
            Err(e) => Err(e),
            Ok(u) if u.points_to(self.router.port()) => Err(SELF_LOOP.to_owned()),
            Ok(Upstream::Socks5(ep)) => match socks5_udp_associate(ep).await {
                Ok((control, relay)) => self.open_upstream(id, control, relay).await,
                Err(e) => Err(e.to_string()),
            },
            Ok(Upstream::Http(_)) => Err("UDP через HTTP-прокси не передаётся".to_owned()),
            Ok(Upstream::Tunnel) => Err("туннель не подключён".to_owned()),
        };
        if let Err(e) = &result {
            self.upstream_errors.insert(id, e.clone());
        }
        (Some(id), result)
    }

    async fn open_upstream(
        &mut self,
        id: Uuid,
        control: TcpStream,
        relay: SocketAddr,
    ) -> Result<(), String> {
        let any: SocketAddr = if relay.is_ipv4() {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        };
        let socket = UdpSocket::bind(any).await.map_err(|e| e.to_string())?;
        if !relay.ip().is_loopback() {
            crate::bind::pin_udp(&socket, relay.is_ipv6()).map_err(|e| e.to_string())?;
        }
        let socket = Arc::new(socket);
        let reader = socket.clone();
        let tx = self.tx.clone();
        let replies = self.replies.clone();
        self.tasks.spawn(async move {
            let mut buf = vec![0u8; MAX_DATAGRAM];
            while let Ok((n, from)) = reader.recv_from(&mut buf).await {
                if from.ip() != relay.ip() {
                    continue;
                }
                // Replies already carry the SOCKS5 UDP header with the source.
                if let Some((src, payload)) = parse_udp_header(&buf[..n]) {
                    let flow = lock(&replies).upstream_flow(&src.host, src.port);
                    if let Some(c) = flow {
                        c.add_down(payload.len());
                    }
                }
                if tx.send(buf[..n].to_vec()).await.is_err() {
                    break;
                }
            }
        });
        self.upstreams.insert(
            id,
            UpstreamAssoc {
                _control: control,
                socket,
                relay,
            },
        );
        Ok(())
    }

    async fn send_upstream(
        &mut self,
        id: Uuid,
        target: &TargetAddr,
        payload: &[u8],
        counters: Arc<Counters>,
    ) {
        let Some(up) = self.upstreams.get(&id) else {
            return;
        };
        {
            let mut replies = lock(&self.replies);
            if replies.by_target.len() >= MAX_SEEN {
                replies.by_target.clear();
            }
            replies
                .by_target
                .insert((target.host.clone(), target.port), counters);
        }
        let Some(addr) = socks5_addr(&target.host, target.port) else {
            return;
        };
        let mut datagram = Vec::with_capacity(3 + addr.len() + payload.len());
        datagram.extend_from_slice(&[0, 0, 0]);
        datagram.extend_from_slice(&addr);
        datagram.extend_from_slice(payload);
        let _ = up.socket.send_to(&datagram, up.relay).await;
    }

    async fn send_direct(&mut self, target: &TargetAddr, payload: &[u8], counters: Arc<Counters>) {
        let Some(dest) = resolve(target).await else {
            return;
        };
        {
            let mut replies = lock(&self.replies);
            if replies.by_addr.len() >= MAX_SEEN {
                replies.by_addr.clear();
            }
            replies.by_addr.insert(canonical(dest), counters);
        }
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
        let socket = UdpSocket::bind(any).await.ok()?;
        crate::bind::pin_udp(&socket, v6).ok()?;
        let socket = Arc::new(socket);
        let reader = socket.clone();
        let tx = self.tx.clone();
        let replies = self.replies.clone();
        self.tasks.spawn(async move {
            let mut buf = vec![0u8; MAX_DATAGRAM];
            while let Ok((n, from)) = reader.recv_from(&mut buf).await {
                let flow = lock(&replies).by_addr.get(&canonical(from)).cloned();
                if let Some(c) = flow {
                    c.add_down(n);
                }
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

fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

fn lock(replies: &Mutex<Replies>) -> std::sync::MutexGuard<'_, Replies> {
    replies.lock().unwrap_or_else(|e| e.into_inner())
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
mod tests;
