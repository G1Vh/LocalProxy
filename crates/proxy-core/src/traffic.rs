//! Bytes per host, counted live as data flows (a long video stream shows up
//! while it plays, not when it ends). TCP: CONNECT tunnels, plain HTTP and
//! SOCKS5 CONNECT; UDP: SOCKS5 UDP ASSOCIATE, one "connection" per
//! destination of an association.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use uuid::Uuid;

#[derive(Debug, Default)]
pub struct Counters {
    up: AtomicU64,
    down: AtomicU64,
    connections: AtomicU64,
    last_ms: AtomicU64,
}

impl Counters {
    pub(crate) fn add_up(&self, n: usize) {
        self.up.fetch_add(n as u64, Ordering::Relaxed);
        self.last_ms.store(now_ms(), Ordering::Relaxed);
    }

    pub(crate) fn add_down(&self, n: usize) {
        self.down.fetch_add(n as u64, Ordering::Relaxed);
        self.last_ms.store(now_ms(), Ordering::Relaxed);
    }
}

/// Totals for one host and route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostTraffic {
    pub host: String,
    /// Through an outbound (true) or direct (false).
    pub via_outbound: bool,
    /// Which outbound, when through one.
    pub outbound_id: Option<Uuid>,
    /// UDP (SOCKS5 UDP ASSOCIATE) rather than TCP.
    pub udp: bool,
    pub up: u64,
    pub down: u64,
    pub connections: u64,
    pub last_ms: u64,
}

/// Host, outbound (`None`: direct), UDP.
type FlowKey = (String, Option<Uuid>, bool);

/// All counters; shared by the router and whoever shows them.
#[derive(Debug, Default)]
pub struct Traffic {
    hosts: Mutex<HashMap<FlowKey, Arc<Counters>>>,
}

impl Traffic {
    /// Counters for a new TCP connection to `host`; the connection is counted now.
    pub fn open(&self, host: &str, outbound: Option<Uuid>) -> Arc<Counters> {
        self.open_flow(host, outbound, false)
    }

    /// Counters for a new UDP destination of an association.
    pub fn open_udp(&self, host: &str, outbound: Option<Uuid>) -> Arc<Counters> {
        self.open_flow(host, outbound, true)
    }

    fn open_flow(&self, host: &str, outbound: Option<Uuid>, udp: bool) -> Arc<Counters> {
        let counters = self
            .hosts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry((host.to_owned(), outbound, udp))
            .or_default()
            .clone();
        counters.connections.fetch_add(1, Ordering::Relaxed);
        counters.last_ms.store(now_ms(), Ordering::Relaxed);
        counters
    }

    /// Busiest hosts first.
    pub fn snapshot(&self) -> Vec<HostTraffic> {
        let mut rows: Vec<HostTraffic> = self
            .hosts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|((host, outbound, udp), c)| HostTraffic {
                host: host.clone(),
                via_outbound: outbound.is_some(),
                outbound_id: *outbound,
                udp: *udp,
                up: c.up.load(Ordering::Relaxed),
                down: c.down.load(Ordering::Relaxed),
                connections: c.connections.load(Ordering::Relaxed),
                last_ms: c.last_ms.load(Ordering::Relaxed),
            })
            .collect();
        rows.sort_by(|a, b| {
            (b.up + b.down)
                .cmp(&(a.up + a.down))
                .then(a.host.cmp(&b.host))
        });
        rows
    }

    /// Forgets everything; connections still open keep counting into
    /// counters nobody shows any more, which is fine.
    pub fn reset(&self) {
        self.hosts.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }
}

/// A stream that adds what passes through it to a host's counters:
/// reads are "down" (from the far end), writes are "up".
pub struct Counted<S> {
    inner: S,
    counters: Arc<Counters>,
}

impl<S> Counted<S> {
    pub fn new(inner: S, counters: Arc<Counters>) -> Self {
        Self { inner, counters }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        let n = buf.filled().len() - before;
        if n > 0 {
            self.counters.add_down(n);
        }
        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &poll {
            self.counters.add_up(*n);
        }
        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn counts_both_directions_per_host_and_route() {
        let traffic = Traffic::default();
        let (a, mut b) = tokio::io::duplex(64);
        let vpn = Some(Uuid::new_v4());
        let mut counted = Counted::new(a, traffic.open("example.com", vpn));
        counted.write_all(b"hello").await.unwrap();
        b.write_all(b"world!!").await.unwrap();
        let mut buf = [0u8; 7];
        counted.read_exact(&mut buf).await.unwrap();
        traffic.open("example.com", vpn);
        traffic.open("example.com", None);
        traffic.open_udp("example.com", vpn).add_down(3);
        traffic.open("example.com", Some(Uuid::new_v4()));

        let rows = traffic.snapshot();
        let proxied = rows
            .iter()
            .find(|r| r.outbound_id == vpn && !r.udp)
            .unwrap();
        assert_eq!(
            rows.iter().filter(|r| r.via_outbound && !r.udp).count(),
            2,
            "each outbound counts apart"
        );
        assert_eq!((proxied.up, proxied.down, proxied.connections), (5, 7, 2));
        let direct = rows.iter().find(|r| !r.via_outbound).unwrap();
        let udp = rows.iter().find(|r| r.udp).unwrap();
        assert_eq!(
            (udp.down, udp.connections),
            (3, 1),
            "UDP is kept apart from TCP"
        );
        assert_eq!((direct.up, direct.down, direct.connections), (0, 0, 1));
        assert_eq!(rows[0], *proxied, "busiest first");

        traffic.reset();
        assert!(traffic.snapshot().is_empty());
    }
}
