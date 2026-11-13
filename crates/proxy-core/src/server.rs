//! Listener on 127.0.0.1 and [::1]: sniffs the first byte and hands the
//! connection to the SOCKS5 or HTTP inbound.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::config::Config;
use crate::forward::{ForwardStatus, Forwards};
use crate::router::{ConnEvent, Router};
use crate::traffic::Traffic;
use crate::{http_inbound, socks5_inbound};

/// A client that connects and stays silent is dropped after this long.
const FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(30);
const STOP_GRACE: Duration = Duration::from_secs(3);

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("порт {0} уже занят другой программой")]
    PortBusy(u16),
    #[error("не удалось открыть порт {port}: {source}")]
    Bind {
        port: u16,
        #[source]
        source: io::Error,
    },
}

pub struct ProxyServer {
    router: Arc<Router>,
    forwards: Forwards,
    port: u16,
    cancel: CancellationToken,
    tracker: TaskTracker,
}

/// What a connection handler needs: the router and a way to spawn background
/// work (tunnels, upstream connections) that dies when the server stops.
#[derive(Clone)]
pub(crate) struct ConnCtx {
    pub router: Arc<Router>,
    cancel: CancellationToken,
    tracker: TaskTracker,
}

impl ConnCtx {
    pub fn spawn<F>(&self, fut: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let cancel = self.cancel.clone();
        self.tracker.spawn(async move {
            tokio::select! {
                _ = cancel.cancelled() => {}
                _ = fut => {}
            }
        });
    }
}

impl ProxyServer {
    /// Binds and starts serving. Port 0 picks a free port (used by tests).
    pub async fn start(config: &Config) -> Result<Self, ServerError> {
        Self::start_with_traffic(config, Arc::default()).await
    }

    /// Like [`ProxyServer::start`], counting into existing totals (so they
    /// survive a restart, e.g. a port change).
    pub async fn start_with_traffic(
        config: &Config,
        traffic: Arc<Traffic>,
    ) -> Result<Self, ServerError> {
        let v4 = TcpListener::bind((Ipv4Addr::LOCALHOST, config.port))
            .await
            .map_err(|source| match source.kind() {
                io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied => {
                    ServerError::PortBusy(config.port)
                }
                _ => ServerError::Bind {
                    port: config.port,
                    source,
                },
            })?;
        let port = v4.local_addr().map_or(config.port, |a| a.port());
        // Some clients resolve "localhost" to ::1 first; serve it too when possible.
        let v6 = match TcpListener::bind((Ipv6Addr::LOCALHOST, port)).await {
            Ok(listener) => Some(listener),
            Err(e) => {
                tracing::warn!("[::1]:{port} unavailable, IPv4 only: {e}");
                None
            }
        };

        let router = Arc::new(Router::new(config, port, traffic));
        let cancel = CancellationToken::new();
        let tracker = TaskTracker::new();
        let ctx = ConnCtx {
            router: router.clone(),
            cancel: cancel.clone(),
            tracker: tracker.clone(),
        };
        for listener in std::iter::once(v4).chain(v6) {
            tracker.spawn(accept_loop(listener, ctx.clone()));
        }
        tracing::info!(port, "proxy listening");
        let forwards = Forwards::new(router.clone(), tracker.clone(), cancel.clone());
        forwards.update(&config.forwards);
        Ok(Self {
            router,
            forwards,
            port,
            cancel,
            tracker,
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn local_addr(&self) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, self.port))
    }

    /// Applies new rules / outbounds / policy to new connections and opens
    /// or closes forwarded ports. Changing the proxy port needs a restart.
    pub fn update(&self, config: &Config) {
        self.router.update(config);
        self.forwards.update(&config.forwards);
    }

    /// State of each enabled port forward.
    pub fn forward_status(&self) -> Vec<ForwardStatus> {
        self.forwards.status()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ConnEvent> {
        self.router.subscribe()
    }

    /// Bytes per host counted by this server.
    pub fn traffic(&self) -> Arc<Traffic> {
        self.router.traffic()
    }

    /// URL of the PAC for the current rules. The `v` parameter changes with the
    /// content, so Windows fetches a fresh copy after every rule change.
    pub fn pac_url(&self) -> String {
        format!(
            "http://127.0.0.1:{}{}?v={}",
            self.port,
            crate::pac::PAC_PATH,
            self.router.snapshot().pac_version
        )
    }

    /// Stops listening and closes every open connection.
    pub async fn stop(self) {
        self.cancel.cancel();
        self.tracker.close();
        if timeout(STOP_GRACE, self.tracker.wait()).await.is_err() {
            tracing::warn!("some connections did not close in time");
        }
        tracing::info!(port = self.port, "proxy stopped");
    }
}

impl Drop for ProxyServer {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

async fn accept_loop(listener: TcpListener, ctx: ConnCtx) {
    loop {
        tokio::select! {
            _ = ctx.cancel.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, _peer)) => ctx.spawn(handle(stream, ctx.clone())),
                Err(e) => {
                    // E.g. out of sockets: back off instead of spinning.
                    tracing::warn!("accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            },
        }
    }
}

async fn handle(stream: TcpStream, ctx: ConnCtx) {
    let _ = stream.set_nodelay(true);
    let mut first = [0u8; 1];
    match timeout(FIRST_BYTE_TIMEOUT, stream.peek(&mut first)).await {
        Ok(Ok(n)) if n > 0 => {}
        _ => return,
    }
    if first[0] == 5 {
        if ctx.router.snapshot().socks5_enabled {
            socks5_inbound::serve(stream, ctx.router).await;
        }
    } else {
        http_inbound::serve(stream, ctx).await;
    }
}
