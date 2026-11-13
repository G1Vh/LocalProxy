//! Port forwards: `127.0.0.1:local_port` leads to a fixed address through an
//! outbound, for programs that cannot use a proxy (database clients, RDP,
//! SSH). Each connection is a CONNECT through the outbound; if it is down the
//! connection is closed, never sent direct.

use std::collections::HashMap;
use std::io;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use serde::Serialize;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use uuid::Uuid;

use crate::config::PortForward;
use crate::router::Router;
use crate::stream::TargetAddr;

/// A port just released (the forward was removed and added again) may take a
/// moment to free up.
const BIND_ATTEMPTS: u32 = 10;
const BIND_RETRY: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", tag = "state")]
pub enum ForwardState {
    Starting,
    Listening,
    Failed { reason: String },
}

/// What the window shows for a forward.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ForwardStatus {
    pub id: Uuid,
    #[serde(flatten)]
    pub state: ForwardState,
    /// Connections accepted since the forward started listening.
    pub connections: u64,
}

struct Running {
    port: u16,
    /// Target and outbound, changeable without reopening the port.
    spec: Arc<RwLock<PortForward>>,
    state: Arc<Mutex<ForwardState>>,
    connections: Arc<AtomicU64>,
    cancel: CancellationToken,
}

/// The listeners of all enabled forwards; lives inside the proxy server.
pub(crate) struct Forwards {
    router: Arc<Router>,
    tracker: TaskTracker,
    parent: CancellationToken,
    running: Mutex<HashMap<Uuid, Running>>,
}

impl Forwards {
    pub fn new(router: Arc<Router>, tracker: TaskTracker, parent: CancellationToken) -> Self {
        Self {
            router,
            tracker,
            parent,
            running: Mutex::default(),
        }
    }

    /// Opens, closes or retargets listeners to match `forwards`.
    pub fn update(&self, forwards: &[PortForward]) {
        let wanted: HashMap<Uuid, &PortForward> = forwards
            .iter()
            .filter(|f| f.enabled && f.local_port != 0)
            .map(|f| (f.id, f))
            .collect();
        let mut running = self.running.lock().unwrap_or_else(|e| e.into_inner());
        running.retain(|id, r| {
            let keep = wanted.get(id).is_some_and(|f| f.local_port == r.port);
            if !keep {
                r.cancel.cancel();
            }
            keep
        });
        for (id, forward) in wanted {
            if let Some(r) = running.get(&id) {
                *r.spec.write().unwrap_or_else(|e| e.into_inner()) = forward.clone();
                continue;
            }
            let r = Running {
                port: forward.local_port,
                spec: Arc::new(RwLock::new(forward.clone())),
                state: Arc::new(Mutex::new(ForwardState::Starting)),
                connections: Arc::default(),
                cancel: self.parent.child_token(),
            };
            self.tracker.spawn(listen(
                r.port,
                r.spec.clone(),
                r.state.clone(),
                r.connections.clone(),
                r.cancel.clone(),
                self.router.clone(),
                self.tracker.clone(),
            ));
            running.insert(id, r);
        }
    }

    pub fn status(&self) -> Vec<ForwardStatus> {
        let running = self.running.lock().unwrap_or_else(|e| e.into_inner());
        running
            .iter()
            .map(|(id, r)| ForwardStatus {
                id: *id,
                state: r.state.lock().unwrap_or_else(|e| e.into_inner()).clone(),
                connections: r.connections.load(Ordering::Relaxed),
            })
            .collect()
    }
}

async fn bind(port: u16) -> io::Result<TcpListener> {
    let mut attempt = 0;
    loop {
        match TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await {
            Ok(l) => return Ok(l),
            Err(e) if e.kind() == io::ErrorKind::AddrInUse && attempt + 1 < BIND_ATTEMPTS => {
                attempt += 1;
                tokio::time::sleep(BIND_RETRY).await;
            }
            Err(e) => return Err(e),
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn listen(
    port: u16,
    spec: Arc<RwLock<PortForward>>,
    state: Arc<Mutex<ForwardState>>,
    connections: Arc<AtomicU64>,
    cancel: CancellationToken,
    router: Arc<Router>,
    tracker: TaskTracker,
) {
    let set = |s: ForwardState| *state.lock().unwrap_or_else(|e| e.into_inner()) = s;
    let listener = tokio::select! {
        _ = cancel.cancelled() => return,
        bound = bind(port) => match bound {
            Ok(l) => l,
            Err(e) => {
                let reason = match e.kind() {
                    io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied => {
                        format!("порт {port} уже занят другой программой")
                    }
                    _ => format!("не удалось открыть порт {port}: {e}"),
                };
                tracing::warn!(port, "forward: {reason}");
                set(ForwardState::Failed { reason });
                return;
            }
        },
    };
    set(ForwardState::Listening);
    tracing::info!(port, "forward listening");
    loop {
        let stream = tokio::select! {
            _ = cancel.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => stream,
                Err(e) => {
                    tracing::warn!(port, "forward accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        connections.fetch_add(1, Ordering::Relaxed);
        let forward = spec.read().unwrap_or_else(|e| e.into_inner()).clone();
        let (router, cancel) = (router.clone(), cancel.clone());
        tracker.spawn(async move {
            tokio::select! {
                _ = cancel.cancelled() => {}
                _ = serve(stream, forward, router) => {}
            }
        });
    }
    tracing::info!(port, "forward closed");
}

async fn serve(mut client: TcpStream, forward: PortForward, router: Arc<Router>) {
    let _ = client.set_nodelay(true);
    let target = TargetAddr::new(forward.target_host.clone(), forward.target_port);
    match router.connect_forward(&target, forward.outbound).await {
        Ok(mut upstream) => {
            let _ = copy_bidirectional(&mut client, &mut upstream).await;
        }
        Err(e) => tracing::debug!(%target, "forward refused: {e}"),
    }
}
