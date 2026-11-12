//! Decides where a connection goes and opens it, applying the on-outbound-down policy.

use std::fmt;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::config::{Config, OnOutboundDown, RuleAction};
use crate::matcher::RuleSet;
use crate::outbound::{ConnectError, Upstream, basic_auth, connect_direct, connect_server};
use crate::stream::{BoxIo, TargetAddr};

const EVENT_BUFFER: usize = 1024;

/// Everything routing needs, rebuilt on each config change and swapped atomically.
#[derive(Debug)]
pub struct Snapshot {
    pub rules: RuleSet,
    pub upstream: Option<Upstream>,
    pub on_down: OnOutboundDown,
    pub socks5_enabled: bool,
}

impl Snapshot {
    pub fn from_config(config: &Config) -> Self {
        Self {
            rules: RuleSet::new(&config.rules),
            upstream: config
                .active_outbound()
                .map(|o| Upstream::from_kind(&o.kind)),
            on_down: config.on_outbound_down,
            socks5_enabled: config.socks5_enabled,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Inbound {
    /// Plain HTTP request in absolute form.
    Http,
    /// HTTP CONNECT tunnel.
    Connect,
    Socks5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RouteKind {
    Direct,
    Proxy,
    /// Matched a proxy rule, outbound was down, policy allowed going direct.
    Fallback,
    /// Matched a proxy rule, outbound was down, policy blocked it.
    Blocked,
    Failed,
}

/// One connection attempt, for the live feed in the UI.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnEvent {
    /// Unix time, milliseconds.
    pub at_ms: u64,
    pub inbound: Inbound,
    pub host: String,
    pub port: u16,
    pub route: RouteKind,
    pub rule_id: Option<Uuid>,
    pub error: Option<String>,
}

#[derive(Debug)]
pub enum RouteError {
    /// Outbound is down and the policy says block.
    Blocked(String),
    Failed(ConnectError),
}

impl fmt::Display for RouteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Blocked(reason) => {
                write!(
                    f,
                    "заблокировано: {reason}; домен идёт только через outbound"
                )
            }
            Self::Failed(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for RouteError {}

/// How the plain-HTTP forwarder has to talk over the stream it was given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpHop {
    /// Stream reaches the origin: send origin-form requests.
    Origin,
    /// Stream reaches an upstream HTTP proxy: send absolute-form requests.
    Proxy { authorization: Option<String> },
}

pub struct Router {
    snapshot: RwLock<Arc<Snapshot>>,
    events: broadcast::Sender<ConnEvent>,
}

impl Router {
    pub fn new(config: &Config) -> Self {
        Self {
            snapshot: RwLock::new(Arc::new(Snapshot::from_config(config))),
            events: broadcast::channel(EVENT_BUFFER).0,
        }
    }

    pub fn update(&self, config: &Config) {
        let snapshot = Arc::new(Snapshot::from_config(config));
        *self.snapshot.write().unwrap_or_else(|e| e.into_inner()) = snapshot;
    }

    pub fn snapshot(&self) -> Arc<Snapshot> {
        self.snapshot
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ConnEvent> {
        self.events.subscribe()
    }

    /// A TCP tunnel to `target`.
    pub async fn connect(
        &self,
        target: &TargetAddr,
        inbound: Inbound,
    ) -> Result<BoxIo, RouteError> {
        self.route(target, inbound, false).await.map(|(io, _)| io)
    }

    /// A stream for forwarding plain HTTP to `target`. Through an HTTP upstream
    /// this is a connection to the proxy itself, not a CONNECT tunnel: many
    /// proxies only allow CONNECT to port 443.
    pub async fn connect_http(&self, target: &TargetAddr) -> Result<(BoxIo, HttpHop), RouteError> {
        self.route(target, Inbound::Http, true).await
    }

    async fn route(
        &self,
        target: &TargetAddr,
        inbound: Inbound,
        plain_http: bool,
    ) -> Result<(BoxIo, HttpHop), RouteError> {
        let snap = self.snapshot();
        let decision = snap.rules.decide(&target.host);

        let result = match decision.action {
            RuleAction::Direct => direct(target, RouteKind::Direct).await,
            RuleAction::Proxy => {
                let attempt = match &snap.upstream {
                    None => Err(ConnectError::OutboundDown("outbound не выбран".into())),
                    Some(Upstream::Http(ep)) if plain_http => {
                        connect_server(ep).await.map(|s| -> (BoxIo, HttpHop) {
                            (
                                Box::new(s),
                                HttpHop::Proxy {
                                    authorization: basic_auth(ep),
                                },
                            )
                        })
                    }
                    Some(upstream) => upstream
                        .connect(target)
                        .await
                        .map(|io| (io, HttpHop::Origin)),
                };
                match attempt {
                    Ok(hop) => Ok((hop, RouteKind::Proxy)),
                    Err(e) if e.is_outbound_down() => match snap.on_down {
                        OnOutboundDown::Block => Err(RouteError::Blocked(e.to_string())),
                        OnOutboundDown::Direct => {
                            tracing::warn!(%target, "{e}; going direct by policy");
                            direct(target, RouteKind::Fallback).await
                        }
                    },
                    Err(e) => Err(RouteError::Failed(e)),
                }
            }
        };

        let (route, error) = match &result {
            Ok((_, route)) => (*route, None),
            Err(e @ RouteError::Blocked(_)) => (RouteKind::Blocked, Some(e.to_string())),
            Err(e @ RouteError::Failed(_)) => (RouteKind::Failed, Some(e.to_string())),
        };
        tracing::debug!(%target, ?inbound, ?route, error = error.as_deref().unwrap_or(""), "route");
        // No subscribers is fine.
        let _ = self.events.send(ConnEvent {
            at_ms: now_ms(),
            inbound,
            host: target.host.clone(),
            port: target.port,
            route,
            rule_id: decision.rule_id,
            error,
        });

        result.map(|(hop, _)| hop)
    }
}

async fn direct(
    target: &TargetAddr,
    kind: RouteKind,
) -> Result<((BoxIo, HttpHop), RouteKind), RouteError> {
    connect_direct(target)
        .await
        .map(|s| ((Box::new(s) as BoxIo, HttpHop::Origin), kind))
        .map_err(RouteError::Failed)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}
