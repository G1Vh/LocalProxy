//! MCP server for AI agents (Claude Code, Claude Desktop and others): the
//! state, the connection feed and checks to read; rules, presets, channels
//! and settings to change. Everything goes through the same functions as the
//! window, so a change made here shows there at once and the other way round.
//!
//! Streamable HTTP on 127.0.0.1 only. Off by default (Settings). Requests
//! need `Authorization: Bearer <token>`; requests from a web page (any
//! `Origin`) and to a foreign `Host` are refused, so a site cannot reach the
//! server through the browser (DNS rebinding).

use std::convert::Infallible;
use std::io;
use std::net::Ipv4Addr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::AUTHORIZATION;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use proxy_core::ConnEvent;
use proxy_core::config::{
    Config, MatchType, McpSettings, Outbound, OutboundKind, Rule, RuleAction,
};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{ServerCapabilities, ServerConfig};
use rmcp::transport::streamable_http_server::session::SessionManager;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{ServerHandler, schemars, tool, tool_handler, tool_router};
use serde::Deserialize;
use serde_json::{Value, json};
use tauri::{AppHandle, Manager};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::commands::{apply_config, set_enabled_inner};
use crate::state::AppState;

/// Feed entries an agent may ask for at once.
const MAX_CONNECTIONS: usize = 1000;
const DEFAULT_CONNECTIONS: usize = 50;

/// The running server; dropped (stopped) when MCP is switched off.
pub struct McpServer {
    port: u16,
    token: String,
    cancel: CancellationToken,
    task: JoinHandle<()>,
}

impl McpServer {
    pub async fn start(app: AppHandle, port: u16, token: String) -> io::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await?;
        let cancel = CancellationToken::new();
        let service = StreamableHttpService::new(
            move || Ok(Tools::new(app.clone())),
            Arc::new(LocalSessionManager::default()),
            http_config(&cancel),
        );
        let task = tokio::spawn(serve(listener, service, token.clone(), cancel.clone()));
        tracing::info!(port, "MCP server listening");
        Ok(Self {
            port,
            token,
            cancel,
            task,
        })
    }

    pub async fn stop(self) {
        self.cancel.cancel();
        let _ = self.task.await;
        tracing::info!(port = self.port, "MCP server stopped");
    }
}

type Service = StreamableHttpService<Tools, LocalSessionManager>;

/// Loopback `Host` only (the transport's default) and no `Origin` at all:
/// programs may call, web pages may not.
pub(crate) fn http_config(cancel: &CancellationToken) -> StreamableHttpServerConfig {
    let mut config = StreamableHttpServerConfig::default()
        .enforce_origin_validation()
        .with_json_response(true);
    config.cancellation_token = cancel.child_token();
    config
}

async fn serve(listener: TcpListener, service: Service, token: String, cancel: CancellationToken) {
    let token: Arc<str> = token.into();
    loop {
        let stream = tokio::select! {
            _ = cancel.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => stream,
                Err(e) => {
                    tracing::warn!("MCP accept failed: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        let (service, token, cancel) = (service.clone(), token.clone(), cancel.clone());
        tokio::spawn(async move {
            let handler = service_fn(move |req: Request<Incoming>| {
                let (service, token) = (service.clone(), token.clone());
                async move { Ok::<_, Infallible>(handle(&service, &token, req).await) }
            });
            let conn = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), handler);
            tokio::select! {
                _ = cancel.cancelled() => {}
                _ = conn => {}
            }
        });
    }
}

/// One HTTP request: the token first, then the MCP transport (which checks
/// `Host` and `Origin` itself).
pub(crate) async fn handle<S, M, B>(
    service: &StreamableHttpService<S, M>,
    token: &str,
    req: Request<B>,
) -> Response<BoxBody<Bytes, Infallible>>
where
    S: ServerHandler + Send + 'static,
    M: SessionManager,
    B: hyper::body::Body + Send + 'static,
    B::Data: Send + 'static,
    B::Error: std::fmt::Display,
{
    if !authorized(&req, token) {
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("WWW-Authenticate", "Bearer")
            .body(
                Full::new(Bytes::from_static(
                    b"LocalProxy MCP: wrong or missing token",
                ))
                .boxed(),
            )
            .expect("static response");
    }
    service.handle(req).await
}

pub(crate) fn authorized<B>(req: &Request<B>, token: &str) -> bool {
    !token.is_empty()
        && req
            .headers()
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .is_some_and(|t| t.trim() == token)
}

/// Brings the server in line with the settings: starts, stops or restarts it.
pub async fn sync(app: &AppHandle, settings: &McpSettings) {
    let state = app.state::<AppState>();
    let mut slot = state.mcp.lock().await;
    let wanted = settings
        .enabled
        .then(|| (settings.port, settings.token.clone()));
    let running = slot.as_ref().map(|s| (s.port, s.token.clone()));
    if wanted == running && (wanted.is_none() || state.mcp_error().is_none()) {
        return;
    }
    if let Some(server) = slot.take() {
        server.stop().await;
    }
    *state.mcp_error() = None;
    let Some((port, token)) = wanted else {
        return;
    };
    match McpServer::start(app.clone(), port, token).await {
        Ok(server) => *slot = Some(server),
        Err(e) => {
            let reason = if e.kind() == io::ErrorKind::AddrInUse {
                format!("порт {port} уже занят другой программой")
            } else {
                format!("не удалось открыть порт {port}: {e}")
            };
            tracing::warn!("MCP: {reason}");
            *state.mcp_error() = Some(reason);
        }
    }
}

/// A token for a newly enabled server: 32 random hex digits.
pub fn new_token() -> String {
    Uuid::new_v4().simple().to_string()
}

/// The settings to start with; a server switched on by hand in config.json
/// gets its token here (and saved), as switching it on in the window does.
pub fn settings_at_startup(state: &AppState) -> McpSettings {
    let mut config = state.config();
    if config.mcp.enabled && config.mcp.token.is_empty() {
        config.mcp.token = new_token();
        if let Err(e) = config.save(&state.config_path) {
            tracing::warn!("cannot save the MCP token: {e}");
        }
    }
    config.mcp.clone()
}

/// The command that connects Claude Code to the server.
pub fn claude_command(settings: &McpSettings) -> String {
    format!(
        "claude mcp add --scope user --transport http localproxy {} --header \"Authorization: Bearer {}\"",
        url(settings.port),
        settings.token
    )
}

pub fn url(port: u16) -> String {
    format!("http://127.0.0.1:{port}/mcp")
}

// ---------- tools ----------

#[derive(Clone)]
pub struct Tools {
    app: AppHandle,
    tool_router: ToolRouter<Self>,
}

type ToolResult = Result<String, String>;

fn pretty(v: &Value) -> ToolResult {
    serde_json::to_string_pretty(v).map_err(|e| e.to_string())
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct EnabledArgs {
    /// true: route traffic by the rules; false: everything goes direct.
    pub enabled: bool,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct ModeArgs {
    /// "tun": the whole system's traffic through a virtual adapter (all
    /// programs); "proxy": the Windows system proxy (programs that use it).
    pub mode: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct HostArgs {
    /// A host name, IP address or URL.
    pub host: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct ConnectionsArgs {
    /// How many of the newest entries (default 50, at most 1000).
    pub limit: Option<usize>,
    /// Only entries whose host, program or error contains this text.
    pub filter: Option<String>,
    /// Only failed or blocked connections.
    pub errors_only: Option<bool>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct LimitArgs {
    /// How many entries, busiest first (default 50).
    pub limit: Option<usize>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct RuleAddArgs {
    /// Domain (openai.com), mask (*.corp.example), subnet (149.154.160.0/20),
    /// URL, or program (discord.exe, a mask or a full path).
    pub pattern: String,
    /// "domainAndSubdomains", "exact", "mask", "cidr" or "process"; guessed
    /// from the pattern when omitted.
    pub match_type: Option<String>,
    /// "proxy" (through a channel, the default) or "direct" (an exception).
    pub action: Option<String>,
    /// Channel name or id for a proxy rule; the default channel when omitted.
    pub channel: Option<String>,
    pub comment: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct RuleRemoveArgs {
    /// The rule's pattern as rules_list shows it, or its id.
    pub pattern: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct PresetArgs {
    /// Preset id from presets_list.
    pub id: String,
    /// Subscribe (true) or unsubscribe (false); unchanged when omitted.
    pub selected: Option<bool>,
    /// Channel name or id for the preset, or "default".
    pub channel: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct ChannelArgs {
    /// Channel name or id.
    pub channel: String,
}

#[tool_router]
impl Tools {
    pub fn new(app: AppHandle) -> Self {
        Self {
            app,
            tool_router: Self::tool_router(),
        }
    }

    fn state(&self) -> tauri::State<'_, AppState> {
        self.app.state::<AppState>()
    }

    async fn apply(&self, config: Config) -> Result<(), String> {
        apply_config(&self.app, &self.state(), config)
            .await
            .map(|_| ())
    }

    #[tool(
        description = "LocalProxy state: on/off, mode (TUN or system proxy), default channel, \
        channels with their health, selected presets, TUN statistics, version and start errors."
    )]
    async fn status(&self) -> ToolResult {
        let state = self.state();
        let config = state.config().clone();
        let health = state.health().clone();
        let tun = crate::ui_commands::get_tun_status(state.clone())
            .await
            .ok()
            .flatten();
        pretty(&json!({
            "version": self.app.package_info().version.to_string(),
            "enabled": config.enabled,
            "mode": if config.tun_enabled { "tun" } else { "proxy" },
            "port": config.port,
            "defaultChannel": channel_name(&config, config.active_outbound_id),
            "health": health.overall,
            "channels": config.outbounds.iter().map(|o| json!({
                "id": o.id,
                "name": o.name,
                "type": kind(&o.kind),
                "default": Some(o.id) == config.active_outbound_id,
                "health": health.outbounds.get(&o.id),
            })).collect::<Vec<_>>(),
            "presets": config.presets,
            "rules": config.rules.len(),
            "tun": tun,
            "startError": state.start_error(),
        }))
    }

    #[tool(description = "Switch routing on or off.")]
    async fn set_enabled(&self, Parameters(args): Parameters<EnabledArgs>) -> ToolResult {
        let config = set_enabled_inner(&self.app, &self.state(), args.enabled).await?;
        Ok(format!("enabled: {}", config.enabled))
    }

    #[tool(
        description = "Choose the mode: \"tun\" (all traffic of the system) or \"proxy\" \
        (Windows system proxy only)."
    )]
    async fn set_mode(&self, Parameters(args): Parameters<ModeArgs>) -> ToolResult {
        let tun = match args.mode.as_str() {
            "tun" => true,
            "proxy" => false,
            other => {
                return Err(format!(
                    "unknown mode \"{other}\": use \"tun\" or \"proxy\""
                ));
            }
        };
        let mut config = self.state().config().clone();
        config.tun_enabled = tun;
        self.apply(config).await?;
        Ok(format!("mode: {}", args.mode))
    }

    #[tool(
        description = "Where a host or URL would go with the current rules and presets, \
        and by which rule."
    )]
    async fn check_host(&self, Parameters(args): Parameters<HostArgs>) -> ToolResult {
        let state = self.state();
        let check = crate::ui_commands::check_host(state.clone(), args.host)?;
        let config = state.config().clone();
        pretty(&json!({
            "host": check.host,
            "action": check.action,
            "channel": channel_name(&config, check.outbound_id),
            "rule": rule_label(&state, &config, check.rule_id),
        }))
    }

    #[tool(
        description = "The connection feed, newest first: host, port, program, route \
        (direct, proxy, fallback, blocked, failed), channel, matched rule and error. Entries hidden \
        in the window are included."
    )]
    async fn connections(&self, Parameters(args): Parameters<ConnectionsArgs>) -> ToolResult {
        let state = self.state();
        let config = state.config().clone();
        let limit = args
            .limit
            .unwrap_or(DEFAULT_CONNECTIONS)
            .min(MAX_CONNECTIONS);
        let events = state.recent_events();
        let picked = filter_events(
            &events,
            args.filter.as_deref(),
            args.errors_only.unwrap_or(false),
            limit,
        );
        pretty(&Value::Array(
            picked
                .into_iter()
                .map(|e| {
                    json!({
                        "atMs": e.at_ms,
                        "inbound": e.inbound,
                        "host": e.host,
                        "port": e.port,
                        "route": e.route,
                        "channel": channel_name(&config, e.outbound_id),
                        "rule": rule_label(&state, &config, e.rule_id),
                        "process": e.process,
                        "error": e.error,
                    })
                })
                .collect(),
        ))
    }

    #[tool(
        description = "Traffic per host since start, busiest first: bytes up and down, \
        connections, TCP or UDP, through which channel."
    )]
    async fn traffic(&self, Parameters(args): Parameters<LimitArgs>) -> ToolResult {
        let state = self.state();
        let config = state.config().clone();
        let rows = state.traffic.snapshot();
        pretty(&Value::Array(
            rows.into_iter()
                .take(args.limit.unwrap_or(DEFAULT_CONNECTIONS))
                .map(|r| {
                    json!({
                        "host": r.host,
                        "udp": r.udp,
                        "channel": channel_name(&config, r.outbound_id),
                        "up": r.up,
                        "down": r.down,
                        "connections": r.connections,
                    })
                })
                .collect(),
        ))
    }

    #[tool(description = "The user's own rules (presets are separate, see presets_list).")]
    async fn rules_list(&self) -> ToolResult {
        let state = self.state();
        let config = state.config().clone();
        let hits = state.rule_stats().clone();
        pretty(&Value::Array(
            config
                .rules
                .iter()
                .map(|r| {
                    json!({
                        "id": r.id,
                        "pattern": r.pattern,
                        "matchType": r.match_type,
                        "action": r.action,
                        "channel": (r.action == RuleAction::Proxy)
                            .then(|| channel_name(&config, r.outbound.or(config.active_outbound_id)))
                            .flatten(),
                        "enabled": r.enabled,
                        "comment": r.comment,
                        "hits": hits.get(&r.id).map(|s| s.hits),
                    })
                })
                .collect(),
        ))
    }

    #[tool(
        description = "Add a rule: a domain, mask, subnet or program through a channel \
        (action \"proxy\") or as a direct exception (action \"direct\")."
    )]
    async fn rule_add(&self, Parameters(args): Parameters<RuleAddArgs>) -> ToolResult {
        let mut config = self.state().config().clone();
        let (pattern, match_type) = match args.match_type.as_deref() {
            Some(t) => {
                let match_type = parse_match_type(t)?;
                let pattern = proxy_core::matcher::normalize_pattern(&args.pattern, match_type)
                    .map_err(|e| e.to_string())?;
                (pattern, match_type)
            }
            None => crate::rules::classify(&args.pattern).ok_or_else(|| {
                format!(
                    "не похоже на домен, маску, подсеть или программу: {}",
                    args.pattern
                )
            })?,
        };
        let action = match args.action.as_deref().unwrap_or("proxy") {
            "proxy" => RuleAction::Proxy,
            "direct" => RuleAction::Direct,
            other => {
                return Err(format!(
                    "unknown action \"{other}\": use \"proxy\" or \"direct\""
                ));
            }
        };
        let outbound = match (&action, args.channel.as_deref()) {
            (RuleAction::Proxy, Some(c)) if c != "default" => Some(find_channel(&config, c)?.id),
            _ => None,
        };
        if config
            .rules
            .iter()
            .any(|r| r.pattern == pattern && r.match_type == match_type)
        {
            return Err(format!("такое правило уже есть: {pattern}"));
        }
        let rule = Rule {
            id: Uuid::new_v4(),
            enabled: true,
            pattern: pattern.clone(),
            match_type,
            action,
            comment: args.comment.unwrap_or_default(),
            outbound,
        };
        let id = rule.id;
        config.rules.insert(0, rule);
        self.apply(config).await?;
        Ok(format!("added rule {pattern} ({id})"))
    }

    #[tool(description = "Remove a rule by its pattern or id.")]
    async fn rule_remove(&self, Parameters(args): Parameters<RuleRemoveArgs>) -> ToolResult {
        let mut config = self.state().config().clone();
        let key = args.pattern.trim().to_lowercase();
        let before = config.rules.len();
        config
            .rules
            .retain(|r| r.pattern != key && r.id.to_string() != key);
        let removed = before - config.rules.len();
        if removed == 0 {
            return Err(format!("нет правила {}", args.pattern));
        }
        self.apply(config).await?;
        Ok(format!("removed {removed} rule(s)"))
    }

    #[tool(
        description = "Domain presets (ready-made sets such as YouTube or OpenAI): which are \
        selected, through which channel, how many entries and hits."
    )]
    async fn presets_list(&self) -> ToolResult {
        let state = self.state();
        let config = state.config().clone();
        let hits = state.rule_stats().clone();
        let presets = state.presets().file.presets.clone();
        pretty(&Value::Array(
            presets
                .iter()
                .map(|p| {
                    let selected = config.presets.contains(&p.id);
                    let entries = p.entries();
                    json!({
                        "id": p.id,
                        "name": p.name,
                        "group": p.group,
                        "selected": selected,
                        "channel": selected
                            .then(|| channel_name(&config, config.preset_outbounds.get(&p.id).copied()
                                .or(config.active_outbound_id)))
                            .flatten(),
                        "domains": p.domains,
                        "hits": entries.iter().filter_map(|e| hits.get(&e.id)).map(|s| s.hits).sum::<u64>(),
                    })
                })
                .collect(),
        ))
    }

    #[tool(
        description = "Select or unselect a preset and/or set the channel it goes through \
        (a channel name or id, or \"default\")."
    )]
    async fn preset_set(&self, Parameters(args): Parameters<PresetArgs>) -> ToolResult {
        let state = self.state();
        if !state.presets().file.presets.iter().any(|p| p.id == args.id) {
            return Err(format!("нет набора «{}»", args.id));
        }
        let mut config = state.config().clone();
        if let Some(selected) = args.selected {
            config.presets.retain(|p| p != &args.id);
            if selected {
                config.presets.push(args.id.clone());
            }
        }
        match args.channel.as_deref() {
            None => {}
            Some("default") => {
                config.preset_outbounds.remove(&args.id);
            }
            Some(c) => {
                let id = find_channel(&config, c)?.id;
                config.preset_outbounds.insert(args.id.clone(), id);
            }
        }
        self.apply(config).await?;
        Ok(format!("preset {} updated", args.id))
    }

    #[tool(
        description = "Channels (outbounds): name, id, type, whether default, health. \
        No secrets are shown."
    )]
    async fn channels_list(&self) -> ToolResult {
        let state = self.state();
        let config = state.config().clone();
        let health = state.health().clone();
        pretty(&Value::Array(
            config
                .outbounds
                .iter()
                .map(|o| {
                    json!({
                        "id": o.id,
                        "name": o.name,
                        "type": kind(&o.kind),
                        "default": Some(o.id) == config.active_outbound_id,
                        "health": health.outbounds.get(&o.id),
                    })
                })
                .collect(),
        ))
    }

    #[tool(description = "Test a channel: latency and the external IP seen through it.")]
    async fn channel_test(&self, Parameters(args): Parameters<ChannelArgs>) -> ToolResult {
        let state = self.state();
        let outbound = find_channel(&state.config(), &args.channel)?.clone();
        let probe = crate::ui_commands::test_outbound(state.clone(), outbound).await?;
        pretty(&json!({ "latencyMs": probe.latency_ms, "externalIp": probe.external_ip }))
    }

    #[tool(
        description = "Make a channel the default one (for proxy rules and presets without \
        a channel of their own)."
    )]
    async fn set_default_channel(&self, Parameters(args): Parameters<ChannelArgs>) -> ToolResult {
        let mut config = self.state().config().clone();
        let id = find_channel(&config, &args.channel)?.id;
        config.active_outbound_id = Some(id);
        self.apply(config).await?;
        Ok(format!("default channel: {}", args.channel))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for Tools {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(rmcp::model::Implementation::new(
                "localproxy",
                self.app.package_info().version.to_string(),
            ))
            .with_instructions(
                "LocalProxy: a selective proxy and VPN client for Windows. Rules send domains, \
                 subnets or programs through a channel (an HTTP/SOCKS5 proxy or a VPN tunnel) or \
                 direct; presets are ready-made domain sets. Changes apply at once and show in \
                 the app's window. Use check_host and connections to see where traffic goes.",
            )
    }
}

// ---------- helpers ----------

fn kind(k: &OutboundKind) -> &'static str {
    match k {
        OutboundKind::Http(_) => "http",
        OutboundKind::Socks5(_) => "socks5",
        OutboundKind::Awg { .. } => "awg",
        OutboundKind::Sstp(_) => "sstp",
    }
}

fn channel_name(config: &Config, id: Option<Uuid>) -> Option<String> {
    let id = id?;
    Some(
        config
            .outbounds
            .iter()
            .find(|o| o.id == id)
            .map_or_else(|| id.to_string(), |o| o.name.clone()),
    )
}

/// A channel by id or name (case does not matter).
pub(crate) fn find_channel<'a>(config: &'a Config, key: &str) -> Result<&'a Outbound, String> {
    let key = key.trim();
    config
        .outbounds
        .iter()
        .find(|o| {
            o.id.to_string() == key
                || o.name.eq_ignore_ascii_case(key)
                || o.name.to_lowercase() == key.to_lowercase()
        })
        .ok_or_else(|| {
            let names: Vec<_> = config.outbounds.iter().map(|o| o.name.as_str()).collect();
            format!("нет канала «{key}»; есть: {}", names.join(", "))
        })
}

pub(crate) fn parse_match_type(s: &str) -> Result<MatchType, String> {
    serde_json::from_value(Value::String(s.to_owned())).map_err(|_| {
        format!("unknown match type \"{s}\": use domainAndSubdomains, exact, mask, cidr or process")
    })
}

/// "openai.com" for a user rule, "YouTube: youtube.com" for a preset entry.
fn rule_label(state: &AppState, config: &Config, id: Option<Uuid>) -> Option<String> {
    let id = id?;
    if let Some(r) = config.rules.iter().find(|r| r.id == id) {
        return Some(r.pattern.clone());
    }
    let presets = state.presets();
    presets.file.presets.iter().find_map(|p| {
        p.entries()
            .into_iter()
            .find(|e| e.id == id)
            .map(|e| format!("{}: {}", p.name, e.pattern))
    })
}

/// The newest `limit` events that match, newest first.
pub(crate) fn filter_events(
    events: &[ConnEvent],
    filter: Option<&str>,
    errors_only: bool,
    limit: usize,
) -> Vec<ConnEvent> {
    let q = filter.map(str::to_lowercase).filter(|q| !q.is_empty());
    events
        .iter()
        .rev()
        .filter(|e| !errors_only || e.error.is_some())
        .filter(|e| {
            q.as_ref().is_none_or(|q| {
                e.host.to_lowercase().contains(q)
                    || e.process
                        .as_deref()
                        .is_some_and(|p| p.to_lowercase().contains(q))
                    || e.error
                        .as_deref()
                        .is_some_and(|x| x.to_lowercase().contains(q))
            })
        })
        .take(limit)
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests;
