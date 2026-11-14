use super::*;

use http_body_util::BodyExt;
use proxy_core::{Inbound, RouteKind};

const TOKEN: &str = "0123456789abcdef0123456789abcdef";

/// A server with no tools: enough to see what the HTTP layer lets through.
#[derive(Clone)]
struct Empty;

impl ServerHandler for Empty {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
    }
}

fn service() -> StreamableHttpService<Empty, LocalSessionManager> {
    StreamableHttpService::new(
        || Ok(Empty),
        Arc::new(LocalSessionManager::default()),
        http_config(&CancellationToken::new()),
    )
}

fn initialize(auth: Option<&str>, origin: Option<&str>, host: &str) -> Request<Full<Bytes>> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": { "name": "test", "version": "1" }
        }
    });
    let mut req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("Host", host)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream");
    if let Some(auth) = auth {
        req = req.header(AUTHORIZATION, auth);
    }
    if let Some(origin) = origin {
        req = req.header("Origin", origin);
    }
    req.body(Full::new(Bytes::from(body.to_string()))).unwrap()
}

async fn status(req: Request<Full<Bytes>>) -> (StatusCode, String) {
    let resp = handle(&service(), TOKEN, req).await;
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn a_program_with_the_token_gets_in() {
    let bearer = format!("Bearer {TOKEN}");
    let (code, body) = status(initialize(Some(&bearer), None, "127.0.0.1:3129")).await;
    assert_eq!(code, StatusCode::OK, "{body}");
    assert!(
        body.contains("serverInfo") || body.contains("protocolVersion"),
        "{body}"
    );
}

#[tokio::test]
async fn without_the_right_token_nothing_gets_in() {
    for auth in [None, Some("Bearer wrong"), Some(TOKEN)] {
        let (code, _) = status(initialize(auth, None, "127.0.0.1:3129")).await;
        assert_eq!(code, StatusCode::UNAUTHORIZED, "{auth:?}");
    }
}

#[tokio::test]
async fn web_pages_and_foreign_hosts_are_refused() {
    let bearer = format!("Bearer {TOKEN}");
    // A page in the browser always sends Origin, even to loopback.
    let (code, _) = status(initialize(
        Some(&bearer),
        Some("http://127.0.0.1:3129"),
        "127.0.0.1:3129",
    ))
    .await;
    assert!(code.is_client_error(), "Origin let through: {code}");
    // DNS rebinding: an outside name pointing at 127.0.0.1.
    let (code, _) = status(initialize(Some(&bearer), None, "evil.example:3129")).await;
    assert!(code.is_client_error(), "foreign Host let through: {code}");
}

#[test]
fn an_empty_token_never_matches() {
    let req = Request::builder()
        .header(AUTHORIZATION, "Bearer ")
        .body(())
        .unwrap();
    assert!(!authorized(&req, ""));
}

fn event(host: &str, process: Option<&str>, error: Option<&str>) -> ConnEvent {
    ConnEvent {
        at_ms: 0,
        inbound: Inbound::Socks5,
        host: host.into(),
        port: 443,
        route: if error.is_some() {
            RouteKind::Failed
        } else {
            RouteKind::Direct
        },
        rule_id: None,
        outbound_id: None,
        process: process.map(Into::into),
        error: error.map(Into::into),
    }
}

#[test]
fn connections_are_newest_first_and_filtered() {
    let events = vec![
        event("a.example", Some(r"C:\Apps\Discord.exe"), None),
        event("b.example", None, Some("connection refused")),
        event("c.example", None, None),
    ];
    let hosts = |v: Vec<ConnEvent>| v.into_iter().map(|e| e.host).collect::<Vec<_>>();
    assert_eq!(
        hosts(filter_events(&events, None, false, 2)),
        ["c.example", "b.example"]
    );
    assert_eq!(
        hosts(filter_events(&events, Some("discord"), false, 10)),
        ["a.example"]
    );
    assert_eq!(
        hosts(filter_events(&events, Some("REFUSED"), false, 10)),
        ["b.example"]
    );
    assert_eq!(hosts(filter_events(&events, None, true, 10)), ["b.example"]);
}

#[test]
fn channels_are_found_by_name_or_id() {
    let office = Outbound {
        id: Uuid::new_v4(),
        name: "Офис".into(),
        kind: OutboundKind::Awg {
            config: String::new(),
        },
    };
    let config = Config {
        outbounds: vec![office.clone()],
        ..Config::default()
    };
    assert_eq!(find_channel(&config, "офис").unwrap().id, office.id);
    assert_eq!(
        find_channel(&config, &office.id.to_string()).unwrap().id,
        office.id
    );
    let err = find_channel(&config, "vpn").unwrap_err();
    assert!(err.contains("Офис"), "{err}");
}

#[test]
fn match_types_by_their_config_names() {
    assert_eq!(parse_match_type("process").unwrap(), MatchType::Process);
    assert_eq!(
        parse_match_type("domainAndSubdomains").unwrap(),
        MatchType::DomainAndSubdomains
    );
    assert!(parse_match_type("domain").is_err());
}
