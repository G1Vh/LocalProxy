//! End-to-end tests over real sockets on loopback.
//!
//! "localhost" is used for hosts that rules send to the outbound and
//! "127.0.0.1" for hosts that go direct.

use std::convert::Infallible;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use proxy_core::config::{
    Config, MatchType, OnOutboundDown, Outbound, OutboundKind, ProxyEndpoint, Rule, RuleAction,
};
use proxy_core::{ProxyServer, RouteKind, ServerError};
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use uuid::Uuid;

const T: Duration = Duration::from_secs(10);

// ---------- test servers ----------

/// Binds 127.0.0.1 and [::1] on the same free port, so "localhost" connects fast.
async fn bind_dual() -> (u16, Vec<TcpListener>) {
    let v4 = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = v4.local_addr().unwrap().port();
    let mut listeners = vec![v4];
    if let Ok(v6) = TcpListener::bind((Ipv6Addr::LOCALHOST, port)).await {
        listeners.push(v6);
    }
    (port, listeners)
}

async fn echo_server() -> u16 {
    let (port, listeners) = bind_dual().await;
    for l in listeners {
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
    }
    port
}

/// `/hello` sets two cookies, `/echo` returns the request body, `/ws` upgrades and echoes.
async fn origin_server() -> u16 {
    async fn handle(mut req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
        match req.uri().path() {
            "/hello" => Ok(Response::builder()
                .header("set-cookie", "a=1")
                .header("set-cookie", "b=2")
                .body(Full::new(Bytes::from_static(b"hello")))
                .unwrap()),
            "/echo" => {
                let body = req.into_body().collect().await.unwrap().to_bytes();
                Ok(Response::new(Full::new(body)))
            }
            "/ws" => {
                let on_upgrade = hyper::upgrade::on(&mut req);
                tokio::spawn(async move {
                    let mut io = TokioIo::new(on_upgrade.await.unwrap());
                    let mut buf = [0u8; 64];
                    while let Ok(n) = io.read(&mut buf).await {
                        if n == 0 || io.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
                Ok(Response::builder()
                    .status(StatusCode::SWITCHING_PROTOCOLS)
                    .header("connection", "upgrade")
                    .header("upgrade", "test")
                    .body(Full::new(Bytes::new()))
                    .unwrap())
            }
            _ => Ok(Response::builder()
                .status(404)
                .body(Full::new(Bytes::new()))
                .unwrap()),
        }
    }
    let (port, listeners) = bind_dual().await;
    for l in listeners {
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(s), hyper::service::service_fn(handle))
                        .with_upgrades()
                        .await;
                });
            }
        });
    }
    port
}

/// (request line, Proxy-Authorization)
type SeenRequest = (String, Option<String>);

/// What a fake upstream HTTP proxy saw: request lines and auth headers.
#[derive(Default, Clone)]
struct Seen(Arc<Mutex<Vec<SeenRequest>>>);

impl Seen {
    fn lines(&self) -> Vec<String> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .map(|(l, _)| l.clone())
            .collect()
    }
    fn auths(&self) -> Vec<Option<String>> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .map(|(_, a)| a.clone())
            .collect()
    }
}

/// Minimal upstream HTTP proxy: CONNECT and absolute-form GET, optional Basic auth.
/// Always dials 127.0.0.1 on the requested port.
async fn fake_http_upstream(required_auth: Option<&'static str>) -> (u16, Seen) {
    let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = l.local_addr().unwrap().port();
    let seen = Seen::default();
    let seen2 = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let seen = seen2.clone();
            tokio::spawn(async move {
                let head = read_head(&mut s).await;
                let line = head.lines().next().unwrap_or_default().to_owned();
                let auth = head
                    .lines()
                    .find_map(|l| l.strip_prefix("Proxy-Authorization: "))
                    .map(str::to_owned);
                seen.0.lock().unwrap().push((line.clone(), auth.clone()));
                if let Some(expected) = required_auth
                    && auth.as_deref() != Some(expected)
                {
                    let _ = s
                        .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                        .await;
                    return;
                }
                let mut parts = line.split_whitespace();
                let method = parts.next().unwrap_or_default().to_owned();
                let target = parts.next().unwrap_or_default().to_owned();
                if method == "CONNECT" {
                    let port: u16 = target.rsplit(':').next().unwrap().parse().unwrap();
                    let mut up = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                        .await
                        .unwrap();
                    s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                        .await
                        .unwrap();
                    let _ = copy_bidirectional(&mut s, &mut up).await;
                } else {
                    let url = target.strip_prefix("http://").unwrap();
                    let (authority, path) = url.split_at(url.find('/').unwrap());
                    let port: u16 = authority.rsplit(':').next().unwrap().parse().unwrap();
                    let mut up = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                        .await
                        .unwrap();
                    let rest = head.split_once("\r\n").unwrap().1;
                    let req = format!("{method} {path} HTTP/1.1\r\n{rest}");
                    up.write_all(req.as_bytes()).await.unwrap();
                    let _ = copy_bidirectional(&mut s, &mut up).await;
                }
            });
        }
    });
    (port, seen)
}

/// Accepts and immediately drops connections: an outbound that is "down".
async fn dead_upstream() -> u16 {
    let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            drop(s);
        }
    });
    port
}

async fn read_head(s: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if s.read(&mut byte).await.unwrap() == 0 {
            break;
        }
        buf.push(byte[0]);
    }
    String::from_utf8(buf).unwrap()
}

// ---------- config helpers ----------

fn rule(pattern: &str, action: RuleAction) -> Rule {
    Rule {
        id: Uuid::new_v4(),
        enabled: true,
        pattern: pattern.into(),
        match_type: MatchType::Exact,
        action,
        comment: String::new(),
        preset: None,
    }
}

fn endpoint(port: u16) -> ProxyEndpoint {
    ProxyEndpoint {
        host: "127.0.0.1".into(),
        port,
        ..Default::default()
    }
}

/// Port 0, "localhost" goes through `outbound`.
fn config(outbound: Option<OutboundKind>, on_down: OnOutboundDown) -> Config {
    let outbound = outbound.map(|kind| Outbound {
        id: Uuid::new_v4(),
        name: "test".into(),
        kind,
    });
    Config {
        port: 0,
        enabled: true,
        on_outbound_down: on_down,
        active_outbound_id: outbound.as_ref().map(|o| o.id),
        outbounds: outbound.into_iter().collect(),
        rules: vec![rule("localhost", RuleAction::Proxy)],
        ..Config::default()
    }
}

async fn start(config: &Config) -> ProxyServer {
    ProxyServer::start(config).await.unwrap()
}

// ---------- client helpers ----------

/// Sends CONNECT and returns the status code and the stream.
async fn http_connect(proxy: u16, target: &str) -> (u16, TcpStream) {
    let mut s = TcpStream::connect((Ipv4Addr::LOCALHOST, proxy))
        .await
        .unwrap();
    s.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let head = timeout(T, read_head(&mut s)).await.unwrap();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, s)
}

async fn assert_echo(s: &mut TcpStream) {
    s.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    timeout(T, s.read_exact(&mut buf)).await.unwrap().unwrap();
    assert_eq!(&buf, b"ping");
}

/// SOCKS5 CONNECT by domain name; returns the reply code and the stream.
async fn socks5_connect(proxy: u16, host: &str, port: u16) -> (u8, TcpStream) {
    let mut s = TcpStream::connect((Ipv4Addr::LOCALHOST, proxy))
        .await
        .unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await.unwrap();
    assert_eq!(r, [5, 0]);
    let mut req = vec![5, 1, 0, 3, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut reply = [0u8; 10];
    timeout(T, s.read_exact(&mut reply)).await.unwrap().unwrap();
    (reply[1], s)
}

fn http_client(proxy_url: &str) -> reqwest::Client {
    reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(proxy_url).unwrap())
        .timeout(T)
        .build()
        .unwrap()
}

// ---------- tests ----------

#[tokio::test]
async fn connect_tunnel_direct() {
    let echo = echo_server().await;
    let proxy = start(&config(None, OnOutboundDown::Block)).await;
    let (status, mut s) = http_connect(proxy.port(), &format!("127.0.0.1:{echo}")).await;
    assert_eq!(status, 200);
    assert_echo(&mut s).await;
}

#[tokio::test]
async fn plain_http_keeps_alive_and_preserves_cookies() {
    let origin = origin_server().await;
    let proxy = start(&config(None, OnOutboundDown::Block)).await;

    let stream = TcpStream::connect(proxy.local_addr()).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(conn);

    for _ in 0..2 {
        sender.ready().await.unwrap();
        let req = Request::get(format!("http://127.0.0.1:{origin}/hello"))
            .header("host", format!("127.0.0.1:{origin}"))
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers().get_all("set-cookie").iter().count(), 2);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"hello");
    }
}

#[tokio::test]
async fn chunked_request_body_is_forwarded() {
    let origin = origin_server().await;
    let proxy = start(&config(None, OnOutboundDown::Block)).await;
    let mut s = TcpStream::connect(proxy.local_addr()).await.unwrap();
    let req = format!(
        "POST http://127.0.0.1:{origin}/echo HTTP/1.1\r\nHost: 127.0.0.1:{origin}\r\n\
         Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n\
         5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut response = String::new();
    timeout(T, s.read_to_string(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.ends_with("hello world"), "{response}");
}

#[tokio::test]
async fn upgrade_over_plain_http() {
    let origin = origin_server().await;
    let proxy = start(&config(None, OnOutboundDown::Block)).await;
    let mut s = TcpStream::connect(proxy.local_addr()).await.unwrap();
    let req = format!(
        "GET http://127.0.0.1:{origin}/ws HTTP/1.1\r\nHost: 127.0.0.1:{origin}\r\n\
         Connection: Upgrade\r\nUpgrade: test\r\n\r\n"
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let head = timeout(T, read_head(&mut s)).await.unwrap();
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    assert!(
        head.to_ascii_lowercase().contains("upgrade: test"),
        "{head}"
    );
    assert_echo(&mut s).await;
}

#[tokio::test]
async fn matched_host_goes_through_http_upstream_with_auth() {
    let echo = echo_server().await;
    let (up_port, seen) = fake_http_upstream(Some("Basic dXNlcjpwYXNz")).await;
    let mut ep = endpoint(up_port);
    ep.username = "user".into();
    ep.password = "pass".into();
    let proxy = start(&config(Some(OutboundKind::Http(ep)), OnOutboundDown::Block)).await;
    let mut events = proxy.subscribe();

    let (status, mut s) = http_connect(proxy.port(), &format!("localhost:{echo}")).await;
    assert_eq!(status, 200);
    assert_echo(&mut s).await;

    // Unmatched host must not touch the upstream.
    let (status, mut s) = http_connect(proxy.port(), &format!("127.0.0.1:{echo}")).await;
    assert_eq!(status, 200);
    assert_echo(&mut s).await;

    assert_eq!(
        seen.lines(),
        vec![format!("CONNECT localhost:{echo} HTTP/1.1")]
    );
    assert_eq!(seen.auths(), vec![Some("Basic dXNlcjpwYXNz".to_owned())]);

    let first = events.recv().await.unwrap();
    assert_eq!(
        (first.host.as_str(), first.route),
        ("localhost", RouteKind::Proxy)
    );
    assert!(first.rule_id.is_some());
    let second = events.recv().await.unwrap();
    assert_eq!(
        (second.host.as_str(), second.route),
        ("127.0.0.1", RouteKind::Direct)
    );
    assert_eq!(second.rule_id, None);
}

#[tokio::test]
async fn wrong_upstream_credentials_count_as_outbound_down() {
    let echo = echo_server().await;
    let (up_port, _) = fake_http_upstream(Some("Basic dXNlcjpwYXNz")).await;
    let proxy = start(&config(
        Some(OutboundKind::Http(endpoint(up_port))),
        OnOutboundDown::Block,
    ))
    .await;
    let (status, _) = http_connect(proxy.port(), &format!("localhost:{echo}")).await;
    assert_eq!(status, 403);
}

#[tokio::test]
async fn plain_http_via_http_upstream_uses_absolute_form() {
    let origin = origin_server().await;
    let (up_port, seen) = fake_http_upstream(None).await;
    let proxy = start(&config(
        Some(OutboundKind::Http(endpoint(up_port))),
        OnOutboundDown::Block,
    ))
    .await;
    let client = http_client(&format!("http://127.0.0.1:{}", proxy.port()));
    let resp = client
        .get(format!("http://localhost:{origin}/hello"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "hello");
    assert_eq!(
        seen.lines(),
        vec![format!("GET http://localhost:{origin}/hello HTTP/1.1")]
    );
}

#[tokio::test]
async fn socks5_inbound_chained_through_socks5_upstream() {
    let origin = origin_server().await;
    // Upstream: a second LocalProxy that sends everything direct.
    let mut upstream_config = config(None, OnOutboundDown::Block);
    upstream_config.rules.clear();
    let upstream = start(&upstream_config).await;
    let mut upstream_events = upstream.subscribe();

    let proxy = start(&config(
        Some(OutboundKind::Socks5(endpoint(upstream.port()))),
        OnOutboundDown::Block,
    ))
    .await;

    // By domain name: resolved at the far end.
    let (code, mut s) = socks5_connect(proxy.port(), "localhost", origin).await;
    assert_eq!(code, 0);
    s.write_all(b"GET /hello HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = String::new();
    timeout(T, s.read_to_string(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(response.ends_with("hello"), "{response}");

    let seen = upstream_events.recv().await.unwrap();
    assert_eq!(seen.host, "localhost");
    assert_eq!(seen.port, origin);
    assert_eq!(seen.route, RouteKind::Direct);
}

#[tokio::test]
async fn socks5_direct_echo() {
    let echo = echo_server().await;
    let proxy = start(&config(None, OnOutboundDown::Block)).await;
    let (code, mut s) = socks5_connect(proxy.port(), "127.0.0.1", echo).await;
    assert_eq!(code, 0);
    assert_echo(&mut s).await;
}

#[tokio::test]
async fn outbound_down_blocks_by_default() {
    let echo = echo_server().await;
    let dead = dead_upstream().await;
    let proxy = start(&config(
        Some(OutboundKind::Http(endpoint(dead))),
        OnOutboundDown::Block,
    ))
    .await;
    let mut events = proxy.subscribe();

    let (status, _) = http_connect(proxy.port(), &format!("localhost:{echo}")).await;
    assert_eq!(status, 403);
    let (code, _) = socks5_connect(proxy.port(), "localhost", echo).await;
    assert_eq!(code, 2, "connection not allowed by ruleset");

    let event = events.recv().await.unwrap();
    assert_eq!(event.route, RouteKind::Blocked);
    assert!(event.error.is_some());

    // Direct traffic is unaffected.
    let (status, mut s) = http_connect(proxy.port(), &format!("127.0.0.1:{echo}")).await;
    assert_eq!(status, 200);
    assert_echo(&mut s).await;
}

#[tokio::test]
async fn outbound_down_falls_back_when_allowed() {
    let echo = echo_server().await;
    let dead = dead_upstream().await;
    let proxy = start(&config(
        Some(OutboundKind::Socks5(endpoint(dead))),
        OnOutboundDown::Direct,
    ))
    .await;
    let mut events = proxy.subscribe();
    let (status, mut s) = http_connect(proxy.port(), &format!("localhost:{echo}")).await;
    assert_eq!(status, 200);
    assert_echo(&mut s).await;
    assert_eq!(events.recv().await.unwrap().route, RouteKind::Fallback);
}

#[tokio::test]
async fn no_active_outbound_blocks_matched_hosts() {
    let echo = echo_server().await;
    let proxy = start(&config(None, OnOutboundDown::Block)).await;
    let (status, _) = http_connect(proxy.port(), &format!("localhost:{echo}")).await;
    assert_eq!(status, 403);
}

#[tokio::test]
async fn direct_failure_is_bad_gateway() {
    let closed = {
        let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        l.local_addr().unwrap().port()
    };
    let proxy = start(&config(None, OnOutboundDown::Block)).await;
    let (status, _) = http_connect(proxy.port(), &format!("127.0.0.1:{closed}")).await;
    assert_eq!(status, 502);
}

#[tokio::test]
async fn rules_update_without_restart() {
    let echo = echo_server().await;
    let mut cfg = config(None, OnOutboundDown::Block);
    cfg.rules.clear();
    let proxy = start(&cfg).await;
    let (status, _) = http_connect(proxy.port(), &format!("localhost:{echo}")).await;
    assert_eq!(status, 200);

    cfg.rules = vec![rule("localhost", RuleAction::Proxy)];
    proxy.update(&cfg);
    let (status, _) = http_connect(proxy.port(), &format!("localhost:{echo}")).await;
    assert_eq!(status, 403);
}

#[tokio::test]
async fn socks5_can_be_switched_off() {
    let echo = echo_server().await;
    let mut cfg = config(None, OnOutboundDown::Block);
    cfg.socks5_enabled = false;
    let proxy = start(&cfg).await;
    let mut s = TcpStream::connect(proxy.local_addr()).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut buf = [0u8; 2];
    let read = timeout(T, s.read(&mut buf)).await.unwrap();
    assert!(matches!(read, Ok(0) | Err(_)), "connection must be closed");
    let _ = echo;
}

#[tokio::test]
async fn stop_closes_listener_and_tunnels() {
    let echo = echo_server().await;
    let proxy = start(&config(None, OnOutboundDown::Block)).await;
    let addr = proxy.local_addr();
    let (_, mut tunnel) = http_connect(proxy.port(), &format!("127.0.0.1:{echo}")).await;
    proxy.stop().await;

    let mut buf = [0u8; 1];
    let read = timeout(T, tunnel.read(&mut buf)).await.unwrap();
    assert!(matches!(read, Ok(0) | Err(_)), "tunnel must be closed");
    assert!(TcpStream::connect(addr).await.is_err());
}

#[tokio::test]
async fn busy_port_is_reported() {
    let first = start(&config(None, OnOutboundDown::Block)).await;
    let mut cfg = config(None, OnOutboundDown::Block);
    cfg.port = first.port();
    match ProxyServer::start(&cfg).await {
        Err(ServerError::PortBusy(p)) => assert_eq!(p, first.port()),
        Err(e) => panic!("unexpected error: {e}"),
        Ok(_) => panic!("second server must not bind a busy port"),
    }
}
