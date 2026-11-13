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
    Config, MatchType, OnOutboundDown, Outbound, OutboundKind, PortForward, ProxyEndpoint, Rule,
    RuleAction,
};
use proxy_core::{Inbound, ProxyServer, RouteKind, ServerError};
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
            "/ip" => Ok(Response::new(Full::new(Bytes::from_static(
                b"203.0.113.7\n",
            )))),
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
        outbound: None,
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

#[tokio::test]
async fn serves_pac_and_version_follows_rules() {
    let mut cfg = config(None, OnOutboundDown::Block);
    let proxy = start(&cfg).await;
    let url_before = proxy.pac_url();
    assert!(url_before.starts_with(&format!("http://127.0.0.1:{}/proxy.pac?v=", proxy.port())));

    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(T)
        .build()
        .unwrap();
    let resp = client.get(&url_before).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()["content-type"],
        "application/x-ns-proxy-autoconfig"
    );
    let pac = resp.text().await.unwrap();
    assert!(pac.contains("\"localhost\""), "{pac}");
    assert!(
        pac.contains(&format!("PROXY 127.0.0.1:{}", proxy.port())),
        "{pac}"
    );

    cfg.rules.push(rule("example.com", RuleAction::Proxy));
    proxy.update(&cfg);
    assert_ne!(proxy.pac_url(), url_before);
    let pac = client
        .get(proxy.pac_url())
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(pac.contains("\"example.com\""), "{pac}");

    let resp = client
        .get(format!("http://127.0.0.1:{}/other", proxy.port()))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn probe_reports_external_ip_through_each_upstream_kind() {
    use proxy_core::outbound::Upstream;
    use proxy_core::probe::probe_at;
    use proxy_core::stream::TargetAddr;

    let origin = origin_server().await;
    let target = TargetAddr::new("127.0.0.1", origin);

    // SOCKS5: a LocalProxy that sends everything direct.
    let mut direct_cfg = config(None, OnOutboundDown::Block);
    direct_cfg.rules.clear();
    let socks = start(&direct_cfg).await;
    let probe = probe_at(&Upstream::Socks5(endpoint(socks.port())), &target, "/ip")
        .await
        .unwrap();
    assert_eq!(probe.external_ip.as_deref(), Some("203.0.113.7"));

    // HTTP: absolute-form through the fake upstream, with credentials.
    let (up_port, seen) = fake_http_upstream(Some("Basic dXNlcjpwYXNz")).await;
    let mut ep = endpoint(up_port);
    ep.username = "user".into();
    ep.password = "pass".into();
    let probe = probe_at(&Upstream::Http(ep), &target, "/ip").await.unwrap();
    assert_eq!(probe.external_ip.as_deref(), Some("203.0.113.7"));
    assert_eq!(
        seen.lines(),
        vec![format!("GET http://127.0.0.1:{origin}/ip HTTP/1.1")]
    );

    // Wrong credentials: the outbound is reported as down.
    let err = probe_at(&Upstream::Http(endpoint(up_port)), &target, "/ip")
        .await
        .unwrap_err();
    assert!(err.is_outbound_down(), "{err}");

    // Not an IP in the body: no external IP, but the outbound works.
    let probe = probe_at(&Upstream::Socks5(endpoint(socks.port())), &target, "/hello")
        .await
        .unwrap();
    assert_eq!(probe.external_ip, None);
}

#[tokio::test]
async fn outbound_pointing_to_itself_is_refused_not_looped() {
    let echo = echo_server().await;
    let mut cfg = config(None, OnOutboundDown::Block);
    let proxy = start(&cfg).await;
    let mut events = proxy.subscribe();

    // Point the outbound at the proxy's own port, as a user might by mistake.
    let own = Outbound {
        id: Uuid::new_v4(),
        name: "self".into(),
        kind: OutboundKind::Socks5(ProxyEndpoint {
            host: "localhost".into(),
            port: proxy.port(),
            ..Default::default()
        }),
    };
    cfg.active_outbound_id = Some(own.id);
    cfg.outbounds = vec![own];
    proxy.update(&cfg);

    let (status, _) = http_connect(proxy.port(), &format!("localhost:{echo}")).await;
    assert_eq!(status, 403);
    let event = events.recv().await.unwrap();
    assert_eq!(event.route, RouteKind::Blocked);
    assert!(event.error.unwrap().contains("петля"));
    // Exactly one connection was routed: no second lap through ourselves.
    assert!(events.try_recv().is_err());
}

// ---------- UDP ASSOCIATE ----------

/// UDP echo on 127.0.0.1 and [::1], same port.
async fn udp_echo_server() -> u16 {
    use tokio::net::UdpSocket;
    let v4 = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = v4.local_addr().unwrap().port();
    let mut sockets = vec![v4];
    if let Ok(v6) = UdpSocket::bind((Ipv6Addr::LOCALHOST, port)).await {
        sockets.push(v6);
    }
    for s in sockets {
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((n, from)) = s.recv_from(&mut buf).await {
                let _ = s.send_to(&buf[..n], from).await;
            }
        });
    }
    port
}

/// Opens an association; returns the control connection, the client socket
/// and the relay address.
async fn udp_associate(proxy: u16) -> (TcpStream, tokio::net::UdpSocket, std::net::SocketAddr) {
    let mut c = TcpStream::connect((Ipv4Addr::LOCALHOST, proxy))
        .await
        .unwrap();
    c.write_all(&[5, 1, 0]).await.unwrap();
    let mut r = [0u8; 2];
    c.read_exact(&mut r).await.unwrap();
    c.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
    let mut reply = [0u8; 10];
    timeout(T, c.read_exact(&mut reply)).await.unwrap().unwrap();
    assert_eq!(reply[1], 0, "UDP ASSOCIATE refused");
    let relay = std::net::SocketAddr::from((
        [reply[4], reply[5], reply[6], reply[7]],
        u16::from_be_bytes([reply[8], reply[9]]),
    ));
    let udp = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    (c, udp, relay)
}

/// Sends one datagram to `host:port` through the relay and waits for a reply.
async fn udp_roundtrip(
    udp: &tokio::net::UdpSocket,
    relay: std::net::SocketAddr,
    host: &str,
    port: u16,
    payload: &[u8],
    wait: Duration,
) -> Option<Vec<u8>> {
    let mut d = vec![0, 0, 0];
    match host.parse::<Ipv4Addr>() {
        Ok(ip) => {
            d.push(1);
            d.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            d.push(3);
            d.push(host.len() as u8);
            d.extend_from_slice(host.as_bytes());
        }
    }
    d.extend_from_slice(&port.to_be_bytes());
    d.extend_from_slice(payload);
    udp.send_to(&d, relay).await.unwrap();
    let mut buf = [0u8; 2048];
    let (n, _) = timeout(wait, udp.recv_from(&mut buf)).await.ok()?.ok()?;
    let reply = &buf[..n];
    // Strip RSV RSV FRAG ATYP ADDR PORT.
    let offset = match reply[3] {
        1 => 4 + 4 + 2,
        4 => 4 + 16 + 2,
        _ => panic!("unexpected address type in reply"),
    };
    Some(reply[offset..].to_vec())
}

#[tokio::test]
async fn udp_associate_direct() {
    let echo = udp_echo_server().await;
    let mut cfg = config(None, OnOutboundDown::Block);
    cfg.rules.clear();
    let proxy = start(&cfg).await;
    let mut events = proxy.subscribe();
    let (_control, udp, relay) = udp_associate(proxy.port()).await;
    for i in 0..3 {
        let msg = format!("ping {i}");
        let reply = udp_roundtrip(&udp, relay, "127.0.0.1", echo, msg.as_bytes(), T).await;
        assert_eq!(reply.as_deref(), Some(msg.as_bytes()));
    }
    let event = events.recv().await.unwrap();
    assert_eq!(event.inbound, proxy_core::Inbound::Udp);
    assert_eq!(event.route, RouteKind::Direct);
    assert!(
        events.try_recv().is_err(),
        "one event per destination, not per datagram"
    );

    // 3 datagrams of "ping N" (6 bytes) each way, one UDP flow, direct.
    let rows = proxy.traffic().snapshot();
    let row = rows
        .iter()
        .find(|r| r.host == "127.0.0.1" && r.udp)
        .unwrap();
    assert!(!row.via_outbound);
    assert_eq!((row.up, row.down, row.connections), (18, 18, 1));
}

#[tokio::test]
async fn udp_associate_through_socks5_upstream_keeps_host_names() {
    let echo = udp_echo_server().await;
    let mut upstream_cfg = config(None, OnOutboundDown::Block);
    upstream_cfg.rules.clear();
    let upstream = start(&upstream_cfg).await;
    let mut upstream_events = upstream.subscribe();

    let proxy = start(&config(
        Some(OutboundKind::Socks5(endpoint(upstream.port()))),
        OnOutboundDown::Block,
    ))
    .await;
    let mut events = proxy.subscribe();
    let (_control, udp, relay) = udp_associate(proxy.port()).await;
    let reply = udp_roundtrip(&udp, relay, "localhost", echo, b"via upstream", T).await;
    assert_eq!(reply.as_deref(), Some(&b"via upstream"[..]));

    let front = events.recv().await.unwrap();
    assert_eq!(
        (front.inbound, front.route),
        (proxy_core::Inbound::Udp, RouteKind::Proxy)
    );
    // The name reached the upstream unresolved: it routed "localhost", not an IP.
    let far = upstream_events.recv().await.unwrap();
    assert_eq!(
        (far.host.as_str(), far.inbound),
        ("localhost", proxy_core::Inbound::Udp)
    );

    // The reply comes back from an address, not from "localhost": it must
    // still be counted for the name, through the outbound.
    let rows = proxy.traffic().snapshot();
    let row = rows
        .iter()
        .find(|r| r.host == "localhost" && r.udp)
        .unwrap();
    assert!(row.via_outbound);
    assert_eq!((row.up, row.down), (12, 12));
}

#[tokio::test]
async fn udp_cannot_go_through_http_upstream() {
    let echo = udp_echo_server().await;
    let (up_port, _) = fake_http_upstream(None).await;
    let proxy = start(&config(
        Some(OutboundKind::Http(endpoint(up_port))),
        OnOutboundDown::Block,
    ))
    .await;
    let mut events = proxy.subscribe();
    let (_control, udp, relay) = udp_associate(proxy.port()).await;
    let reply = udp_roundtrip(&udp, relay, "localhost", echo, b"x", Duration::from_secs(1)).await;
    assert_eq!(reply, None, "matched UDP must be dropped, not sent direct");
    let event = events.recv().await.unwrap();
    assert_eq!(event.route, RouteKind::Blocked);
    assert!(event.error.unwrap().contains("HTTP"));

    // Unmatched destinations still work in the same association.
    let reply = udp_roundtrip(&udp, relay, "127.0.0.1", echo, b"direct", T).await;
    assert_eq!(reply.as_deref(), Some(&b"direct"[..]));
}

/// Minimal upstream SOCKS5 server that requires username/password and only
/// does CONNECT (always to 127.0.0.1 on the requested port).
async fn fake_socks5_with_auth(user: &'static str, pass: &'static str) -> u16 {
    let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut head = [0u8; 2];
                s.read_exact(&mut head).await.unwrap();
                let mut methods = vec![0u8; head[1] as usize];
                s.read_exact(&mut methods).await.unwrap();
                assert!(methods.contains(&2), "client must offer user/pass");
                s.write_all(&[5, 2]).await.unwrap();
                let mut v = [0u8; 2];
                s.read_exact(&mut v).await.unwrap();
                let mut u = vec![0u8; v[1] as usize];
                s.read_exact(&mut u).await.unwrap();
                let plen = s.read_u8().await.unwrap();
                let mut p = vec![0u8; plen as usize];
                s.read_exact(&mut p).await.unwrap();
                if u != user.as_bytes() || p != pass.as_bytes() {
                    let _ = s.write_all(&[1, 1]).await;
                    return;
                }
                s.write_all(&[1, 0]).await.unwrap();
                let mut req = [0u8; 4];
                s.read_exact(&mut req).await.unwrap();
                let skip = match req[3] {
                    1 => 4,
                    4 => 16,
                    _ => s.read_u8().await.unwrap() as usize,
                };
                let mut addr = vec![0u8; skip];
                s.read_exact(&mut addr).await.unwrap();
                let port = s.read_u16().await.unwrap();
                let mut up = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                    .await
                    .unwrap();
                s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
                let _ = copy_bidirectional(&mut s, &mut up).await;
            });
        }
    });
    port
}

#[tokio::test]
async fn socks5_upstream_with_credentials() {
    let echo = echo_server().await;
    let up = fake_socks5_with_auth("alice", "s3cret").await;
    let mut ep = endpoint(up);
    ep.username = "alice".into();
    ep.password = "s3cret".into();
    let proxy = start(&config(
        Some(OutboundKind::Socks5(ep.clone())),
        OnOutboundDown::Block,
    ))
    .await;
    let (status, mut s) = http_connect(proxy.port(), &format!("localhost:{echo}")).await;
    assert_eq!(status, 200);
    assert_echo(&mut s).await;

    ep.password = "wrong".into();
    let proxy = start(&config(
        Some(OutboundKind::Socks5(ep)),
        OnOutboundDown::Block,
    ))
    .await;
    let (status, _) = http_connect(proxy.port(), &format!("localhost:{echo}")).await;
    assert_eq!(status, 403, "bad credentials mean the outbound is down");
}

#[tokio::test]
async fn traffic_is_counted_live_per_host_and_route() {
    let echo = echo_server().await;
    let traffic = std::sync::Arc::new(proxy_core::traffic::Traffic::default());
    let mut cfg = config(None, OnOutboundDown::Block);
    cfg.rules.clear();
    let proxy = ProxyServer::start_with_traffic(&cfg, traffic.clone())
        .await
        .unwrap();

    let (status, mut s) = http_connect(proxy.port(), &format!("127.0.0.1:{echo}")).await;
    assert_eq!(status, 200);
    assert_echo(&mut s).await;
    // Still open: the numbers must already be there.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let rows = traffic.snapshot();
    let row = rows.iter().find(|r| r.host == "127.0.0.1").unwrap();
    assert!(!row.via_outbound);
    assert_eq!((row.up, row.down, row.connections), (4, 4, 1));

    traffic.reset();
    assert!(traffic.snapshot().is_empty());
}

#[tokio::test]
async fn each_rule_goes_through_its_own_outbound() {
    let echo = echo_server().await;
    let (default_port, default_seen) = fake_http_upstream(None).await;
    let (office_port, office_seen) = fake_http_upstream(None).await;
    let dead = dead_upstream().await;
    let outbound = |name: &str, port: u16| Outbound {
        id: Uuid::new_v4(),
        name: name.into(),
        kind: OutboundKind::Http(endpoint(port)),
    };
    let (default, office, down) = (
        outbound("default", default_port),
        outbound("office", office_port),
        outbound("down", dead),
    );
    let with = |pattern: &str, outbound: Option<Uuid>| Rule {
        outbound,
        ..rule(pattern, RuleAction::Proxy)
    };
    let config = Config {
        port: 0,
        enabled: true,
        active_outbound_id: Some(default.id),
        rules: vec![
            with("a.test", None),
            with("b.test", Some(office.id)),
            with("c.test", Some(down.id)),
            with("d.test", Some(Uuid::new_v4())),
        ],
        outbounds: vec![default.clone(), office.clone(), down.clone()],
        ..Config::default()
    };
    let proxy = start(&config).await;
    let mut events = proxy.subscribe();

    for host in ["a.test", "b.test"] {
        let (status, mut s) = http_connect(proxy.port(), &format!("{host}:{echo}")).await;
        assert_eq!(status, 200, "{host}");
        assert_echo(&mut s).await;
    }
    assert_eq!(
        default_seen.lines(),
        [format!("CONNECT a.test:{echo} HTTP/1.1")]
    );
    assert_eq!(
        office_seen.lines(),
        [format!("CONNECT b.test:{echo} HTTP/1.1")]
    );
    for host in ["c.test", "d.test"] {
        let (status, _) = http_connect(proxy.port(), &format!("{host}:{echo}")).await;
        assert_eq!(status, 403, "{host}: blocked, never sent elsewhere");
    }

    let seen: Vec<_> = (0..4).map(|_| events.try_recv().unwrap()).collect();
    let by_host = |h: &str| seen.iter().find(|e| e.host == h).unwrap();
    assert_eq!(by_host("a.test").outbound_id, Some(default.id));
    assert_eq!(by_host("b.test").outbound_id, Some(office.id));
    assert_eq!(
        (by_host("c.test").route, by_host("c.test").outbound_id),
        (RouteKind::Blocked, Some(down.id))
    );
    assert!(
        by_host("d.test")
            .error
            .as_deref()
            .unwrap()
            .contains("удалён")
    );

    let traffic = proxy.traffic().snapshot();
    let row = |h: &str| traffic.iter().find(|r| r.host == h).unwrap();
    assert_eq!(row("a.test").outbound_id, Some(default.id));
    assert_eq!(row("b.test").outbound_id, Some(office.id));
}

async fn free_port() -> u16 {
    let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    l.local_addr().unwrap().port()
}

async fn wait_forward(proxy: &ProxyServer, id: Uuid) -> proxy_core::ForwardState {
    for _ in 0..100 {
        if let Some(s) = proxy.forward_status().into_iter().find(|s| s.id == id)
            && s.state != proxy_core::ForwardState::Starting
        {
            return s.state;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("forward did not start");
}

#[tokio::test]
async fn port_forward_goes_through_its_outbound_only() {
    let echo = echo_server().await;
    let (office_port, office_seen) = fake_http_upstream(None).await;
    let office = Outbound {
        id: Uuid::new_v4(),
        name: "office".into(),
        kind: OutboundKind::Http(endpoint(office_port)),
    };
    let down = Outbound {
        id: Uuid::new_v4(),
        name: "down".into(),
        kind: OutboundKind::Http(endpoint(dead_upstream().await)),
    };
    let local = free_port().await;
    let mut forward = PortForward {
        id: Uuid::new_v4(),
        enabled: true,
        local_port: local,
        target_host: "mysql.office.lan".into(),
        target_port: echo,
        outbound: Some(office.id),
        comment: String::new(),
    };
    let mut config = Config {
        port: 0,
        enabled: true,
        outbounds: vec![office.clone(), down.clone()],
        forwards: vec![forward.clone()],
        on_outbound_down: OnOutboundDown::Direct,
        ..Config::default()
    };
    let proxy = start(&config).await;
    let mut events = proxy.subscribe();
    assert_eq!(
        wait_forward(&proxy, forward.id).await,
        proxy_core::ForwardState::Listening
    );

    let mut s = TcpStream::connect((Ipv4Addr::LOCALHOST, local))
        .await
        .unwrap();
    assert_echo(&mut s).await;
    drop(s);
    assert_eq!(
        office_seen.lines(),
        [format!("CONNECT mysql.office.lan:{echo} HTTP/1.1")],
        "the name is resolved on the far side"
    );
    let event = events.recv().await.unwrap();
    assert_eq!(
        (event.inbound, event.route, event.outbound_id),
        (Inbound::Forward, RouteKind::Proxy, Some(office.id))
    );

    // Retargeted to a dead outbound without reopening the port: closed,
    // not sent direct even though the policy allows it for rules.
    forward.outbound = Some(down.id);
    config.forwards = vec![forward.clone()];
    proxy.update(&config);
    let mut s = TcpStream::connect((Ipv4Addr::LOCALHOST, local))
        .await
        .unwrap();
    let mut buf = [0u8; 1];
    let n = timeout(T, s.read(&mut buf)).await.unwrap().unwrap_or(0);
    assert_eq!(n, 0, "closed");
    assert_eq!(events.recv().await.unwrap().route, RouteKind::Blocked);

    // A busy port is reported; switching the forward off closes the port.
    let busy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let taken = PortForward {
        id: Uuid::new_v4(),
        local_port: busy.local_addr().unwrap().port(),
        ..forward.clone()
    };
    forward.enabled = false;
    config.forwards = vec![forward.clone(), taken.clone()];
    proxy.update(&config);
    assert!(matches!(
        wait_forward(&proxy, taken.id).await,
        proxy_core::ForwardState::Failed { .. }
    ));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        TcpStream::connect((Ipv4Addr::LOCALHOST, local))
            .await
            .is_err(),
        "disabled forward stops listening"
    );
}
