use super::*;

const CONF: &str = "[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.8.1.2/32
Jc = 3
Jmin = 10
Jmax = 30

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = 127.0.0.1:9
AllowedIPs = 0.0.0.0/0
";

fn awg(conf: &str) -> TunnelSpec {
    TunnelSpec::Awg { conf: conf.into() }
}

/// Points the code at the tunnel built by `pnpm build:tunnel`.
fn use_built_tunnel() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("binaries")
        .join("localproxy-tunnel-x86_64-pc-windows-msvc.exe");
    assert!(
        path.exists(),
        "{} is missing: run `pnpm build:tunnel` first",
        path.display()
    );
    // SAFETY: every test here sets the same value.
    unsafe { std::env::set_var("LOCALPROXY_TUNNEL", path) };
}

#[test]
fn start_request_shape() {
    let sstp = TunnelSpec::Sstp(SstpSpec {
        server: "vpn.example.com".into(),
        user: "alice".into(),
        password: "p".into(),
        cert_sha256: "ab".into(),
        insecure: false,
    });
    let json = serde_json::to_value(&sstp).unwrap();
    assert_eq!(json["sstp"]["server"], "vpn.example.com");
    assert_eq!(json["sstp"]["certSha256"], "ab");
    assert_eq!(serde_json::to_value(awg("x")).unwrap()["awg"]["conf"], "x");
}

#[tokio::test]
async fn tunnel_starts_reports_status_and_stops() {
    use_built_tunnel();
    let id = Uuid::new_v4();
    let mut tunnel = TunnelProcess::start(id, &awg(CONF)).await.unwrap();
    assert!(tunnel.endpoint.port > 0);
    assert_eq!(tunnel.endpoint.host, "127.0.0.1");
    assert!(!tunnel.endpoint.password.is_empty());
    let status = tunnel.status().await.unwrap();
    assert_eq!(status.last_handshake, 0, "nobody listens on 127.0.0.1:9");
    assert!(tunnel.is_alive());
    let port = tunnel.endpoint.port;
    tunnel.stop().await;
    assert!(
        tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_err(),
        "the tunnel must be gone after stop"
    );
}

#[tokio::test]
async fn bad_config_is_reported() {
    use_built_tunnel();
    let err = TunnelProcess::start(Uuid::new_v4(), &awg("[Interface]\nAddress = 10.0.0.2/32\n"))
        .await
        .err()
        .unwrap();
    assert!(err.contains("PrivateKey"), "{err}");
}

#[tokio::test]
async fn unreachable_sstp_server_is_reported() {
    use_built_tunnel();
    let spec = TunnelSpec::Sstp(SstpSpec {
        server: "127.0.0.1:9".into(),
        user: "alice".into(),
        password: "p".into(),
        cert_sha256: String::new(),
        insecure: false,
    });
    let err = TunnelProcess::start(Uuid::new_v4(), &spec)
        .await
        .err()
        .unwrap();
    assert!(err.starts_with("SSTP: нет соединения"), "{err}");
}
