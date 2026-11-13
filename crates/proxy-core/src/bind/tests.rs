
use super::*;

#[tokio::test]
async fn loopback_is_never_pinned() {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    // An interface that does not exist would break a pinned socket.
    set_interface(0xFFFF, 0xFFFF);
    let result = tcp_connect(addr).await;
    set_interface(0, 0);
    assert!(result.is_ok(), "{result:?}");
}

/// Needs the network: `LOCALPROXY_TEST_IF=<index of the internet
/// interface> cargo test -p proxy-core pinned -- --ignored`.
#[tokio::test]
#[ignore]
async fn pinned_socket_uses_the_given_interface() {
    let index: u32 = std::env::var("LOCALPROXY_TEST_IF")
        .unwrap()
        .parse()
        .unwrap();
    let target: SocketAddr = "1.1.1.1:443".parse().unwrap();
    set_interface(index, 0);
    let good = tcp_connect(target).await;
    set_interface(0xFFF0, 0);
    let bad = tokio::time::timeout(std::time::Duration::from_secs(5), tcp_connect(target)).await;
    set_interface(0, 0);
    assert!(good.is_ok(), "pinned to the real interface: {good:?}");
    assert!(
        !matches!(bad, Ok(Ok(_))),
        "pinned to a missing interface must fail"
    );
}
