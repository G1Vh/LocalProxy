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
