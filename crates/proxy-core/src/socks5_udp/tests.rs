use super::*;

#[test]
fn header_roundtrip() {
    let addr: SocketAddr = "203.0.113.7:5353".parse().unwrap();
    let mut d = udp_header(addr);
    d.extend_from_slice(b"hi");
    let (target, payload) = parse_udp_header(&d).unwrap();
    assert_eq!(target, TargetAddr::new("203.0.113.7", 5353));
    assert_eq!(payload, b"hi");

    let mut named = vec![0, 0, 0, 3, 9];
    named.extend_from_slice(b"localhost");
    named.extend_from_slice(&53u16.to_be_bytes());
    named.extend_from_slice(b"q");
    let (target, payload) = parse_udp_header(&named).unwrap();
    assert_eq!(target, TargetAddr::new("localhost", 53));
    assert_eq!(payload, b"q");

    let v6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
    let (target, _) = parse_udp_header(&udp_header(v6)).unwrap();
    assert_eq!(target, TargetAddr::new("2001:db8::1", 443));
}

#[test]
fn rejects_fragments_and_garbage() {
    assert!(parse_udp_header(&[0, 0, 1, 1, 1, 2, 3, 4, 0, 53]).is_none());
    assert!(parse_udp_header(&[0, 0, 0, 1, 1, 2]).is_none());
    assert!(parse_udp_header(&[0, 0, 0, 3, 20, b'a']).is_none());
    assert!(parse_udp_header(&[0, 0, 0, 9]).is_none());
}
