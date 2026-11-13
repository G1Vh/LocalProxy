use super::*;

#[test]
fn strips_hop_by_hop_and_connection_listed() {
    let mut h = HeaderMap::new();
    h.insert(
        header::CONNECTION,
        HeaderValue::from_static("keep-alive, X-Custom"),
    );
    h.insert("x-custom", HeaderValue::from_static("1"));
    h.insert("keep-alive", HeaderValue::from_static("timeout=5"));
    h.insert(
        header::PROXY_AUTHORIZATION,
        HeaderValue::from_static("Basic x"),
    );
    h.append(header::SET_COOKIE, HeaderValue::from_static("a=1"));
    h.append(header::SET_COOKIE, HeaderValue::from_static("b=2"));
    strip_hop_by_hop(&mut h, false);
    assert!(!h.contains_key("x-custom"));
    assert!(!h.contains_key(header::CONNECTION));
    assert!(!h.contains_key("keep-alive"));
    assert!(!h.contains_key(header::PROXY_AUTHORIZATION));
    assert_eq!(h.get_all(header::SET_COOKIE).iter().count(), 2);
}

#[test]
fn keeps_upgrade_when_asked() {
    let mut h = HeaderMap::new();
    h.insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
    h.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
    assert!(is_upgrade(&h));
    strip_hop_by_hop(&mut h, true);
    assert_eq!(h.get(header::UPGRADE).unwrap(), "websocket");
    assert_eq!(h.get(header::CONNECTION).unwrap(), "upgrade");
}
