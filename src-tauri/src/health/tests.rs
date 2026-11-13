use super::*;

fn event(inbound: Inbound, route: RouteKind, outbound: Uuid) -> ConnEvent {
    ConnEvent {
        at_ms: 0,
        inbound,
        host: "x".into(),
        port: 443,
        route,
        rule_id: None,
        outbound_id: (route != RouteKind::Direct).then_some(outbound),
        process: None,
        error: (route == RouteKind::Blocked).then(|| "канал недоступен".into()),
    }
}

#[test]
fn newest_tcp_event_per_outbound_decides() {
    use Inbound::*;
    use RouteKind::*;
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    assert!(verdicts(&[]).is_empty());
    assert!(
        verdicts(&[event(Connect, Direct, a)]).is_empty(),
        "direct says nothing about outbounds"
    );
    let v = verdicts(&[
        event(Connect, Blocked, a),
        event(Http, Proxy, a),
        event(Socks5, Proxy, b),
        event(Connect, Blocked, b),
        event(Udp, Proxy, b),
    ]);
    assert_eq!(v[&a], Health::Up);
    assert!(
        matches!(v[&b], Health::Down { .. }),
        "UDP does not count, the TCP failure stands"
    );
}

#[test]
fn overall_names_the_broken_outbounds() {
    let mk = |name: &str| Outbound {
        id: Uuid::new_v4(),
        name: name.into(),
        kind: proxy_core::config::OutboundKind::Http(ProxyEndpoint::default()),
    };
    let (office, vpn) = (mk("Офис"), mk("VPN"));
    let config = Config {
        outbounds: vec![office.clone(), vpn.clone()],
        ..Config::default()
    };
    let down = |r: &str| Health::Down { reason: r.into() };
    let all_up = BTreeMap::from([(office.id, Health::Up), (vpn.id, Health::Up)]);
    assert_eq!(overall(&config, &all_up), Health::Up);
    let one_down = BTreeMap::from([(office.id, Health::Up), (vpn.id, down("таймаут"))]);
    assert_eq!(overall(&config, &one_down), down("«VPN»: таймаут"));
    let single = BTreeMap::from([(vpn.id, down("таймаут"))]);
    assert_eq!(overall(&config, &single), down("таймаут"), "no name needed");
}
