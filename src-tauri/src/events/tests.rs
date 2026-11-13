
use super::*;
use proxy_core::{Inbound, RouteKind};

fn event(process: Option<&str>, host: &str, port: u16, error: bool) -> ConnEvent {
    ConnEvent {
        at_ms: 7,
        inbound: Inbound::Socks5,
        host: host.into(),
        port,
        route: if error {
            RouteKind::Failed
        } else {
            RouteKind::Direct
        },
        rule_id: None,
        outbound_id: None,
        process: process.map(str::to_owned),
        error: error.then(|| "отказ".into()),
    }
}

#[test]
fn hides_by_program_host_and_port() {
    let rustdesk = HiddenEvent {
        id: Uuid::new_v4(),
        process: Some("rustdesk.exe".into()),
        host: Some("access.g1vh.tw1.ru".into()),
        port: Some(21114),
        errors_only: true,
    };
    let any_port = HiddenEvent {
        id: Uuid::new_v4(),
        process: None,
        host: Some("telemetry.example".into()),
        port: None,
        errors_only: false,
    };
    let app = r"C:\Program Files\RustDesk\RustDesk.exe";
    let mut batch = vec![
        event(Some(app), "access.g1vh.tw1.ru", 21114, true),
        event(Some(app), "Access.G1vh.Tw1.Ru", 21114, true),
        event(Some(app), "access.g1vh.tw1.ru", 21114, false), // not an error
        event(Some(app), "access.g1vh.tw1.ru", 21116, true),  // other port
        event(Some(r"C:\other.exe"), "access.g1vh.tw1.ru", 21114, true),
        event(None, "access.g1vh.tw1.ru", 21114, true), // program unknown
        event(None, "telemetry.example", 443, false),
    ];
    let mut stats = RuleStats::new();
    assert!(drop_hidden(
        &[rustdesk.clone(), any_port.clone()],
        &mut batch,
        &mut stats
    ));
    let left: Vec<_> = batch
        .iter()
        .map(|e| (e.port, e.error.is_some(), e.process.is_some()))
        .collect();
    assert_eq!(
        left,
        [
            (21114, false, true),
            (21116, true, true),
            (21114, true, true),
            (21114, true, false)
        ]
    );
    assert_eq!(stats[&rustdesk.id].hits, 2);
    assert_eq!(stats[&any_port.id].hits, 1);
    assert_eq!(stats[&rustdesk.id].last_ms, 7);

    let mut quiet = vec![event(None, "x.com", 443, true)];
    assert!(!drop_hidden(&[rustdesk], &mut quiet, &mut stats));
    assert_eq!(quiet.len(), 1);
}
