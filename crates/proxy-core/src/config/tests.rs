
use super::*;

fn sample() -> Config {
    let office = Outbound {
        id: Uuid::new_v4(),
        name: "Office".into(),
        kind: OutboundKind::Http(ProxyEndpoint {
            host: "10.20.0.5".into(),
            port: 8080,
            username: "user".into(),
            password: "p@ss".into(),
        }),
    };
    let awg = Outbound {
        id: Uuid::new_v4(),
        name: "VPS".into(),
        kind: OutboundKind::Awg {
            config: "[Interface]\nPrivateKey = x\n".into(),
        },
    };
    Config {
        enabled: true,
        active_outbound_id: Some(office.id),
        outbounds: vec![
            office,
            awg,
            Outbound {
                id: Uuid::new_v4(),
                name: "Work VPN".into(),
                kind: OutboundKind::Sstp(SstpEndpoint {
                    server: "vpn.example.com".into(),
                    username: "alice".into(),
                    password: "secret".into(),
                    ..SstpEndpoint::default()
                }),
            },
        ],
        rules: vec![Rule {
            id: Uuid::new_v4(),
            enabled: true,
            pattern: "openai.com".into(),
            match_type: MatchType::DomainAndSubdomains,
            action: RuleAction::Proxy,
            comment: String::new(),
            outbound: None,
        }],
        presets: vec!["youtube".into()],
        ..Config::default()
    }
}

#[test]
fn used_outbounds_and_forgetting_deleted_ones() {
    let mut config = sample();
    let (office, vpn) = (config.outbounds[0].id, config.outbounds[2].id);
    assert_eq!(config.used_outbounds().len(), 1, "only the default one");
    config.rules[0].outbound = Some(vpn);
    let mut off = config.rules[0].clone();
    off.id = Uuid::new_v4();
    off.enabled = false;
    off.outbound = Some(config.outbounds[1].id);
    config.rules.push(off);
    let used: Vec<_> = config.used_outbounds().iter().map(|o| o.id).collect();
    assert_eq!(used, [office, vpn], "disabled rules do not count");

    config.preset_outbounds.insert("youtube".into(), vpn);
    config.preset_outbounds.insert("unselected".into(), vpn);
    config.outbounds.retain(|o| o.id != vpn);
    assert_eq!(
        config.forget_missing_outbounds(),
        3,
        "a rule and two presets"
    );
    assert_eq!(config.rules[0].outbound, None);
    assert!(config.preset_outbounds.is_empty());
    assert_eq!(config.forget_missing_outbounds(), 0);
}

#[test]
fn missing_file_gives_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let config = Config::load(&dir.path().join("config.json")).unwrap();
    assert_eq!(config, Config::default());
    assert_eq!(config.port, DEFAULT_PORT);
    assert!(config.socks5_enabled);
    assert_eq!(config.on_outbound_down, OnOutboundDown::Block);
}

#[test]
fn save_then_load_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nested").join("config.json");
    let config = sample();
    config.save(&path).unwrap();
    assert_eq!(Config::load(&path).unwrap(), config);
    assert_eq!(config.active_outbound().unwrap().name, "Office");
}

#[test]
fn json_shape_is_stable() {
    let json = serde_json::to_value(sample()).unwrap();
    assert_eq!(json["onOutboundDown"], "block");
    assert_eq!(json["outbounds"][0]["type"], "http");
    assert_eq!(json["outbounds"][0]["host"], "10.20.0.5");
    assert_eq!(json["outbounds"][1]["type"], "awg");
    assert_eq!(json["outbounds"][2]["type"], "sstp");
    assert_eq!(json["outbounds"][2]["server"], "vpn.example.com");
    assert_eq!(json["outbounds"][2]["certSha256"], "");
    assert_eq!(json["rules"][0]["matchType"], "domainAndSubdomains");
    assert_eq!(json["rules"][0]["action"], "proxy");
}

#[test]
fn partial_file_fills_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    fs::write(&path, r#"{"port": 8888, "rules": [{"id": "6f1c1a8e-0000-4000-8000-000000000001", "pattern": "github.com"}]}"#).unwrap();
    let config = Config::load(&path).unwrap();
    assert_eq!(config.port, 8888);
    assert!(config.socks5_enabled);
    let rule = &config.rules[0];
    assert!(rule.enabled);
    assert_eq!(rule.match_type, MatchType::DomainAndSubdomains);
    assert_eq!(rule.action, RuleAction::Proxy);
}

#[test]
fn broken_file_is_moved_aside() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    fs::write(&path, "{ not json").unwrap();
    let (config, err) = Config::load_or_recover(&path);
    assert_eq!(config, Config::default());
    assert!(matches!(err, Some(ConfigError::Parse { .. })));
    assert!(!path.exists());
    assert!(dir.path().join("config.json.broken").exists());
}

#[test]
fn newer_schema_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    fs::write(&path, r#"{"version": 999}"#).unwrap();
    assert!(matches!(
        Config::load(&path),
        Err(ConfigError::UnsupportedVersion { found: 999, .. })
    ));
}
