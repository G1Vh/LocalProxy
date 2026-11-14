use super::*;

#[test]
fn bundled_list_is_valid() {
    let file = bundled();
    assert!(file.revision >= 1);
    for id in [
        "openai",
        "anthropic",
        "github",
        "gemini",
        "youtube",
        "telegram",
        "discord",
    ] {
        assert!(file.presets.iter().any(|p| p.id == id), "{id}");
    }
}

#[test]
fn selected_presets_expand_from_the_current_list() {
    let preset = |domains: &[&str]| PresetsFile {
        revision: 1,
        presets: vec![Preset {
            id: "yt".into(),
            name: "YouTube".into(),
            note: None,
            group: None,
            domains: domains.iter().map(|d| d.to_string()).collect(),
        }],
    };
    let mut config = Config::default();
    assert!(
        effective(&config, &preset(&["youtube.com"]))
            .rules
            .is_empty()
    );

    config.presets = vec!["yt".into(), "retired".into()];
    let old = effective(&config, &preset(&["youtube.com", "old.example"]));
    let new = effective(
        &config,
        &preset(&["youtube.com", "youtu.be", "149.154.160.0/20"]),
    );
    let patterns = |c: &Config| {
        c.rules
            .iter()
            .map(|r| r.pattern.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(patterns(&old), ["youtube.com", "old.example"]);
    assert_eq!(
        patterns(&new),
        ["youtube.com", "youtu.be", "149.154.160.0/20"]
    );
    assert_eq!(new.rules[2].match_type, MatchType::Cidr);
    assert!(
        new.rules.iter().all(|r| r.outbound.is_none()),
        "default outbound"
    );
    let vpn = uuid::Uuid::new_v4();
    config.preset_outbounds.insert("yt".into(), vpn);
    let routed = effective(&config, &preset(&["youtube.com"]));
    assert_eq!(
        routed.rules[0].outbound,
        Some(vpn),
        "the preset's own outbound"
    );
    assert_eq!(
        old.rules[0].id, new.rules[0].id,
        "ids are stable across updates"
    );
    assert!(
        config.rules.is_empty(),
        "nothing is copied into the user's rules"
    );
}

#[test]
fn rejects_bad_files() {
    assert!(parse("not json").is_err());
    assert!(parse(r#"{"revision": 1, "presets": []}"#).is_err());
    let dup = r#"{"revision": 1, "presets": [
            {"id": "a", "name": "A", "domains": ["a.com"]},
            {"id": "a", "name": "A2", "domains": ["b.com"]}]}"#;
    assert!(parse(dup).is_err());
    let bad = r#"{"revision": 1, "presets": [{"id": "a", "name": "A", "domains": ["bad host"]}]}"#;
    assert!(parse(bad).unwrap_err().contains("bad host"));
}

#[test]
fn newer_cache_wins_older_is_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let mut newer = bundled();
    newer.revision += 1;
    newer.presets.truncate(1);
    save_cache(dir.path(), &newer).unwrap();
    assert_eq!(load(dir.path()), (newer, Source::Cache));

    let mut older = bundled();
    older.revision = 0;
    save_cache(dir.path(), &older).unwrap();
    assert_eq!(load(dir.path()).1, Source::Bundled);

    std::fs::write(cache_path(dir.path()), "garbage").unwrap();
    assert_eq!(load(dir.path()).1, Source::Bundled);
}
