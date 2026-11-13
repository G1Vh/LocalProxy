
use super::*;

#[test]
fn classify_entries() {
    assert_eq!(
        classify("149.154.167.51/20"),
        Some(("149.154.160.0/20".into(), MatchType::Cidr))
    );
    assert_eq!(
        classify("2001:b28:f23d::/48"),
        Some(("2001:b28:f23d::/48".into(), MatchType::Cidr))
    );
    assert_eq!(
        classify("*.youtube.com"),
        Some(("youtube.com".into(), MatchType::DomainAndSubdomains))
    );
    assert_eq!(
        classify("cdn-*.x.net"),
        Some(("cdn-*.x.net".into(), MatchType::Mask))
    );
    assert_eq!(classify("bad host"), None);
    assert_eq!(
        classify("Discord.exe"),
        Some(("discord.exe".into(), MatchType::Process))
    );
    assert_eq!(
        classify(r"C:\Apps\Tool"),
        Some((r"c:\apps\tool.exe".into(), MatchType::Process))
    );
}

#[test]
fn paste_list_normalizes_and_skips_duplicates() {
    let mut config = Config::default();
    let report = add_lines(
        &mut config,
        "https://Chat.OpenAI.com/c/1\n# comment\n\n*.openai.com\ncdn-*.x.net  # cdn\nbad host\nchat.openai.com",
    );
    assert_eq!(report.added, 3);
    assert_eq!(report.skipped, 1);
    assert_eq!(report.invalid, vec!["bad host"]);
    let patterns: Vec<_> = config.rules.iter().map(|r| r.pattern.as_str()).collect();
    assert_eq!(patterns, ["chat.openai.com", "openai.com", "cdn-*.x.net"]);
    assert_eq!(config.rules[2].match_type, MatchType::Mask);
    assert!(
        config
            .rules
            .iter()
            .all(|r| r.action == RuleAction::Proxy && r.enabled)
    );
}

#[test]
fn export_import_roundtrip() {
    let mut source = Config::default();
    add_lines(&mut source, "openai.com\ngithub.com");
    source.rules[1].action = RuleAction::Direct;
    source.rules[1].enabled = false;
    source.rules[1].comment = "exception".into();
    source.presets = vec!["youtube".into(), "telegram".into()];
    let text = export(&source);

    let mut target = Config::default();
    add_lines(&mut target, "openai.com");
    target.presets = vec!["youtube".into()];
    let report = import(&mut target, &text);
    assert_eq!((report.added, report.skipped), (1, 1));
    let github = target
        .rules
        .iter()
        .find(|r| r.pattern == "github.com")
        .unwrap();
    assert_eq!(github.action, RuleAction::Direct);
    assert!(!github.enabled);
    assert_eq!(github.comment, "exception");
    assert_eq!(target.presets, ["youtube", "telegram"]);
}

#[test]
fn import_plain_text() {
    let mut config = Config::default();
    let report = import(&mut config, "example.com\nexample.org\n");
    assert_eq!(report.added, 2);
}
