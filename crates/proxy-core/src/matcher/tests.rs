
use super::*;

fn rule(pattern: &str, match_type: MatchType, action: RuleAction) -> Rule {
    Rule {
        id: Uuid::new_v4(),
        enabled: true,
        pattern: pattern.into(),
        match_type,
        action,
        comment: String::new(),
        outbound: None,
    }
}

fn proxy(pattern: &str, t: MatchType) -> Rule {
    rule(pattern, t, RuleAction::Proxy)
}

fn direct(pattern: &str, t: MatchType) -> Rule {
    rule(pattern, t, RuleAction::Direct)
}

use MatchType::{DomainAndSubdomains as Sub, Exact, Mask};

fn action(set: &RuleSet, host: &str) -> RuleAction {
    set.decide(host).action
}

#[test]
fn nothing_matches_goes_direct() {
    let set = RuleSet::new(&[proxy("openai.com", Sub)]);
    assert_eq!(set.decide("example.com"), Decision::UNMATCHED);
    assert_eq!(RuleSet::default().decide("openai.com"), Decision::UNMATCHED);
}

#[test]
fn exact_matches_only_itself() {
    let set = RuleSet::new(&[proxy("github.com", Exact)]);
    assert_eq!(action(&set, "github.com"), RuleAction::Proxy);
    assert_eq!(action(&set, "api.github.com"), RuleAction::Direct);
    assert_eq!(action(&set, "notgithub.com"), RuleAction::Direct);
}

#[test]
fn subdomains_include_apex_but_respect_label_boundary() {
    let set = RuleSet::new(&[proxy("openai.com", Sub)]);
    for host in [
        "openai.com",
        "api.openai.com",
        "a.b.openai.com",
        "OpenAI.COM.",
        "api.openai.com:443",
    ] {
        let host = host.split(':').next().unwrap();
        assert_eq!(action(&set, host), RuleAction::Proxy, "{host}");
    }
    assert_eq!(action(&set, "notopenai.com"), RuleAction::Direct);
    assert_eq!(action(&set, "openai.com.evil.net"), RuleAction::Direct);
}

#[test]
fn mask_globs_whole_host() {
    let set = RuleSet::new(&[proxy("cdn-*.example.net", Mask)]);
    assert_eq!(action(&set, "cdn-1.example.net"), RuleAction::Proxy);
    assert_eq!(action(&set, "cdn-eu.west.example.net"), RuleAction::Proxy);
    assert_eq!(action(&set, "cdn.example.net"), RuleAction::Direct);

    let set = RuleSet::new(&[proxy("*.example.com", Mask)]);
    assert_eq!(action(&set, "a.example.com"), RuleAction::Proxy);
    assert_eq!(action(&set, "example.com"), RuleAction::Direct);

    let set = RuleSet::new(&[proxy("node?.local", Mask)]);
    assert_eq!(action(&set, "node1.local"), RuleAction::Proxy);
    assert_eq!(action(&set, "node12.local"), RuleAction::Direct);
}

#[test]
fn more_specific_exception_wins() {
    let set = RuleSet::new(&[proxy("corp.com", Sub), direct("intranet.corp.com", Sub)]);
    assert_eq!(action(&set, "corp.com"), RuleAction::Proxy);
    assert_eq!(action(&set, "mail.corp.com"), RuleAction::Proxy);
    assert_eq!(action(&set, "intranet.corp.com"), RuleAction::Direct);
    assert_eq!(action(&set, "wiki.intranet.corp.com"), RuleAction::Direct);
}

#[test]
fn more_specific_proxy_wins_over_broad_exception() {
    let set = RuleSet::new(&[direct("corp.com", Sub), proxy("api.corp.com", Exact)]);
    assert_eq!(action(&set, "api.corp.com"), RuleAction::Proxy);
    assert_eq!(action(&set, "www.corp.com"), RuleAction::Direct);
}

#[test]
fn ties_prefer_exact_then_direct() {
    let set = RuleSet::new(&[direct("x.com", Sub), proxy("x.com", Exact)]);
    assert_eq!(action(&set, "x.com"), RuleAction::Proxy);

    let set = RuleSet::new(&[proxy("x.com", Sub), direct("x.com", Sub)]);
    assert_eq!(action(&set, "x.com"), RuleAction::Direct);
}

#[test]
fn decision_reports_rule_id() {
    let r = proxy("openai.com", Sub);
    let set = RuleSet::new(std::slice::from_ref(&r));
    assert_eq!(set.decide("api.openai.com").rule_id, Some(r.id));
}

#[test]
fn disabled_and_invalid_rules_are_ignored() {
    let mut off = proxy("openai.com", Sub);
    off.enabled = false;
    let bad = proxy("open*.com", Sub);
    let set = RuleSet::new(&[off, bad]);
    assert!(set.is_empty());
}

#[test]
fn ip_literals() {
    let set = RuleSet::new(&[proxy("10.1.2.3", Exact), proxy("[2001:db8::1]:443", Exact)]);
    assert_eq!(action(&set, "10.1.2.3"), RuleAction::Proxy);
    assert_eq!(action(&set, "[2001:db8::1]"), RuleAction::Proxy);
    assert_eq!(action(&set, "2001:db8::1"), RuleAction::Proxy);
}

#[test]
fn idn_hosts() {
    let set = RuleSet::new(&[proxy("пример.рф", Sub)]);
    assert_eq!(action(&set, "xn--e1afmkfd.xn--p1ai"), RuleAction::Proxy);
    assert_eq!(action(&set, "www.пример.рф"), RuleAction::Proxy);
}

#[test]
fn pattern_normalization() {
    let n = |s, t| normalize_pattern(s, t);
    assert_eq!(
        n("https://Chat.OpenAI.com/c/123?x=1", Sub).unwrap(),
        "chat.openai.com"
    );
    assert_eq!(n("*.openai.com", Sub).unwrap(), "openai.com");
    assert_eq!(n(".openai.com", Sub).unwrap(), "openai.com");
    assert_eq!(n("example.com:8443", Exact).unwrap(), "example.com");
    assert_eq!(n("user:pw@host.io", Exact).unwrap(), "host.io");
    assert_eq!(n("example.com.", Exact).unwrap(), "example.com");
    assert_eq!(n("2001:db8::1", Exact).unwrap(), "2001:db8::1");
    assert_eq!(n("*.example.com", Mask).unwrap(), "*.example.com");
    assert_eq!(n("   ", Sub), Err(PatternError::Empty));
    assert_eq!(
        n("*.example.com", Exact),
        Err(PatternError::WildcardNeedsMask)
    );
    assert_eq!(
        n("exa mple.com", Exact),
        Err(PatternError::InvalidCharacters)
    );
}

#[test]
fn cidr_rules() {
    use MatchType::Cidr;
    let set = RuleSet::new(&[
        proxy("149.154.160.0/20", Cidr),
        proxy("2001:b28:f23d::/48", Cidr),
        direct("149.154.167.0/24", Cidr),
        proxy("10.0.0.0/8", Cidr),
    ]);
    assert_eq!(action(&set, "149.154.160.1"), RuleAction::Proxy);
    assert_eq!(action(&set, "149.154.175.255"), RuleAction::Proxy);
    assert_eq!(action(&set, "149.154.176.0"), RuleAction::Direct);
    assert_eq!(
        action(&set, "149.154.167.51"),
        RuleAction::Direct,
        "/24 beats /20"
    );
    assert_eq!(action(&set, "2001:b28:f23d:f001::a"), RuleAction::Proxy);
    assert_eq!(action(&set, "[2001:b28:f23d::1]"), RuleAction::Proxy);
    assert_eq!(action(&set, "2001:b28:f23e::1"), RuleAction::Direct);
    assert_eq!(
        action(&set, "telegram.org"),
        RuleAction::Direct,
        "names never hit subnets"
    );

    let n = |s| normalize_pattern(s, Cidr);
    assert_eq!(n(" 149.154.167.51/20 ").unwrap(), "149.154.160.0/20");
    assert_eq!(n("2001:b28:f23d:1::/48").unwrap(), "2001:b28:f23d::/48");
    assert_eq!(n("0.0.0.0/0").unwrap(), "0.0.0.0/0");
    assert_eq!(n("1.2.3.4/33"), Err(PatternError::InvalidCidr));
    assert_eq!(n("1.2.3.4"), Err(PatternError::InvalidCidr));
    assert_eq!(n("example.com/8"), Err(PatternError::InvalidCidr));
}

#[test]
fn glob_edge_cases() {
    assert!(glob(b"*", b"anything.at.all"));
    assert!(glob(b"a*b*c", b"aXXbYYc"));
    assert!(!glob(b"a*b*c", b"aXXbYY"));
    assert!(glob(b"**.x", b"a.x"));
    assert!(!glob(b"", b"a"));
}

#[test]
fn program_rules_win_over_addresses() {
    let rule = |pattern: &str, match_type: MatchType, action: RuleAction| Rule {
        id: Uuid::new_v4(),
        enabled: true,
        pattern: normalize_pattern(pattern, match_type).unwrap(),
        match_type,
        action,
        comment: String::new(),
        outbound: None,
    };
    let discord = rule("Discord", MatchType::Process, RuleAction::Proxy);
    let steam = rule("steam*.exe", MatchType::Process, RuleAction::Direct);
    let full = rule(
        r"C:\Games\Steam\steam.exe",
        MatchType::Process,
        RuleAction::Proxy,
    );
    let domain = rule(
        "discord.com",
        MatchType::DomainAndSubdomains,
        RuleAction::Direct,
    );
    let set = RuleSet::new(&[discord.clone(), steam.clone(), full.clone(), domain.clone()]);

    let app = r"C:\Users\me\AppData\Local\Discord\app-1.0\Discord.exe";
    assert_eq!(
        set.decide_for("discord.com", Some(app)).rule_id,
        Some(discord.id),
        "program beats address"
    );
    assert_eq!(
        set.decide_for("discord.com", None).rule_id,
        Some(domain.id),
        "unknown program: address rules"
    );
    assert_eq!(
        set.decide_for("x.com", Some(r"D:\steamwebhelper.exe"))
            .rule_id,
        Some(steam.id),
        "mask"
    );
    assert_eq!(
        set.decide_for("x.com", Some(r"C:\Games\Steam\steam.exe"))
            .rule_id,
        Some(full.id),
        "a full path beats a mask"
    );
    assert_eq!(set.decide_for("x.com", Some(r"C:\other.exe")).rule_id, None);
    assert_eq!(
        normalize_pattern(" Discord ", MatchType::Process).unwrap(),
        "discord.exe"
    );
    assert_eq!(
        normalize_pattern("C:/Apps/Tool.EXE", MatchType::Process).unwrap(),
        r"c:\apps\tool.exe"
    );
    assert!(normalize_pattern("bad|name", MatchType::Process).is_err());
}
