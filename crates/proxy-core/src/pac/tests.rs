use std::process::Command;

use uuid::Uuid;

use super::*;
use crate::config::Rule;

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

fn sample_rules() -> RuleSet {
    use MatchType::*;
    use RuleAction::*;
    RuleSet::new(&[
        rule("openai.com", DomainAndSubdomains, Proxy),
        rule("corp.com", DomainAndSubdomains, Proxy),
        rule("intranet.corp.com", DomainAndSubdomains, Direct),
        rule("api.corp.com", Exact, Proxy),
        rule("cdn-*.example.net", Mask, Proxy),
        rule("node?.local", Mask, Proxy),
        rule("x.com", DomainAndSubdomains, Direct),
        rule("x.com", Exact, Proxy),
        rule("github.com", Exact, Proxy),
        rule("пример.рф", DomainAndSubdomains, Proxy),
        rule("10.1.2.3", Exact, Proxy),
        rule("149.154.160.0/20", Cidr, Proxy),
        rule("149.154.167.0/24", Cidr, Direct),
        rule("2001:b28:f23d::/48", Cidr, Proxy),
    ])
}

const HOSTS: &[&str] = &[
    "openai.com",
    "api.openai.com",
    "notopenai.com",
    "openai.com.evil.net",
    "OpenAI.com.",
    "corp.com",
    "mail.corp.com",
    "intranet.corp.com",
    "wiki.intranet.corp.com",
    "api.corp.com",
    "cdn-1.example.net",
    "cdn-eu.west.example.net",
    "cdn.example.net",
    "node1.local",
    "node12.local",
    "x.com",
    "www.x.com",
    "github.com",
    "api.github.com",
    "xn--e1afmkfd.xn--p1ai",
    "www.xn--e1afmkfd.xn--p1ai",
    "10.1.2.3",
    "10.1.2.4",
    "example.org",
    "localhost",
    "149.154.160.1",
    "149.154.175.200",
    "149.154.176.1",
    "149.154.167.51",
];

#[test]
fn pac_lists_rules_in_precedence_order() {
    let pac = generate(&sample_rules(), 3128, OnOutboundDown::Block);
    let api = pac.find("\"api.corp.com\"").unwrap();
    let corp = pac.find("\"corp.com\"").unwrap();
    assert!(api < corp, "more specific rule must come first");
    assert!(pac.contains("var PROXY = \"PROXY 127.0.0.1:3128\";"));
    let pac = generate(&sample_rules(), 3128, OnOutboundDown::Direct);
    assert!(pac.contains("var PROXY = \"PROXY 127.0.0.1:3128; DIRECT\";"));
}

#[test]
fn version_changes_with_content() {
    let a = generate(&sample_rules(), 3128, OnOutboundDown::Block);
    let b = generate(&sample_rules(), 3129, OnOutboundDown::Block);
    assert_eq!(version(&a), version(&a));
    assert_ne!(version(&a), version(&b));
    assert_eq!(version(&a).len(), 8);
}

/// Runs the generated PAC in Node with a browser-like `shExpMatch` and
/// checks every host against the Rust matcher. Skipped without Node.
#[test]
fn pac_agrees_with_matcher() {
    let rules = sample_rules();
    let pac = generate(&rules, 3128, OnOutboundDown::Block);
    let harness = format!(
        r#"function shExpMatch(s, p) {{
  var re = "^" + p.replace(/[.+^${{}}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".") + "$";
  return new RegExp(re).test(s);
}}
function ip4(s) {{ return s.split(".").reduce(function (a, o) {{ return a * 256 + Number(o); }}, 0); }}
function isInNet(h, p, m) {{
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(h)) throw new Error("isInNet called with a name: " + h);
  var a = ip4(h), n = ip4(p), k = ip4(m);
  for (var b = 31; b >= 0; b--) {{
    var bit = Math.pow(2, b);
    if (Math.floor(k / bit) % 2 === 1 && Math.floor(a / bit) % 2 !== Math.floor(n / bit) % 2) return false;
  }}
  return true;
}}
{pac}
var hosts = {hosts};
console.log(JSON.stringify(hosts.map(function (h) {{ return FindProxyForURL("http://" + h + "/", h); }})));
"#,
        hosts = serde_json::to_string(HOSTS).unwrap(),
    );
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("pac-test.js");
    std::fs::write(&script, harness).unwrap();
    let output = match Command::new("node").arg(&script).output() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("node not available, skipping PAC check: {e}");
            return;
        }
    };
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let results: Vec<String> = serde_json::from_slice(&output.stdout).unwrap();
    for (host, got) in HOSTS.iter().zip(results) {
        let expected = match rules.decide(host).action {
            RuleAction::Proxy => "PROXY 127.0.0.1:3128",
            RuleAction::Direct => "DIRECT",
        };
        assert_eq!(got, expected, "host {host}");
    }
}
