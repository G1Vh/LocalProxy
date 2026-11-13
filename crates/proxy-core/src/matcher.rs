//! Rule normalization and host matching.
//!
//! Precedence when several enabled rules match a host:
//! 1. the rule with the longest literal part wins (`api.openai.com` beats `openai.com`);
//! 2. on a tie, exact beats domain-and-subdomains, which beats mask;
//! 3. on a full tie, `direct` beats `proxy`, so an exception always wins.
//!
//! A host no rule matches goes direct.

use std::cmp::Ordering;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use uuid::Uuid;

use crate::config::{MatchType, Rule, RuleAction};

/// Result of matching a host against the rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    pub action: RuleAction,
    /// The rule that decided; `None` when nothing matched.
    pub rule_id: Option<Uuid>,
    /// The rule's own outbound; `None` means the default one.
    pub outbound: Option<Uuid>,
}

impl Decision {
    pub const UNMATCHED: Self = Self {
        action: RuleAction::Direct,
        rule_id: None,
        outbound: None,
    };
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PatternError {
    #[error("пустой шаблон")]
    Empty,
    #[error("в шаблоне есть * или ? — для этого выберите тип «маска»")]
    WildcardNeedsMask,
    #[error("недопустимые символы в шаблоне")]
    InvalidCharacters,
    #[error("подсеть пишется как 149.154.160.0/20 или 2001:db8::/32")]
    InvalidCidr,
}

#[derive(Debug, Clone)]
pub(crate) struct Compiled {
    pub id: Uuid,
    pub match_type: MatchType,
    /// Normalized pattern: a domain for exact / subdomains, a glob for masks,
    /// `network/prefix` for subnets.
    pub pattern: String,
    pub action: RuleAction,
    pub outbound: Option<Uuid>,
    pub literal_len: usize,
    /// Parsed network for [`MatchType::Cidr`].
    pub net: Option<(IpAddr, u8)>,
}

/// Rules compiled for matching, sorted by precedence (strongest first),
/// so the first rule that matches decides. The PAC file relies on this order too.
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    rules: Vec<Compiled>,
    /// Program rules, checked before address rules.
    processes: Vec<Compiled>,
}

impl RuleSet {
    /// Compiles the enabled rules; rules with invalid patterns are skipped and logged.
    pub fn new(rules: &[Rule]) -> Self {
        let mut rules: Vec<Compiled> = rules
            .iter()
            .filter(|r| r.enabled)
            .filter_map(|r| match normalize_pattern(&r.pattern, r.match_type) {
                Ok(pattern) => {
                    let net = (r.match_type == MatchType::Cidr)
                        .then(|| parse_cidr(&pattern).ok())
                        .flatten();
                    // For subnets a longer prefix is the more specific rule.
                    let literal_len = match net {
                        Some((_, prefix)) => usize::from(prefix),
                        None => pattern.chars().filter(|c| !matches!(c, '*' | '?')).count(),
                    };
                    Some(Compiled {
                        id: r.id,
                        match_type: r.match_type,
                        literal_len,
                        pattern,
                        action: r.action,
                        outbound: r.outbound,
                        net,
                    })
                }
                Err(e) => {
                    tracing::warn!(pattern = %r.pattern, "rule skipped: {e}");
                    None
                }
            })
            .collect();
        rules.sort_by(|a, b| precedence(b, a));
        // A full path beats a file name, which beats a mask.
        let (mut processes, rules): (Vec<_>, Vec<_>) = rules
            .into_iter()
            .partition(|r| r.match_type == MatchType::Process);
        processes.sort_by_key(|r| {
            let rank = if r.pattern.contains('\\') {
                0
            } else if r.pattern.contains(['*', '?']) {
                2
            } else {
                1
            };
            (rank, usize::MAX - r.literal_len)
        });
        Self { rules, processes }
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Rules in precedence order, strongest first.
    pub(crate) fn entries(&self) -> &[Compiled] {
        &self.rules
    }

    /// Decision for a connection to `host` by the program at `process` (its
    /// exe path, if known): a program rule wins, then address rules.
    pub fn decide_for(&self, host: &str, process: Option<&str>) -> Decision {
        if let Some(path) = process {
            let path = path.to_lowercase();
            let name = path.rsplit('\\').next().unwrap_or(&path);
            if let Some(r) = self.processes.iter().find(|r| {
                let text = if r.pattern.contains('\\') {
                    &path
                } else {
                    name
                };
                glob(r.pattern.as_bytes(), text.as_bytes())
            }) {
                return Decision {
                    action: r.action,
                    rule_id: Some(r.id),
                    outbound: r.outbound,
                };
            }
        }
        self.decide(host)
    }

    pub fn decide(&self, host: &str) -> Decision {
        let host = normalize_host(host);
        self.rules
            .iter()
            .find(|r| matches(r, &host))
            .map_or(Decision::UNMATCHED, |r| Decision {
                action: r.action,
                rule_id: Some(r.id),
                outbound: r.outbound,
            })
    }
}

fn precedence(a: &Compiled, b: &Compiled) -> Ordering {
    fn type_rank(t: MatchType) -> u8 {
        match t {
            MatchType::Exact => 2,
            MatchType::DomainAndSubdomains => 1,
            MatchType::Mask | MatchType::Cidr | MatchType::Process => 0,
        }
    }
    fn action_rank(a: RuleAction) -> u8 {
        match a {
            RuleAction::Direct => 1,
            RuleAction::Proxy => 0,
        }
    }
    a.literal_len
        .cmp(&b.literal_len)
        .then(type_rank(a.match_type).cmp(&type_rank(b.match_type)))
        .then(action_rank(a.action).cmp(&action_rank(b.action)))
}

fn matches(rule: &Compiled, host: &str) -> bool {
    let p = rule.pattern.as_str();
    match rule.match_type {
        MatchType::Exact => host == p,
        MatchType::DomainAndSubdomains => {
            host == p
                || (host.len() > p.len()
                    && host.ends_with(p)
                    && host.as_bytes()[host.len() - p.len() - 1] == b'.')
        }
        MatchType::Mask => glob(p.as_bytes(), host.as_bytes()),
        MatchType::Cidr => match (host.parse::<IpAddr>(), rule.net) {
            (Ok(addr), Some((net, prefix))) => in_network(addr, net, prefix),
            _ => false,
        },
        MatchType::Process => false,
    }
}

fn in_network(addr: IpAddr, net: IpAddr, prefix: u8) -> bool {
    match (addr, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            u32::from(a) & mask == u32::from(n) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
            u128::from(a) & mask == u128::from(n) & mask
        }
        _ => false,
    }
}

/// Parses `address/prefix` and returns the network address with host bits cleared.
pub fn parse_cidr(input: &str) -> Result<(IpAddr, u8), PatternError> {
    let (addr, prefix) = input
        .trim()
        .split_once('/')
        .ok_or(PatternError::InvalidCidr)?;
    let addr: IpAddr = addr.parse().map_err(|_| PatternError::InvalidCidr)?;
    let prefix: u8 = prefix.parse().map_err(|_| PatternError::InvalidCidr)?;
    let network = match addr {
        IpAddr::V4(a) if prefix <= 32 => {
            let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            IpAddr::V4(Ipv4Addr::from(u32::from(a) & mask))
        }
        IpAddr::V6(a) if prefix <= 128 => {
            let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
            IpAddr::V6(Ipv6Addr::from(u128::from(a) & mask))
        }
        _ => return Err(PatternError::InvalidCidr),
    };
    Ok((network, prefix))
}

/// `*` matches any run of characters (including none and dots), `?` exactly one.
fn glob(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some((p, t));
            p += 1;
        } else if let Some((sp, st)) = star {
            p = sp + 1;
            t = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|&c| c == b'*')
}

/// Normalizes a host from a request: lowercase, no brackets, no trailing dot, punycode.
pub fn normalize_host(host: &str) -> String {
    let host = host.trim();
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let host = host.trim_end_matches('.');
    to_ascii_labels(&host.to_lowercase())
}

/// Turns what a user typed into the canonical pattern for the given match type.
///
/// Accepts things pasted from a browser: `https://Example.com:8443/path` becomes
/// `example.com`; `*.example.com` and `.example.com` are accepted for
/// domain-and-subdomains and mean the same as `example.com`.
pub fn normalize_pattern(input: &str, match_type: MatchType) -> Result<String, PatternError> {
    if match_type == MatchType::Process {
        return normalize_process(input);
    }
    if match_type == MatchType::Cidr {
        let (network, prefix) = parse_cidr(input)?;
        return Ok(format!("{network}/{prefix}"));
    }
    let mut s = input.trim().to_lowercase();
    // `?` starts a query only in a pasted URL; elsewhere it is a mask wildcard.
    let is_url = s.contains("://");
    if let Some(i) = s.find("://") {
        s.drain(..i + 3);
    }
    let cut = if is_url {
        s.find(['/', '?', '#'])
    } else {
        s.find(['/', '#'])
    };
    if let Some(i) = cut {
        s.truncate(i);
    }
    if let Some(i) = s.rfind('@') {
        s.drain(..=i);
    }
    // Strip the port; keep bare IPv6 addresses intact.
    if let Some(inner) = s.strip_prefix('[') {
        s = inner.split(']').next().unwrap_or_default().to_owned();
    } else if s.matches(':').count() == 1 {
        s.truncate(s.find(':').unwrap_or(s.len()));
    }
    let mut s = s.trim_end_matches('.').to_owned();

    if match_type == MatchType::DomainAndSubdomains {
        s = s
            .trim_start_matches("*.")
            .trim_start_matches('.')
            .to_owned();
    }
    if s.is_empty() {
        return Err(PatternError::Empty);
    }
    let has_wildcard = s.contains(['*', '?']);
    if has_wildcard && match_type != MatchType::Mask {
        return Err(PatternError::WildcardNeedsMask);
    }
    let s = to_ascii_labels(&s);
    let allowed =
        |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '*' | '?');
    if !s.chars().all(allowed) {
        return Err(PatternError::InvalidCharacters);
    }
    Ok(s)
}

/// A program: lowercase, backslashes, `.exe` added to a bare name.
fn normalize_process(input: &str) -> Result<String, PatternError> {
    let s = input
        .trim()
        .trim_matches('"')
        .trim()
        .replace('/', "\\")
        .to_lowercase();
    if s.is_empty() {
        return Err(PatternError::Empty);
    }
    if s.chars()
        .any(|c| c.is_control() || matches!(c, '<' | '>' | '|' | '"'))
    {
        return Err(PatternError::InvalidCharacters);
    }
    let name = s.rsplit('\\').next().unwrap_or(&s);
    if name.is_empty() {
        return Err(PatternError::Empty);
    }
    if !name.contains(['.', '*', '?']) {
        return Ok(format!("{s}.exe"));
    }
    Ok(s)
}

/// Punycode-encodes labels with non-ASCII characters, leaving wildcards alone.
fn to_ascii_labels(s: &str) -> String {
    if s.is_ascii() {
        return s.to_owned();
    }
    s.split('.')
        .map(|label| {
            if label.is_ascii() || label.contains(['*', '?']) {
                label.to_owned()
            } else {
                idna::domain_to_ascii(label).unwrap_or_else(|_| label.to_owned())
            }
        })
        .collect::<Vec<_>>()
        .join(".")
}

#[cfg(test)]
mod tests;
