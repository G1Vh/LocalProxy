//! Bulk rule editing: paste a list, import / export.

use proxy_core::config::{Config, MatchType, Rule, RuleAction};
use proxy_core::matcher::{normalize_pattern, parse_cidr};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MergeReport {
    pub added: usize,
    /// Already present (same pattern and match type).
    pub skipped: usize,
    /// Lines that are not valid patterns, as typed.
    pub invalid: Vec<String>,
}

/// Works out the rule type for one entry of a list:
/// `149.154.160.0/20` is a subnet, `*.example.com` means "example.com and
/// subdomains", a wildcard anywhere else makes a mask, the rest is
/// "domain and subdomains", `discord.exe` or a path is a program. Returns the
/// normalized pattern.
pub fn classify(entry: &str) -> Option<(String, MatchType)> {
    let lower = entry.to_lowercase();
    if !lower.contains("://") && (lower.ends_with(".exe") || lower.contains('\\')) {
        let pattern = normalize_pattern(entry, MatchType::Process).ok()?;
        return Some((pattern, MatchType::Process));
    }
    if parse_cidr(entry).is_ok() {
        let pattern = normalize_pattern(entry, MatchType::Cidr).ok()?;
        return Some((pattern, MatchType::Cidr));
    }
    // Normalizing as a mask strips URL parts but keeps wildcards.
    let as_mask = normalize_pattern(entry, MatchType::Mask).ok()?;
    let bare = as_mask.trim_prefix("*.");
    if bare.contains(['*', '?']) {
        Some((as_mask.clone(), MatchType::Mask))
    } else {
        Some((bare.to_owned(), MatchType::DomainAndSubdomains))
    }
}

/// Adds one proxy rule per line (see [`classify`]); `#` starts a comment.
/// Duplicates are skipped.
pub fn add_lines(config: &mut Config, text: &str) -> MergeReport {
    let mut report = MergeReport::default();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let Some((pattern, match_type)) = classify(line) else {
            report.invalid.push(line.to_owned());
            continue;
        };
        let rule = Rule {
            id: Uuid::new_v4(),
            enabled: true,
            pattern,
            match_type,
            action: RuleAction::Proxy,
            comment: String::new(),
            outbound: None,
        };
        merge_one(config, rule, &mut report);
    }
    report
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RulesFile {
    format: String,
    version: u32,
    rules: Vec<ExportedRule>,
    /// Selected preset ids.
    #[serde(default)]
    presets: Vec<String>,
}

const FORMAT: &str = "localproxy-rules";

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExportedRule {
    pattern: String,
    #[serde(default)]
    match_type: MatchType,
    #[serde(default)]
    action: RuleAction,
    #[serde(default = "yes")]
    enabled: bool,
    #[serde(default)]
    comment: String,
}

fn yes() -> bool {
    true
}

pub fn export(config: &Config) -> String {
    let file = RulesFile {
        format: FORMAT.into(),
        version: 1,
        rules: config
            .rules
            .iter()
            .map(|r| ExportedRule {
                pattern: r.pattern.clone(),
                match_type: r.match_type,
                action: r.action,
                enabled: r.enabled,
                comment: r.comment.clone(),
            })
            .collect(),
        presets: config.presets.clone(),
    };
    serde_json::to_string_pretty(&file).expect("rules serialize")
}

/// Accepts our JSON export (rules and selected presets) or a plain list of
/// domains, one per line.
pub fn import(config: &mut Config, text: &str) -> MergeReport {
    let Ok(file) = serde_json::from_str::<RulesFile>(text) else {
        return add_lines(config, text);
    };
    let mut report = MergeReport::default();
    for r in file.rules {
        let rule = Rule {
            id: Uuid::new_v4(),
            enabled: r.enabled,
            pattern: r.pattern,
            match_type: r.match_type,
            action: r.action,
            comment: r.comment,
            outbound: None,
        };
        merge_one(config, rule, &mut report);
    }
    for id in file.presets {
        if !config.presets.contains(&id) {
            config.presets.push(id);
        }
    }
    report
}

fn merge_one(config: &mut Config, mut rule: Rule, report: &mut MergeReport) {
    let Ok(pattern) = normalize_pattern(&rule.pattern, rule.match_type) else {
        report.invalid.push(rule.pattern);
        return;
    };
    let exists = config.rules.iter().any(|r| {
        r.match_type == rule.match_type
            && normalize_pattern(&r.pattern, r.match_type).as_deref() == Ok(pattern.as_str())
    });
    if exists {
        report.skipped += 1;
        return;
    }
    rule.pattern = pattern;
    config.rules.push(rule);
    report.added += 1;
}

#[cfg(test)]
mod tests;
