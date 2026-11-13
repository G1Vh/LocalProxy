//! Domain presets. The list lives in the repository (`presets/presets.json`)
//! and is fetched from GitHub at startup, so it can be updated without
//! releasing the app. The copy built into the app is the fallback; the last
//! good download is cached next to the config. Whichever has the higher
//! `revision` wins — bump it with every change to the file.
//!
//! The config only stores which presets are selected. Their entries become
//! rules at runtime, from whatever list is current, so an updated preset
//! applies by itself: new domains start working, removed ones stop.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use proxy_core::config::{Config, MatchType, Rule, RuleAction};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::rules::classify;

/// Namespace for preset rule ids (UUID v5), so an entry keeps its id across
/// restarts and list updates and its hit counter does not reset.
const ENTRY_NAMESPACE: Uuid = Uuid::from_u128(0x6c6f_6361_6c70_5052_8e7d_7072_6573_6574);

pub const REMOTE_URL: &str =
    "https://raw.githubusercontent.com/G1Vh/LocalProxy/main/presets/presets.json";
const FETCH_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_SIZE: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Preset {
    pub id: String,
    pub name: String,
    /// What the set covers and its known limits, shown in the UI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Domains, masks or subnets; see [`classify`].
    pub domains: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresetsFile {
    pub revision: u32,
    pub presets: Vec<Preset>,
}

/// Where the current list came from, for the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Source {
    Bundled,
    Cache,
    Remote,
}

/// One entry of a preset as the routing sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    /// Rule id used in connection events and hit counters.
    pub id: Uuid,
    pub pattern: String,
    pub match_type: MatchType,
}

impl Preset {
    pub fn entries(&self) -> Vec<Entry> {
        self.domains
            .iter()
            .filter_map(|d| classify(d))
            .map(|(pattern, match_type)| Entry {
                id: Uuid::new_v5(
                    &ENTRY_NAMESPACE,
                    format!("{}|{match_type:?}|{pattern}", self.id).as_bytes(),
                ),
                pattern,
                match_type,
            })
            .collect()
    }
}

/// The config the proxy actually runs with: the user's rules plus the
/// entries of every selected preset (proxy rules). The user's own rules keep
/// priority by specificity, so a manual "direct" exception still works.
pub fn effective(config: &Config, file: &PresetsFile) -> Config {
    let mut effective = config.clone();
    for id in &config.presets {
        let Some(preset) = file.presets.iter().find(|p| &p.id == id) else {
            tracing::warn!(preset = %id, "selected preset is not in the list any more");
            continue;
        };
        let outbound = config.preset_outbounds.get(id).copied();
        effective
            .rules
            .extend(preset.entries().into_iter().map(|e| Rule {
                id: e.id,
                enabled: true,
                pattern: e.pattern,
                match_type: e.match_type,
                action: RuleAction::Proxy,
                comment: String::new(),
                outbound,
            }));
    }
    effective
}

pub fn bundled() -> PresetsFile {
    parse(include_str!("../../presets/presets.json")).expect("bundled presets.json is valid")
}

/// Parses and validates a presets file; any bad entry rejects the whole file.
pub fn parse(text: &str) -> Result<PresetsFile, String> {
    let file: PresetsFile =
        serde_json::from_str(text).map_err(|e| format!("не JSON списка наборов: {e}"))?;
    if file.presets.is_empty() {
        return Err("в списке нет ни одного набора".into());
    }
    let mut ids = HashSet::new();
    for preset in &file.presets {
        if preset.id.trim().is_empty() || preset.name.trim().is_empty() {
            return Err("у набора пустой id или название".into());
        }
        if !ids.insert(preset.id.as_str()) {
            return Err(format!("набор «{}» встречается дважды", preset.id));
        }
        if preset.domains.is_empty() {
            return Err(format!("набор «{}» пустой", preset.id));
        }
        if let Some(bad) = preset.domains.iter().find(|d| classify(d).is_none()) {
            return Err(format!("в наборе «{}» неверная запись «{bad}»", preset.id));
        }
    }
    Ok(file)
}

pub fn cache_path(config_dir: &Path) -> PathBuf {
    config_dir.join("presets.json")
}

/// The newest of the bundled list and the cached download.
pub fn load(config_dir: &Path) -> (PresetsFile, Source) {
    let bundled = bundled();
    let cached = std::fs::read_to_string(cache_path(config_dir))
        .ok()
        .and_then(|text| parse(&text).ok());
    match cached {
        Some(cached) if cached.revision > bundled.revision => (cached, Source::Cache),
        _ => (bundled, Source::Bundled),
    }
}

pub fn save_cache(config_dir: &Path, file: &PresetsFile) -> std::io::Result<()> {
    std::fs::create_dir_all(config_dir)?;
    let json = serde_json::to_vec_pretty(file).expect("presets serialize");
    std::fs::write(cache_path(config_dir), json)
}

/// Downloads the list from GitHub, straight, not through the user's proxy.
pub async fn fetch() -> Result<PresetsFile, String> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(FETCH_TIMEOUT)
        .user_agent(concat!("LocalProxy/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| e.to_string())?;
    let response = client
        .get(REMOTE_URL)
        .send()
        .await
        .map_err(|e| format!("GitHub недоступен: {e}"))?;
    if !response.status().is_success() {
        return Err(format!("GitHub ответил {}", response.status()));
    }
    let body = response.bytes().await.map_err(|e| e.to_string())?;
    if body.len() > MAX_SIZE {
        return Err("список наборов подозрительно большой".into());
    }
    parse(&String::from_utf8_lossy(&body))
}

#[cfg(test)]
mod tests {
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
        let bad =
            r#"{"revision": 1, "presets": [{"id": "a", "name": "A", "domains": ["bad host"]}]}"#;
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
}
