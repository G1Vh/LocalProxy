//! Finds browser extensions that took over the proxy setting.
//!
//! In Chromium browsers an extension that sets a proxy (chrome.proxy API)
//! outranks the Windows settings, so the browser stops reading our PAC. We
//! cannot override that, but we can tell the user which extension does it.
//! Chromium keeps such settings in the profile's `Secure Preferences` under
//! `extensions.settings.<id>.preferences.proxy`.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::Value;

/// Chromium browsers and their `User Data` folders under `%LOCALAPPDATA%`.
const BROWSERS: &[(&str, &str)] = &[
    ("Edge", r"Microsoft\Edge\User Data"),
    ("Chrome", r"Google\Chrome\User Data"),
    ("Яндекс.Браузер", r"Yandex\YandexBrowser\User Data"),
    ("Brave", r"BraveSoftware\Brave-Browser\User Data"),
    ("Vivaldi", r"Vivaldi\User Data"),
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyExtension {
    pub browser: String,
    /// Profile name as the browser shows it, e.g. "Профиль 1".
    pub profile: String,
    pub extension: String,
    pub id: String,
}

pub fn scan() -> Vec<ProxyExtension> {
    let Some(local) = std::env::var_os("LOCALAPPDATA").map(PathBuf::from) else {
        return Vec::new();
    };
    BROWSERS
        .iter()
        .flat_map(|(browser, dir)| scan_user_data(browser, &local.join(dir)))
        .collect()
}

/// Scans one browser's `User Data` folder (all profiles).
pub fn scan_user_data(browser: &str, user_data: &Path) -> Vec<ProxyExtension> {
    let Ok(dirs) = fs::read_dir(user_data) else {
        return Vec::new();
    };
    let local_state = read_json(&user_data.join("Local State"));
    let mut found = Vec::new();
    let mut profiles: Vec<PathBuf> = dirs
        .flatten()
        .map(|d| d.path())
        .filter(|p| {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or_default();
            name == "Default" || name.starts_with("Profile ")
        })
        .collect();
    profiles.sort();

    for profile in profiles {
        let dir_name = profile
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_owned();
        let shown = local_state
            .as_ref()
            .and_then(|s| s.pointer(&format!("/profile/info_cache/{dir_name}/name")))
            .and_then(Value::as_str)
            .unwrap_or(&dir_name)
            .to_owned();
        for file in ["Secure Preferences", "Preferences"] {
            let Some(prefs) = read_json(&profile.join(file)) else {
                continue;
            };
            let Some(settings) = prefs
                .pointer("/extensions/settings")
                .and_then(Value::as_object)
            else {
                continue;
            };
            for (id, ext) in settings {
                if controls_proxy(ext)
                    && !found
                        .iter()
                        .any(|f: &ProxyExtension| &f.id == id && f.profile == shown)
                {
                    found.push(ProxyExtension {
                        browser: browser.to_owned(),
                        profile: shown.clone(),
                        extension: extension_name(&profile, id, ext),
                        id: id.clone(),
                    });
                }
            }
        }
    }
    found
}

fn controls_proxy(ext: &Value) -> bool {
    let sets_proxy = ["/preferences/proxy", "/regular_only_preferences/proxy"]
        .iter()
        .any(|p| ext.pointer(p).is_some());
    // Disabled extensions keep a non-empty `disable_reasons` (or `state: 0` in older builds).
    let disabled = match ext.get("disable_reasons") {
        Some(Value::Array(reasons)) => !reasons.is_empty(),
        Some(Value::Number(n)) => n.as_u64() != Some(0),
        _ => false,
    } || ext.get("state").and_then(Value::as_u64) == Some(0);
    sets_proxy && !disabled
}

/// The extension's name; `__MSG_key__` names are looked up in its locale files.
fn extension_name(profile: &Path, id: &str, ext: &Value) -> String {
    let manifest_name = ext.pointer("/manifest/name").and_then(Value::as_str);
    let Some(name) = manifest_name else {
        return id.to_owned();
    };
    let Some(key) = name
        .strip_prefix("__MSG_")
        .and_then(|n| n.strip_suffix("__"))
    else {
        return name.to_owned();
    };
    let ext_dir = ext
        .get("path")
        .and_then(Value::as_str)
        .map(|p| profile.join("Extensions").join(p));
    let default_locale = ext
        .pointer("/manifest/default_locale")
        .and_then(Value::as_str)
        .unwrap_or("en");
    ext_dir
        .and_then(|dir| {
            ["ru", default_locale, "en"].iter().find_map(|locale| {
                let messages = read_json(&dir.join("_locales").join(locale).join("messages.json"))?;
                messages.as_object()?.iter().find_map(|(k, v)| {
                    k.eq_ignore_ascii_case(key)
                        .then(|| v.get("message")?.as_str().map(str::to_owned))
                        .flatten()
                })
            })
        })
        .unwrap_or_else(|| id.to_owned())
}

fn read_json(path: &Path) -> Option<Value> {
    serde_json::from_slice(&fs::read(path).ok()?).ok()
}

#[cfg(test)]
mod tests;
