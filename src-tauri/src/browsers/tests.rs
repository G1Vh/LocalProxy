use super::*;
use serde_json::json;

fn write(path: &Path, value: &Value) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}

#[test]
fn finds_enabled_extensions_that_set_a_proxy() {
    let root = tempfile::tempdir().unwrap();
    let ud = root.path();
    write(
        &ud.join("Local State"),
        &json!({"profile": {"info_cache": {"Profile 1": {"name": "Работа"}}}}),
    );
    let pac = json!({"proxy": {"mode": "pac_script"}});
    write(
        &ud.join("Default").join("Secure Preferences"),
        &json!({"extensions": {"settings": {
            "aaa": {"manifest": {"name": "Plain Name"}, "preferences": pac},
            "bbb": {"manifest": {"name": "Off"}, "preferences": pac, "disable_reasons": [1]},
            "ccc": {"manifest": {"name": "No proxy"}, "preferences": {}},
            "ddd": {"manifest": {"name": "__MSG_extName__", "default_locale": "en"},
                    "path": "ddd/1.0", "preferences": pac}
        }}}),
    );
    write(
        &ud.join("Default")
            .join("Extensions")
            .join("ddd")
            .join("1.0")
            .join("_locales")
            .join("ru")
            .join("messages.json"),
        &json!({"extname": {"message": "Обход блокировок"}}),
    );
    write(
        &ud.join("Profile 1").join("Secure Preferences"),
        &json!({"extensions": {"settings": {
            "eee": {"manifest": {"name": "Old"}, "regular_only_preferences": pac, "state": 1}
        }}}),
    );
    write(
        &ud.join("System Profile").join("Secure Preferences"),
        &json!({}),
    );

    let found = scan_user_data("Edge", ud);
    let names: Vec<_> = found
        .iter()
        .map(|f| (f.profile.as_str(), f.extension.as_str()))
        .collect();
    assert_eq!(
        names,
        [
            ("Default", "Plain Name"),
            ("Default", "Обход блокировок"),
            ("Работа", "Old")
        ]
    );
}

#[test]
fn missing_browser_is_fine() {
    let root = tempfile::tempdir().unwrap();
    assert!(scan_user_data("Chrome", &root.path().join("nope")).is_empty());
}
