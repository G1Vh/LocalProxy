use super::*;

#[test]
fn recognizes_our_pac() {
    let mut s = ProxySettings::direct();
    assert!(!s.is_localproxy_pac());
    s.flags |= PROXY_TYPE_AUTO_PROXY_URL;
    s.autoconfig_url = Some("http://127.0.0.1:3128/proxy.pac?v=1".into());
    assert!(s.is_localproxy_pac());
    s.autoconfig_url = Some("http://wpad.corp/proxy.pac".into());
    assert!(!s.is_localproxy_pac());
}

/// Reads the real settings; no changes are made.
#[test]
fn query_reads_current_settings() {
    let s = query().expect("query works for the current user");
    assert!(s.flags & PROXY_TYPE_DIRECT != 0 || s.flags != 0);
}
