
use super::*;

#[test]
fn recognizes_values_we_write() {
    assert!(is_ours("HTTP_PROXY", "http://127.0.0.1:3128"));
    assert!(is_ours("HTTPS_PROXY", "http://127.0.0.1:8080"));
    assert!(is_ours("NO_PROXY", NO_PROXY));
    assert!(!is_ours("HTTP_PROXY", "http://localhost:3128"));
    assert!(!is_ours("HTTP_PROXY", "http://proxy.corp:8080"));
    assert!(!is_ours("NO_PROXY", "localhost"));
}
