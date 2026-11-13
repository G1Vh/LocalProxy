
use super::*;
use tokio::io::AsyncReadExt;

#[test]
fn parse_authority_forms() {
    let p = |s| TargetAddr::parse_authority(s, 443);
    assert_eq!(p("example.com"), Some(TargetAddr::new("example.com", 443)));
    assert_eq!(
        p("example.com:8080"),
        Some(TargetAddr::new("example.com", 8080))
    );
    assert_eq!(p("[::1]:80"), Some(TargetAddr::new("::1", 80)));
    assert_eq!(p("[::1]"), Some(TargetAddr::new("::1", 443)));
    assert_eq!(p("2001:db8::1"), Some(TargetAddr::new("2001:db8::1", 443)));
    assert_eq!(p("host:notaport"), None);
    assert_eq!(p(""), None);
    assert_eq!(TargetAddr::new("::1", 80).to_string(), "[::1]:80");
    assert_eq!(TargetAddr::new("a.b", 80).to_string(), "a.b:80");
}

#[tokio::test]
async fn prefixed_yields_prefix_first() {
    let inner: &[u8] = b" world";
    let mut s = Prefixed::new(b"hello".to_vec(), tokio::io::join(inner, tokio::io::sink()));
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    assert_eq!(out, "hello world");
}
