use super::*;

#[test]
fn basic_auth_header() {
    let mut ep = ProxyEndpoint {
        host: "h".into(),
        port: 1,
        ..Default::default()
    };
    assert_eq!(basic_auth(&ep), None);
    ep.username = "user".into();
    ep.password = "p@ss:word".into();
    assert_eq!(basic_auth(&ep).unwrap(), "Basic dXNlcjpwQHNzOndvcmQ=");
}
