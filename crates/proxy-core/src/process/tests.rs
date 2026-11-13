use super::*;

#[tokio::test]
async fn finds_our_own_process_on_both_ends() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (accepted, _) = listener.accept().await.unwrap();
    let path = of_local_client(&accepted).expect("owner of the client side");
    let me = std::env::current_exe().unwrap();
    assert!(
        path.eq_ignore_ascii_case(&me.to_string_lossy()),
        "{path} vs {}",
        me.display()
    );
    drop(client);
}

#[tokio::test]
async fn ipv6_loopback_too() {
    let Ok(listener) = tokio::net::TcpListener::bind("[::1]:0").await else {
        return; // no IPv6 here
    };
    let _client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (accepted, _) = listener.accept().await.unwrap();
    assert!(of_local_client(&accepted).is_some());
}

#[test]
fn file_names() {
    assert_eq!(
        file_name(r"C:\Program Files\Discord\Discord.exe"),
        "Discord.exe"
    );
    assert_eq!(file_name("System"), "System");
}
