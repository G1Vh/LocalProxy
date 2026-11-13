//! While the TUN adapter takes all of the system's traffic, LocalProxy's own
//! connections out (direct ones and those to upstream proxies) must not go
//! back into it: each would loop through the TUN into LocalProxy again.
//! They are pinned to the physical interface instead (IP_UNICAST_IF), which
//! keeps its own default route. Loopback is never pinned.

use std::io;
use std::net::SocketAddr;
use std::os::windows::io::AsRawSocket;
use std::sync::atomic::{AtomicU32, Ordering};

use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use windows_sys::Win32::Networking::WinSock::{IPPROTO_IP, IPPROTO_IPV6, SOCKET, setsockopt};

const IP_UNICAST_IF: i32 = 31;
const IPV6_UNICAST_IF: i32 = 31;

static IF4: AtomicU32 = AtomicU32::new(0);
static IF6: AtomicU32 = AtomicU32::new(0);

/// Pins new outgoing sockets to these interface indexes; 0 releases a family.
pub fn set_interface(v4: u32, v6: u32) {
    IF4.store(v4, Ordering::Relaxed);
    IF6.store(v6, Ordering::Relaxed);
    tracing::info!(v4, v6, "outgoing sockets pinned to interface");
}

/// Current pins (0: none).
pub fn interface() -> (u32, u32) {
    (IF4.load(Ordering::Relaxed), IF6.load(Ordering::Relaxed))
}

fn pin(socket: SOCKET, v6: bool) -> io::Result<()> {
    let (level, name, value) = if v6 {
        (IPPROTO_IPV6, IPV6_UNICAST_IF, IF6.load(Ordering::Relaxed))
    } else {
        // The IPv4 option takes the index in network byte order.
        (
            IPPROTO_IP,
            IP_UNICAST_IF,
            IF4.load(Ordering::Relaxed).to_be(),
        )
    };
    if value == 0 {
        return Ok(());
    }
    // SAFETY: a valid socket and a 4-byte option value that outlives the call.
    let rc = unsafe {
        setsockopt(
            socket,
            level,
            name,
            (&value as *const u32).cast(),
            size_of::<u32>() as i32,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// A TCP connection to `addr`, pinned unless it is loopback.
pub(crate) async fn tcp_connect(addr: SocketAddr) -> io::Result<TcpStream> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    if !addr.ip().is_loopback() {
        pin(socket.as_raw_socket() as SOCKET, addr.is_ipv6())?;
    }
    socket.connect(addr).await
}

/// Pins a UDP socket that sends beyond this machine.
pub(crate) fn pin_udp(socket: &UdpSocket, v6: bool) -> io::Result<()> {
    pin(socket.as_raw_socket() as SOCKET, v6)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn loopback_is_never_pinned() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        // An interface that does not exist would break a pinned socket.
        set_interface(0xFFFF, 0xFFFF);
        let result = tcp_connect(addr).await;
        set_interface(0, 0);
        assert!(result.is_ok(), "{result:?}");
    }

    /// Needs the network: `LOCALPROXY_TEST_IF=<index of the internet
    /// interface> cargo test -p proxy-core pinned -- --ignored`.
    #[tokio::test]
    #[ignore]
    async fn pinned_socket_uses_the_given_interface() {
        let index: u32 = std::env::var("LOCALPROXY_TEST_IF")
            .unwrap()
            .parse()
            .unwrap();
        let target: SocketAddr = "1.1.1.1:443".parse().unwrap();
        set_interface(index, 0);
        let good = tcp_connect(target).await;
        set_interface(0xFFF0, 0);
        let bad =
            tokio::time::timeout(std::time::Duration::from_secs(5), tcp_connect(target)).await;
        set_interface(0, 0);
        assert!(good.is_ok(), "pinned to the real interface: {good:?}");
        assert!(
            !matches!(bad, Ok(Ok(_))),
            "pinned to a missing interface must fail"
        );
    }
}
