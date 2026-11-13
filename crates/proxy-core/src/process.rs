//! Which program a connection belongs to: Windows keeps the owning process
//! of every TCP connection (GetExtendedTcpTable); its exe path comes from
//! QueryFullProcessImageNameW. No administrator rights needed for programs
//! of the same user; system processes may stay unnamed.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};

/// A process id may be reused by another program after a while.
const PATH_TTL: Duration = Duration::from_secs(30);

/// The exe path of the program on the other end of `stream`, which is a
/// connection accepted on this machine.
pub fn of_local_client(stream: &TcpStream) -> Option<Arc<str>> {
    let (Ok(client), Ok(ours)) = (stream.peer_addr(), stream.local_addr()) else {
        return None;
    };
    if !client.ip().is_loopback() {
        return None;
    }
    image_path(tcp_owner(client, ours)?)
}

/// Owner of the TCP connection `local` → `remote` (as that side sees it).
pub fn tcp_owner(local: SocketAddr, remote: SocketAddr) -> Option<u32> {
    let (family, row_size) = match local.ip() {
        IpAddr::V4(_) => (AF_INET, size_of::<MIB_TCPROW_OWNER_PID>()),
        IpAddr::V6(_) => (AF_INET6, size_of::<MIB_TCP6ROW_OWNER_PID>()),
    };
    let table = tcp_table(u32::from(family))?;
    let count = u32::from_ne_bytes(table.get(..4)?.try_into().ok()?) as usize;
    // Rows start after the count, aligned to 4 bytes.
    let rows = table.get(4..4 + count * row_size)?;
    for row in rows.chunks_exact(row_size) {
        // SAFETY: each chunk is one row of the type the table class gives.
        let (l, r, pid) = unsafe {
            match local.ip() {
                IpAddr::V4(_) => {
                    let row = &*(row.as_ptr().cast::<MIB_TCPROW_OWNER_PID>());
                    (
                        v4(row.dwLocalAddr, row.dwLocalPort),
                        v4(row.dwRemoteAddr, row.dwRemotePort),
                        row.dwOwningPid,
                    )
                }
                IpAddr::V6(_) => {
                    let row = &*(row.as_ptr().cast::<MIB_TCP6ROW_OWNER_PID>());
                    (
                        v6(row.ucLocalAddr, row.dwLocalPort),
                        v6(row.ucRemoteAddr, row.dwRemotePort),
                        row.dwOwningPid,
                    )
                }
            }
        };
        if l == local && r == remote {
            return Some(pid);
        }
    }
    None
}

fn v4(addr: u32, port: u32) -> SocketAddr {
    SocketAddr::new(
        Ipv4Addr::from(addr.to_ne_bytes()).into(),
        u16::from_be(port as u16),
    )
}

fn v6(addr: [u8; 16], port: u32) -> SocketAddr {
    SocketAddr::new(Ipv6Addr::from(addr).into(), u16::from_be(port as u16))
}

fn tcp_table(family: u32) -> Option<Vec<u8>> {
    let mut size = 0u32;
    for _ in 0..3 {
        let mut buf = vec![0u8; size as usize + 4096];
        size = buf.len() as u32;
        // SAFETY: the buffer is `size` bytes long.
        let rc = unsafe {
            GetExtendedTcpTable(
                buf.as_mut_ptr().cast(),
                &mut size,
                0,
                family,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if rc == 0 {
            buf.truncate(size as usize);
            return Some(buf);
        }
        // ERROR_INSUFFICIENT_BUFFER: `size` now says how much; try again.
    }
    None
}

/// Exe path by process id, with when it was looked up.
type PathCache = Mutex<HashMap<u32, (Instant, Option<Arc<str>>)>>;

fn cache() -> &'static PathCache {
    static CACHE: OnceLock<PathCache> = OnceLock::new();
    CACHE.get_or_init(Default::default)
}

/// Full exe path of a process, cached briefly.
pub fn image_path(pid: u32) -> Option<Arc<str>> {
    if pid == 0 || pid == 4 {
        return Some("System".into());
    }
    let mut cache = cache().lock().unwrap_or_else(|e| e.into_inner());
    if let Some((at, path)) = cache.get(&pid)
        && at.elapsed() < PATH_TTL
    {
        return path.clone();
    }
    let path = query_image(pid).map(Arc::from);
    if cache.len() > 4096 {
        cache.clear();
    }
    cache.insert(pid, (Instant::now(), path.clone()));
    path
}

fn query_image(pid: u32) -> Option<String> {
    // SAFETY: plain Win32 calls; the handle is closed before returning.
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return None;
        }
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len);
        CloseHandle(h);
        (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
    }
}

/// File name of an exe path, the way rules and the window show it.
pub fn file_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

#[cfg(test)]
mod tests;
