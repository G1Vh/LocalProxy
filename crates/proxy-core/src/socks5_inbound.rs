//! SOCKS5 inbound (RFC 1928), no authentication, CONNECT command.
//! UDP ASSOCIATE arrives with the WireGuard/AmneziaWG outbound (stage 5).

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::router::{Inbound, RouteError, Router};
use crate::stream::TargetAddr;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

const REP_SUCCEEDED: u8 = 0;
const REP_GENERAL_FAILURE: u8 = 1;
const REP_NOT_ALLOWED: u8 = 2;
const REP_NETWORK_UNREACHABLE: u8 = 3;
const REP_HOST_UNREACHABLE: u8 = 4;
const REP_CONNECTION_REFUSED: u8 = 5;
const REP_TTL_EXPIRED: u8 = 6;
const REP_COMMAND_NOT_SUPPORTED: u8 = 7;
const REP_ADDRESS_NOT_SUPPORTED: u8 = 8;

pub async fn serve(mut client: TcpStream, router: Arc<Router>) {
    let target = match timeout(HANDSHAKE_TIMEOUT, handshake(&mut client)).await {
        Ok(Ok(Some(target))) => target,
        Ok(Ok(None)) => return,
        Ok(Err(e)) => {
            tracing::debug!("socks5 handshake failed: {e}");
            return;
        }
        Err(_) => {
            tracing::debug!("socks5 handshake timed out");
            return;
        }
    };

    match router.connect(&target, Inbound::Socks5).await {
        Ok(mut upstream) => {
            if reply(&mut client, REP_SUCCEEDED).await.is_ok()
                && let Err(e) = copy_bidirectional(&mut client, &mut upstream).await
            {
                tracing::trace!(%target, "socks5 tunnel closed: {e}");
            }
        }
        Err(e) => {
            let code = match &e {
                RouteError::Blocked(_) => REP_NOT_ALLOWED,
                RouteError::Failed(err) => match err.io_kind() {
                    Some(io::ErrorKind::ConnectionRefused) => REP_CONNECTION_REFUSED,
                    Some(io::ErrorKind::TimedOut) => REP_TTL_EXPIRED,
                    Some(io::ErrorKind::HostUnreachable) => REP_HOST_UNREACHABLE,
                    Some(io::ErrorKind::NetworkUnreachable) => REP_NETWORK_UNREACHABLE,
                    _ => REP_GENERAL_FAILURE,
                },
            };
            let _ = reply(&mut client, code).await;
        }
    }
}

/// Negotiates the method and reads the request.
/// `Ok(None)` means the client was answered with an error and should be dropped.
async fn handshake(client: &mut TcpStream) -> io::Result<Option<TargetAddr>> {
    let mut head = [0u8; 2];
    client.read_exact(&mut head).await?;
    if head[0] != 5 {
        return Ok(None);
    }
    let mut methods = vec![0u8; head[1] as usize];
    client.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        client.write_all(&[5, 0xFF]).await?;
        return Ok(None);
    }
    client.write_all(&[5, 0]).await?;

    let mut request = [0u8; 4];
    client.read_exact(&mut request).await?;
    let [version, command, _reserved, address_type] = request;
    if version != 5 {
        return Ok(None);
    }
    let host = match address_type {
        1 => {
            let mut ip = [0u8; 4];
            client.read_exact(&mut ip).await?;
            Ipv4Addr::from(ip).to_string()
        }
        3 => {
            let len = client.read_u8().await? as usize;
            let mut name = vec![0u8; len];
            client.read_exact(&mut name).await?;
            String::from_utf8_lossy(&name).into_owned()
        }
        4 => {
            let mut ip = [0u8; 16];
            client.read_exact(&mut ip).await?;
            Ipv6Addr::from(ip).to_string()
        }
        _ => {
            reply(client, REP_ADDRESS_NOT_SUPPORTED).await?;
            return Ok(None);
        }
    };
    let port = client.read_u16().await?;

    if command != 1 {
        reply(client, REP_COMMAND_NOT_SUPPORTED).await?;
        return Ok(None);
    }
    Ok(Some(TargetAddr::new(host, port)))
}

async fn reply(client: &mut TcpStream, code: u8) -> io::Result<()> {
    // Bound address is not meaningful for our clients: 0.0.0.0:0.
    client.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await
}
