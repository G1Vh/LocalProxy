//! SOCKS5 inbound (RFC 1928): CONNECT and UDP ASSOCIATE. No authentication;
//! a username/password (RFC 1929) is accepted but not checked, except that
//! the user "process" names the program behind the connection: LocalProxy's
//! TUN mode sends the exe path that way, since its connections all come
//! from the TUN service itself.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::router::{Inbound, RouteError, Router};
use crate::socks5_udp;
use crate::stream::TargetAddr;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

const CMD_CONNECT: u8 = 1;
const CMD_UDP_ASSOCIATE: u8 = 3;

const REP_SUCCEEDED: u8 = 0;
const REP_GENERAL_FAILURE: u8 = 1;
const REP_NOT_ALLOWED: u8 = 2;
const REP_NETWORK_UNREACHABLE: u8 = 3;
const REP_HOST_UNREACHABLE: u8 = 4;
const REP_CONNECTION_REFUSED: u8 = 5;
const REP_TTL_EXPIRED: u8 = 6;
const REP_COMMAND_NOT_SUPPORTED: u8 = 7;
const REP_ADDRESS_NOT_SUPPORTED: u8 = 8;

/// Username that carries the program's exe path in the password.
const PROCESS_USER: &[u8] = b"process";

pub async fn serve(mut client: TcpStream, router: Arc<Router>) {
    let (command, target, named) = match timeout(HANDSHAKE_TIMEOUT, handshake(&mut client)).await {
        Ok(Ok(Some(request))) => request,
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

    // The TUN names the program itself; looking it up costs a walk through
    // the system's TCP table, so only for clients that did not.
    let process = named
        .map(Arc::from)
        .or_else(|| crate::process::of_local_client(&client));
    if command == CMD_UDP_ASSOCIATE {
        // The address in the request is only a hint about the client; ignored.
        return socks5_udp::associate(client, router, process).await;
    }

    match router
        .connect(&target, Inbound::Socks5, process.as_deref())
        .await
    {
        Ok(mut upstream) => {
            if reply(&mut client, REP_SUCCEEDED).await.is_ok()
                && let Err(e) = crate::stream::relay(&mut client, &mut upstream).await
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

/// Negotiates the method and reads the request, with the program named by
/// the client if it did. `Ok(None)` means the client was answered with an
/// error and should be dropped.
async fn handshake(client: &mut TcpStream) -> io::Result<Option<(u8, TargetAddr, Option<String>)>> {
    let mut head = [0u8; 2];
    client.read_exact(&mut head).await?;
    if head[0] != 5 {
        return Ok(None);
    }
    let mut methods = vec![0u8; head[1] as usize];
    client.read_exact(&mut methods).await?;
    let mut named = None;
    if methods.contains(&0) {
        client.write_all(&[5, 0]).await?;
    } else if methods.contains(&2) {
        client.write_all(&[5, 2]).await?;
        named = read_credentials(client).await?;
        client.write_all(&[1, 0]).await?;
    } else {
        client.write_all(&[5, 0xFF]).await?;
        return Ok(None);
    }

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

    if command != CMD_CONNECT && command != CMD_UDP_ASSOCIATE {
        reply(client, REP_COMMAND_NOT_SUPPORTED).await?;
        return Ok(None);
    }
    Ok(Some((command, TargetAddr::new(host, port), named)))
}

/// RFC 1929 username/password; returns the program if the user is "process".
async fn read_credentials(client: &mut TcpStream) -> io::Result<Option<String>> {
    let _version = client.read_u8().await?;
    let mut user = vec![0u8; client.read_u8().await? as usize];
    client.read_exact(&mut user).await?;
    let mut pass = vec![0u8; client.read_u8().await? as usize];
    client.read_exact(&mut pass).await?;
    Ok((user == PROCESS_USER && !pass.is_empty())
        .then(|| String::from_utf8_lossy(&pass).into_owned()))
}

async fn reply(client: &mut TcpStream, code: u8) -> io::Result<()> {
    // Bound address is not meaningful for our clients: 0.0.0.0:0.
    client.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await
}
