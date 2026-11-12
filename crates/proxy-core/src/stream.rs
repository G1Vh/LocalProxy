//! Stream plumbing shared by inbounds and outbounds.

use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Any bidirectional byte stream we can tunnel through.
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Io for T {}

pub type BoxIo = Box<dyn Io>;

/// A stream that first yields bytes already read off the wire
/// (e.g. data that arrived together with an upstream proxy's response headers).
pub struct Prefixed<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> Prefixed<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pos < self.prefix.len() {
            let rest = &self.prefix[self.pos..];
            let n = rest.len().min(buf.remaining());
            buf.put_slice(&rest[..n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Destination of a connection: host name or IP literal plus port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetAddr {
    /// Host name or IP literal, without brackets.
    pub host: String,
    pub port: u16,
}

impl TargetAddr {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }

    /// Parses `host`, `host:port`, `[v6]` or `[v6]:port`.
    pub fn parse_authority(s: &str, default_port: u16) -> Option<Self> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        if let Some(rest) = s.strip_prefix('[') {
            let (host, after) = rest.split_once(']')?;
            let port = match after.strip_prefix(':') {
                Some(p) => p.parse().ok()?,
                None if after.is_empty() => default_port,
                None => return None,
            };
            return Some(Self::new(host, port));
        }
        match s.rsplit_once(':') {
            // More than one colon without brackets: a bare IPv6 address.
            Some((host, _)) if host.contains(':') => Some(Self::new(s, default_port)),
            Some((host, port)) => Some(Self::new(host, port.parse().ok()?)),
            None => Some(Self::new(s, default_port)),
        }
    }
}

impl fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

#[cfg(test)]
mod tests {
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
}
