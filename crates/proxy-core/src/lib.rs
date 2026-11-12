//! LocalProxy engine. Independent of the GUI so it can be tested on its own.
//!
//! One local port accepts HTTP proxy clients (CONNECT and plain HTTP) and
//! SOCKS5 clients. Each connection is matched against the rules: matched hosts
//! go through the active outbound, everything else goes direct.

pub mod config;
mod http_inbound;
pub mod matcher;
pub mod outbound;
pub mod router;
pub mod server;
mod socks5_inbound;
pub mod stream;

pub use config::Config;
pub use router::{ConnEvent, Inbound, RouteKind};
pub use server::{ProxyServer, ServerError};
