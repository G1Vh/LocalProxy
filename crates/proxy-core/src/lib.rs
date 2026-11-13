//! LocalProxy engine. Independent of the GUI so it can be tested on its own.
//!
//! One local port accepts HTTP proxy clients (CONNECT and plain HTTP) and
//! SOCKS5 clients. Each connection is matched against the rules: matched hosts
//! go through their channel (outbound), everything else goes direct.

pub mod bind;
pub mod config;
mod forward;
mod http_inbound;
pub mod matcher;
pub mod outbound;
pub mod pac;
pub mod probe;
pub mod process;
pub mod router;
pub mod server;
mod socks5_inbound;
mod socks5_udp;
pub mod stream;
pub mod traffic;

pub use config::Config;
pub use forward::{ForwardState, ForwardStatus};
pub use router::{ConnEvent, Inbound, RouteKind};
pub use server::{ProxyServer, ServerError};
