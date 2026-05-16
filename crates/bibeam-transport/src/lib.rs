#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod peer_config;
pub mod tls;
pub mod wg_tunnel;

pub use peer_config::WgPeerConfig;
pub use tls::{TlsConfigError, coordinator_client_config};
pub use wg_tunnel::{WgTunnel, WgTunnelError};
