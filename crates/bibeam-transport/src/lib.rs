#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod holepunch;
pub mod peer_config;
pub mod rate_limit;
pub mod relay;
pub mod socks5;
pub mod stun;
pub mod tls;
pub mod wg_tunnel;

pub use holepunch::{HolepunchError, simultaneous_open};
pub use peer_config::WgPeerConfig;
pub use rate_limit::{RateLimitConfigError, RateLimitDenied, SessionRateLimiter};
pub use relay::{RelayError, RelayPath};
pub use socks5::{Socks5Error, run_socks5_listener};
pub use stun::{StunError, discover_public_address};
pub use tls::{TlsConfigError, coordinator_client_config};
pub use wg_tunnel::{WgTunnel, WgTunnelError};
