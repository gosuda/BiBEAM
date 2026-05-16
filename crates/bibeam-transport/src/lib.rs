#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod holepunch;
pub mod peer_config;
pub mod rate_limit;
pub mod relay;
pub mod socks5;
pub mod stun;
pub mod telemetry;
pub mod tls;
pub mod wg_tunnel;

pub use holepunch::{HolepunchError, simultaneous_open};
pub use peer_config::WgPeerConfig;
pub use rate_limit::{RateLimitConfigError, RateLimitDenied, SessionRateLimiter};
pub use relay::{RelayError, RelayPath};
pub use socks5::{Socks5Error, run_socks5_listener};
pub use stun::{StunError, discover_public_address};
pub use telemetry::{
    BYTES_IN_TOTAL, BYTES_OUT_TOTAL, DECRYPT_FAILURE_TOTAL, HOLEPUNCH_STARTED_TOTAL,
    HOLEPUNCH_SUCCEEDED_TOTAL, HOLEPUNCH_TIMED_OUT_TOTAL, TELEMETRY_TARGET,
    WG_HANDSHAKE_COMPLETED_TOTAL, WG_HANDSHAKE_STARTED_TOTAL, record_bytes_in, record_bytes_out,
    record_decrypt_failure, record_handshake_completed, record_handshake_started,
    record_holepunch_started, record_holepunch_succeeded, record_holepunch_timed_out,
};
pub use tls::{TlsConfigError, coordinator_client_config};
pub use wg_tunnel::{WgTunnel, WgTunnelError};
