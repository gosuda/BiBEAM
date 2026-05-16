#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod wg_tunnel;

pub use wg_tunnel::{WgTunnel, WgTunnelError};
