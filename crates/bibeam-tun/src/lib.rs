#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod device;
pub mod inbound;
pub mod mtu;
pub mod outbound;
pub mod parser;

pub use device::{TunDevice, TunError};
pub use inbound::InboundPipeline;
pub use mtu::{DEFAULT_MTU, TUNNEL_OVERHEAD, clamp_tcp_mss, negotiated_mss};
pub use outbound::OutboundPipeline;
pub use parser::{ParseError, ParsedPacket, parse};
