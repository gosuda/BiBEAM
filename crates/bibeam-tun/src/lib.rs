#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod backpressure;
pub mod device;
pub mod flow;
pub mod inbound;
pub mod mtu;
pub mod outbound;
pub mod parser;

pub use backpressure::{DEFAULT_CHANNEL_BOUND, bounded_packet_channel};
pub use device::{TunDevice, TunError};
pub use flow::{FlowKey, FlowState, FlowTable};
pub use inbound::InboundPipeline;
pub use mtu::{DEFAULT_MTU, TUNNEL_OVERHEAD, clamp_tcp_mss, negotiated_mss};
pub use outbound::OutboundPipeline;
pub use parser::{ParseError, ParsedPacket, parse};
