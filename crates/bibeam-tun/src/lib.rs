#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod device;
pub mod inbound;
pub mod outbound;
pub mod parser;

pub use device::{TunDevice, TunError};
pub use inbound::InboundPipeline;
pub use outbound::OutboundPipeline;
pub use parser::{ParseError, ParsedPacket, parse};
