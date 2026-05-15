#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod device;
pub mod parser;

pub use device::{TunDevice, TunError};
pub use parser::{ParseError, ParsedPacket, parse};
