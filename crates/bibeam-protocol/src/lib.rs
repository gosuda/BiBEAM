#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod codec;
pub mod frame;

pub use codec::{decode, encode};
pub use frame::{Frame, MAGIC, VERSION};
