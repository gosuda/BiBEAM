#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod device;

pub use device::{TunDevice, TunError};
