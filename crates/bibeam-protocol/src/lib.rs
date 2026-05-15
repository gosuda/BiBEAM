#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod frame;

pub use frame::{Frame, MAGIC, VERSION};
