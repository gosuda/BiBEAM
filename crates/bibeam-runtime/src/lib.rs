#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod log;

pub use log::{LogInitError, init_json_logging};
