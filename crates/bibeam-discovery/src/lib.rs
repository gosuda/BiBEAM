#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod error;
pub mod http;

pub use error::DiscoveryError;
pub use http::{CoordinatorClient, status_is_retriable};
