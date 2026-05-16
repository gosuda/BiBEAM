#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod error;
pub mod failover;
pub mod http;
pub mod ws;

pub use error::DiscoveryError;
pub use failover::CoordinatorPool;
pub use http::{CoordinatorClient, status_is_retriable};
pub use ws::{CoordinatorEvent, CoordinatorWs, encode_event};
