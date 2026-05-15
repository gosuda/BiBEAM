#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod ids;

pub use ids::{CohortId, NodeId, PeerId};
