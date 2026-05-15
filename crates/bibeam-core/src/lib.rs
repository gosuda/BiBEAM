#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod error;
pub mod ids;

pub use error::Error;
pub use ids::{CohortId, NodeId, PeerId};

/// Convenience alias over [`std::result::Result`] using the crate's [`Error`].
///
/// Every fallible call inside the `BiBEAM` core surface uses this alias, so
/// callers can write `bibeam_core::Result<T>` instead of repeating the error
/// type each time.
pub type Result<T> = std::result::Result<T, Error>;
