#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod error;
pub mod identity;
pub mod ids;
pub mod redaction;
pub mod time;

pub use error::Error;
pub use identity::Fingerprint;
pub use ids::{ChainId, CohortId, NodeId, PeerId};
pub use redaction::{RedactionKey, redact_ip, redact_peer_id};
pub use time::Timestamp;

/// Convenience alias over [`std::result::Result`] using the crate's [`Error`].
///
/// Every fallible call inside the `BiBeam` core surface uses this alias, so
/// callers can write `bibeam_core::Result<T>` instead of repeating the error
/// type each time.
pub type Result<T> = std::result::Result<T, Error>;
