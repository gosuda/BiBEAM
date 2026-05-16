#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod error;
pub mod failover;
pub mod http;
pub mod invite_validator;
pub mod pkarr_fallback;
pub mod records;
pub mod ws;

pub use error::DiscoveryError;
pub use failover::CoordinatorPool;
pub use http::{CoordinatorClient, status_is_retriable};
pub use invite_validator::{SignedInvite, signing_payload, verify_invite};
pub use pkarr_fallback::DhtFallback;
pub use records::{ExitRecord, PeerRecord, RelayRecord};
pub use ws::{CoordinatorEvent, CoordinatorWs, encode_event};
