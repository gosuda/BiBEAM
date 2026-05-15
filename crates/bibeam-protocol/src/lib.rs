#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod claims;
pub mod codec;
pub mod cohort;
pub mod control;
pub mod error;
pub mod frame;
pub mod tunnel;

pub use claims::SessionClaims;
pub use codec::{decode, encode};
pub use cohort::{CohortAdmit, CohortLive, CohortMessage, CohortRotate};
pub use control::{
    ControlMessage, Disconnect, Heartbeat, MatchRequest, MatchResponse, Register, RegisterAck,
};
pub use error::ProtocolError;
pub use frame::{Frame, MAGIC, VERSION};
pub use tunnel::Tunnel;
