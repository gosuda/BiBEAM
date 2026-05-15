#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod codec;
pub mod cohort;
pub mod control;
pub mod frame;
pub mod tunnel;

pub use codec::{decode, encode};
pub use cohort::{CohortAdmit, CohortLive, CohortMessage, CohortRotate};
pub use control::{
    ControlMessage, Disconnect, Heartbeat, MatchRequest, MatchResponse, Register, RegisterAck,
};
pub use frame::{Frame, MAGIC, VERSION};
pub use tunnel::Tunnel;
