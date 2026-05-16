#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod claims;
pub mod codec;
pub mod cohort;
pub mod control;
pub mod error;
pub mod frame;
pub mod multihop;
pub mod tunnel;

pub use claims::SessionClaims;
pub use codec::{decode, encode};
pub use cohort::{CohortAdmit, CohortLive, CohortMessage, CohortRotate};
pub use control::{
    ControlMessage, Disconnect, Heartbeat, MatchRequest, MatchResponse, MultiHopAssignment,
    Register, RegisterAck, SingleHopMatch,
};
pub use error::ProtocolError;
pub use frame::{Frame, MAGIC, VERSION};
pub use multihop::{
    ForwarderLease, MultiHopAssignmentError, RELAY_FRAME_PREFIX_LEN, RelayFrame, WG_KEY_LEN,
    WgPeerConfig, WgPublicKey,
};
pub use tunnel::Tunnel;
