#![forbid(unsafe_code)]
//! Control-plane messages exchanged with the coordinator.
//!
//! Peers register with the coordinator, ask it to match them into a
//! cohort, then keep the registration alive with heartbeats until they
//! either rotate to a new cohort or disconnect. Each of those steps is
//! represented by one struct in this module; [`ControlMessage`] is the
//! tagged sum that travels inside [`crate::frame::Frame::Control`].
//!
//! Per the project threat model the coordinator is semi-trusted: it is
//! authenticated and rate-limited, but it never sees plaintext tunnel
//! payloads. Every shape here is therefore part of the public, signed
//! control plane and intentionally carries no secret material — the
//! one apparent exception, [`RegisterAck::session_token`], holds a
//! PASETO v4 token that is itself self-contained and verifiable.
//!
//! All timestamps use [`Timestamp`], which round-trips through RFC 3339
//! on the wire (see `bibeam_core::time`).

use std::net::SocketAddr;

use bibeam_core::{CohortId, NodeId, PeerId, Timestamp};
use bytes::Bytes;
use serde::{Deserialize, Serialize};

/// Initial registration message a peer sends to the coordinator.
///
/// `addr_hint` is the address the peer advertises for inbound
/// connections; the coordinator may override or augment it with what
/// it sees at the socket level. `can_exit` advertises willingness to
/// serve as an exit node for other peers. `capacity_hint` is an
/// opaque, peer-supplied score the coordinator may use as one input
/// to match-making.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Register {
    /// Identifier of the registering peer.
    pub peer_id: PeerId,
    /// Address the peer advertises for inbound connections.
    pub addr_hint: SocketAddr,
    /// Whether this peer is willing to serve as an exit node.
    pub can_exit: bool,
    /// Peer-supplied capacity score; opaque to the coordinator.
    pub capacity_hint: u32,
    /// When the peer captured this registration.
    pub at: Timestamp,
}

/// Coordinator's acknowledgement of a successful [`Register`].
///
/// `session_token` is a PASETO v4 token issued by the coordinator (see
/// F-CRYPTO.4). Its claim set is the shape declared in `SessionClaims`
/// (introduced in F-PROTO.6). `expires_at` is duplicated here so peers
/// do not have to parse the token to find out when to renew.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterAck {
    /// PASETO v4 session token issued by the coordinator.
    pub session_token: Bytes,
    /// Wall-clock instant after which `session_token` will be rejected.
    pub expires_at: Timestamp,
}

/// Peer-initiated request to be matched into a cohort.
///
/// Sent after a successful [`Register`] and any time the peer wants a
/// fresh cohort (for example after a cohort rotation — see F-PROTO.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchRequest {
    /// Identifier of the requesting peer.
    pub peer_id: PeerId,
    /// When the peer captured this request.
    pub at: Timestamp,
}

/// Coordinator's response to a [`MatchRequest`].
///
/// `cohort` identifies the cohort the peer should join. `exit_set` is
/// the canonical list of exit nodes for that cohort; the peer should
/// route through one of them. `rotation_deadline` tells the peer when
/// it must request a fresh cohort.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchResponse {
    /// Cohort the peer should join.
    pub cohort: CohortId,
    /// Exit nodes serving traffic for `cohort`.
    pub exit_set: Vec<NodeId>,
    /// Wall-clock instant at which the peer must rotate.
    pub rotation_deadline: Timestamp,
}

/// Peer-to-coordinator keep-alive.
///
/// A peer sends one [`Heartbeat`] per session interval. Missing
/// heartbeats let the coordinator garbage-collect dead registrations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Heartbeat {
    /// Identifier of the peer sending the heartbeat.
    pub peer_id: PeerId,
    /// When the peer captured this heartbeat.
    pub at: Timestamp,
}

/// Voluntary disconnect notification.
///
/// Sent by a peer cleanly leaving the mesh so the coordinator can
/// remove its registration without waiting for the heartbeat timeout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Disconnect {
    /// Identifier of the disconnecting peer.
    pub peer_id: PeerId,
    /// Human-readable disconnect reason for the coordinator's logs.
    pub reason: String,
    /// When the peer captured this disconnect.
    pub at: Timestamp,
}

/// Tagged sum of every control-plane message.
///
/// Wrapped by [`crate::frame::Frame::Control`] on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlMessage {
    /// Initial peer registration.
    Register(Register),
    /// Acknowledgement of a successful registration.
    RegisterAck(RegisterAck),
    /// Request to be matched into a cohort.
    MatchRequest(MatchRequest),
    /// Response carrying the matched cohort and its exit set.
    MatchResponse(MatchResponse),
    /// Periodic keep-alive.
    Heartbeat(Heartbeat),
    /// Voluntary disconnect notification.
    Disconnect(Disconnect),
}
