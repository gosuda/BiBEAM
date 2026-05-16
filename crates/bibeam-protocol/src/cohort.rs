#![forbid(unsafe_code)]
//! Cohort lifecycle messages.
//!
//! A cohort is a logical grouping of peers that share a trust scope and
//! a common exit set. The three messages here describe each transition
//! every cohort undergoes:
//!
//! - [`CohortAdmit`]: a single peer is added to the cohort,
//! - [`CohortLive`]: the cohort's current canonical membership and exit
//!   set, broadcast on transitions and on resync,
//! - [`CohortRotate`]: the cohort is retired and replaced with a fresh
//!   one (e.g. to limit how long any single membership is observable).
//!
//! [`CohortMessage`] is the tagged sum that travels inside
//! [`crate::frame::Frame::Cohort`]. The control plane (F-PROTO.3)
//! drives admission and rotation; these messages are the cohort plane
//! itself, broadcast within the cohort.

use std::collections::HashMap;

use bibeam_core::{CohortId, NodeId, PeerId, Timestamp};
use serde::{Deserialize, Serialize};

/// One peer has been admitted to a cohort.
///
/// Sent by the coordinator (or another cohort participant relaying the
/// coordinator's decision) to all current members.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CohortAdmit {
    /// Cohort the peer was admitted to.
    pub cohort: CohortId,
    /// Identifier of the peer being admitted.
    pub member: PeerId,
    /// When the admission was decided.
    pub at: Timestamp,
}

/// Canonical snapshot of a cohort's current state.
///
/// Broadcast after every admission or rotation, and on demand when a
/// peer needs to resynchronise its view. Carries both the full member
/// list and the canonical exit set so a fresh peer can become useful
/// without round-tripping back to the coordinator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CohortLive {
    /// Cohort being described.
    pub cohort: CohortId,
    /// Current members of `cohort`.
    pub members: Vec<PeerId>,
    /// Current exit nodes serving `cohort`'s traffic.
    pub exits: Vec<NodeId>,
    /// Per-exit operator-tagged region tag, indexed by [`NodeId`] from
    /// [`Self::exits`]. Same free-form string shape as
    /// `bibeam_discovery::ExitRecord::region` (R-REGION.1) — the
    /// coordinator copies the tag verbatim from the discovery record at
    /// snapshot time. Missing entries mean "region unknown for that
    /// exit"; callers that filter by a requested region MUST treat a
    /// missing tag as a non-match, never as a wildcard.
    ///
    /// Defaults to an empty map for backward-compat: pre-region
    /// snapshots (and the cohort-emitter's TODO under F-CLI.4b) will
    /// deserialise into the missing-tag-is-non-match branch.
    // TODO(R-REGION.3): the coordinator-side cohort emitter has to
    // populate this map from `ExitRecord::region` whenever a cohort is
    // admitted or rotated. Until that lands, every snapshot ships an
    // empty map and `pick_exit(..., Some(r))` will always refuse —
    // matching the §11 R-3 "no exit in <region>; defer" semantics.
    #[serde(default)]
    pub exit_regions: HashMap<NodeId, String>,
    /// When this snapshot was captured.
    pub at: Timestamp,
}

/// One cohort is retiring; its replacement has been chosen.
///
/// Peers receiving this message should migrate any in-flight tunnels
/// to `new` before `old` is torn down. Rotation cadence is a policy
/// decision made by the coordinator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CohortRotate {
    /// Cohort being retired.
    pub old: CohortId,
    /// Replacement cohort.
    pub new: CohortId,
    /// When the rotation was decided.
    pub at: Timestamp,
}

/// Tagged sum of every cohort-plane message.
///
/// Wrapped by [`crate::frame::Frame::Cohort`] on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CohortMessage {
    /// One peer was admitted to a cohort.
    Admit(CohortAdmit),
    /// Canonical snapshot of a cohort's current state.
    Live(CohortLive),
    /// One cohort is retiring; its replacement has been chosen.
    Rotate(CohortRotate),
}
