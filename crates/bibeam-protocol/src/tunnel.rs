#![forbid(unsafe_code)]
//! Data-plane tunnel datagram.
//!
//! Tunnel frames carry a single WG-sealed IP packet between two
//! peers. The cryptographic sealing/unsealing lives in `bibeam-crypto`
//! and `bibeam-transport`; this layer is wire-shape only — `payload` is
//! treated as opaque bytes by the codec and by any router along the
//! path.
//!
//! Splitting cipher-text out of the protocol crate keeps the wire shape
//! independent of the chosen AEAD: a future cipher swap reshapes
//! `bibeam-crypto`, not [`Tunnel`].

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use bibeam_core::PeerId;

/// One sealed IP datagram tagged with its originating peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tunnel {
    /// Identifier of the peer that sealed `payload`.
    pub peer_id: PeerId,
    /// WG-sealed IP frame; opaque to this layer.
    pub payload: Bytes,
}
