#![forbid(unsafe_code)]
//! Multi-hop forwarder chain control-plane shapes (R-MULTIHOP-PROTO).
//!
//! When the coordinator routes a peer through one or more intermediate
//! forwarders (rather than directly to an exit), it ships a
//! [`crate::control::MatchResponse::MultiHopAssignment`] carrying the
//! types in this module:
//!
//! - [`WgPeerConfig`]: the public side of the client↔exit `WireGuard`
//!   session. Public keys + endpoints + allowed-ips + keepalive. The
//!   coordinator NEVER puts private key material in this struct; the
//!   local endpoint already holds its own private key from registration.
//! - [`ForwarderLease`]: one row per forwarder in the chain. Each row
//!   tells a forwarder which upstream and downstream sockets it is
//!   authorised to relay between, until [`ForwarderLease::lease_expires_at`].
//! - [`RelayFrame`]: the on-the-wire datagram a forwarder sees and
//!   demultiplexes against its lease table.
//!
//! # Packet-to-lease binding (resolved here)
//!
//! A forwarder must verify "this packet belongs to one of my leased
//! chains" without (i) holding `WireGuard` private keys and (ii)
//! decrypting payload. Three candidates were considered:
//!
//! - **(A) `(src, dst)` tuple matching.** Forwarder routing table
//!   keyed by `(allowed_src, allowed_dst)`; incoming packet's
//!   source-address ↔ destination-address pair must hit a leased row.
//!   Observable at the IP layer; zero encapsulation overhead.
//!   **Rejected.** Vulnerable if the upstream peer's NAT remaps the
//!   source address mid-session — the lease would wrongly bind, and the
//!   forwarder would either drop a legitimate flow or accept a
//!   misrouted one.
//!
//! - **(B) Explicit `bibeam-relay` encapsulation.** Wrap `WireGuard`
//!   UDP packets in a small `[chain_id (16 bytes) | wg_payload]`
//!   framing — that is exactly [`RelayFrame`]. Forwarder reads
//!   `chain_id`, looks up the row, strips the frame, forwards the
//!   `wg_payload`. **CHOSEN.** NAT-robust (no fragility on a NAT
//!   remap mid-session), lease-explicit (forwarder verifies a
//!   cryptographically opaque chain id, not just heuristic
//!   addresses), 16 bytes fixed overhead is negligible alongside
//!   `WireGuard`'s existing 16-byte AEAD tag, and avoids the
//!   coord-round-trip cost of option (C).
//!
//! - **(C) Post-handshake sender-index registration.** After the
//!   `WireGuard` handshake completes, the client and exit register
//!   their final sender-indices with the coordinator; the coordinator
//!   then forwards an index-to-chain map to the forwarders.
//!   Forwarders demultiplex by reading the `WireGuard` transport
//!   header's sender-index field. Zero encapsulation overhead.
//!   **Rejected.** Requires a coordinator round-trip after every
//!   handshake — both at session start and at every WG rekey — which
//!   increases coordinator traffic and complicates the recovery path
//!   when the coordinator is unreachable.
//!
//! # Frame layout for option (B)
//!
//! [`RelayFrame::encode`] writes a fixed 16-byte `chain_id` prefix
//! followed by the raw `wg_payload` bytes — no varint length, no
//! postcard framing on the body. [`RelayFrame::decode`] requires the
//! buffer to be at least 16 bytes (enough for the `chain_id`) and
//! treats every remaining byte as the payload. That delivers the
//! "16 bytes per packet" claim above literally and makes the frame
//! cheap to demultiplex without a serde-aware decoder on the hot path.
//!
//! Control-plane carriers of the multi-hop types ([`WgPeerConfig`],
//! [`ForwarderLease`], `MatchResponse::MultiHopAssignment`) ride the
//! existing postcard envelope ([`crate::codec`]); only the relay-frame
//! datagram itself uses the fixed-prefix layout. The two formats serve
//! distinct fitness functions — control plane prioritises typed
//! schema evolution, data plane prioritises per-packet overhead.
//!
//! # Relationship to `bibeam_crypto::WgPublicKey`
//!
//! [`WgPublicKey`] in this module is the wire-form newtype carried in
//! the control plane: 32 raw bytes plus `serde` derives. It is
//! deliberately parallel to `bibeam_crypto::WgPublicKey`, which is the
//! richer in-memory form that wraps an `x25519_dalek::PublicKey` and
//! lives in the crypto crate. The two types stay separate because
//! `bibeam-crypto` already depends on `bibeam-protocol`; importing the
//! richer form back into the protocol crate would close that dependency
//! cycle. `bibeam-crypto` may add `From`/`Into` conversions between the
//! two whenever needed; the protocol-side type stays serde-only.

use core::net::SocketAddr;

use bibeam_core::{ChainId, NodeId, Timestamp};
use bytes::Bytes;
use ipnet::IpNet;
use postcard::Error as PostcardError;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Structural-invariant failures rejected when deserialising a
/// [`crate::control::MultiHopAssignment`].
///
/// Surfaces inside the `serde` deserialize pipeline via the
/// `#[serde(try_from = "...")]` shim; callers see it through the
/// standard postcard / serde error path.
#[derive(Debug, Error)]
pub enum MultiHopAssignmentError {
    /// Decoded chain held zero forwarders. A multi-hop assignment with
    /// no forwarders is by definition the single-hop case and MUST be
    /// expressed as [`crate::control::MatchResponse::SingleHop`].
    #[error("multi-hop assignment has empty forwarder chain; use SingleHop instead")]
    EmptyChain,
}

/// Length of a `WireGuard` X25519 public key in bytes.
///
/// Matches `bibeam_crypto::WG_KEY_LEN`; we duplicate the constant here
/// so the protocol crate stays free of the crypto crate (the dependency
/// arrow runs `bibeam-crypto` → `bibeam-protocol`, not the reverse).
pub const WG_KEY_LEN: usize = 32;

/// Wire-form `WireGuard` X25519 public key.
///
/// Carries the raw 32 bytes only; the protocol crate never sees the
/// matching private key. The richer in-memory form (with
/// `x25519_dalek::PublicKey` accessors and base64 helpers) lives in
/// `bibeam_crypto::WgPublicKey`; see the module-level docs for why the
/// two types are deliberately parallel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WgPublicKey(pub [u8; WG_KEY_LEN]);

impl WgPublicKey {
    /// Wrap 32 raw `WireGuard` public-key bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; WG_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the underlying 32 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; WG_KEY_LEN] {
        &self.0
    }
}

/// Paired public keys + endpoint info that lets one end of a multi-hop
/// `WireGuard` session bring its tunnel up.
///
/// The coordinator renders one [`WgPeerConfig`] per endpoint of the
/// session: one for the client (with `peer_endpoint` pointing at the
/// first-hop forwarder, so the client's outbound WG datagrams enter
/// the chain) and one for the exit (with `peer_endpoint` pointing at
/// the exit's inbound socket, populated as forwarders learn the
/// session's source after the first authenticated frame).
///
/// `local_static_public` is the *local* endpoint's static public key,
/// rendered so the local endpoint can sanity-check that the coordinator
/// addressed this config to the right peer. `peer_static_public` is
/// the other endpoint's static public key (the value `wg setconf`
/// expects after `PublicKey =`).
///
/// The coordinator NEVER includes private key material in
/// [`WgPeerConfig`]; the local endpoint already holds its own
/// `WgSecretKey` from registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WgPeerConfig {
    /// Public side of the local endpoint's static keypair.
    ///
    /// Rendered to the client carries the client's public key; rendered
    /// to the exit carries the exit's public key. The local endpoint
    /// uses this field to detect a coordinator-side addressing error
    /// (the local public key it sees here MUST match the public key
    /// it registered with).
    pub local_static_public: WgPublicKey,
    /// Static public key of the peer at the far end of the WG session.
    pub peer_static_public: WgPublicKey,
    /// Socket address WG packets are sent to.
    ///
    /// For the client this is the first-hop forwarder's socket; for the
    /// exit this is the direct inbound socket the exit listens on.
    pub peer_endpoint: SocketAddr,
    /// CIDR blocks the local endpoint should route through the peer.
    ///
    /// Typically `0.0.0.0/0` + `::/0` on the client side (egress
    /// everywhere through the exit) and the client's tunnel-IP on the
    /// exit side (the exit only accepts return traffic destined for
    /// the client's address).
    pub allowed_ips: Vec<IpNet>,
    /// `WireGuard` persistent-keepalive interval, in seconds.
    ///
    /// `25` is the standard NAT-punching value. `0` disables the
    /// keepalive (acceptable on a network with no stateful NAT in
    /// the path).
    pub persistent_keepalive_secs: u16,
}

/// One forwarder's authorisation row inside a multi-hop chain.
///
/// `MatchResponse::MultiHopAssignment::per_forwarder_routing` carries
/// one entry per forwarder in `forwarder_chain`. The coordinator hands
/// each forwarder its own copy of the matching [`ForwarderLease`]
/// out-of-band; the forwarder writes the row into its lease table and
/// matches every incoming [`RelayFrame`] against it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwarderLease {
    /// Forwarder this lease authorises.
    pub forwarder: NodeId,
    /// Opaque chain identifier the forwarder uses to look up this row.
    ///
    /// Same value rides each [`RelayFrame::chain_id`] sent through the
    /// chain; matching the two is how the forwarder demultiplexes
    /// packets to the right downstream peer.
    pub chain_id: ChainId,
    /// Upstream peer's socket — client for hop 1, previous forwarder
    /// for inner hops.
    pub allowed_src: SocketAddr,
    /// Downstream peer's socket — next forwarder, or the exit for the
    /// last hop.
    pub allowed_dst: SocketAddr,
    /// Wall-clock instant after which the forwarder MUST tear the row
    /// down.
    ///
    /// Typical value is `now + 15 min`; the coordinator renews the
    /// lease before expiry by issuing a fresh [`ForwarderLease`] with
    /// the same `chain_id`.
    pub lease_expires_at: Timestamp,
}

/// Forwarder-visible wrapper around a single `WireGuard` UDP datagram.
///
/// Layout on the wire:
///
/// ```text
/// [chain_id (16 bytes)] || [wg_payload (variable, opaque to the forwarder)]
/// ```
///
/// The forwarder reads the 16-byte prefix, looks `chain_id` up in its
/// lease table, and forwards `wg_payload` verbatim to
/// [`ForwarderLease::allowed_dst`]. Forwarders never decrypt
/// `wg_payload` — that requires `WireGuard` keys that only the client
/// and the exit hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayFrame {
    /// Chain this frame belongs to.
    pub chain_id: ChainId,
    /// Opaque `WireGuard` payload — typically a `WireGuard` transport
    /// or handshake datagram. The forwarder never reads this field.
    pub wg_payload: Bytes,
}

/// Number of fixed prefix bytes a [`RelayFrame`] writes before its
/// `wg_payload` — the 16 raw bytes of a `chain_id` ULID.
pub const RELAY_FRAME_PREFIX_LEN: usize = 16;

impl RelayFrame {
    /// Encode this frame as `chain_id (16) || wg_payload`.
    ///
    /// The returned buffer is freshly allocated; callers may share it
    /// cheaply because [`Bytes`] is reference-counted.
    #[must_use]
    pub fn encode(&self) -> Bytes {
        let mut buf = Vec::with_capacity(RELAY_FRAME_PREFIX_LEN + self.wg_payload.len());
        buf.extend_from_slice(&self.chain_id.into_ulid().to_bytes());
        buf.extend_from_slice(&self.wg_payload);
        Bytes::from(buf)
    }

    /// Decode a forwarder-visible buffer.
    ///
    /// Returns [`PostcardError::DeserializeUnexpectedEnd`] if `buf`
    /// is shorter than [`RELAY_FRAME_PREFIX_LEN`] — the only failure
    /// mode of the fixed-prefix layout, since every remaining byte is
    /// accepted as the opaque payload.
    pub fn decode(buf: &[u8]) -> Result<Self, PostcardError> {
        let Some((prefix, body)) = buf.split_first_chunk::<RELAY_FRAME_PREFIX_LEN>() else {
            return Err(PostcardError::DeserializeUnexpectedEnd);
        };
        let chain_id = ChainId(ulid::Ulid::from_bytes(*prefix));
        Ok(Self {
            chain_id,
            wg_payload: Bytes::copy_from_slice(body),
        })
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests in this module cover the `RelayFrame` encode/decode
    //! contract — the fixed-prefix data-plane layout that does NOT ride
    //! the postcard envelope, so it needs its own hand-written byte-
    //! layout coverage here.
    //!
    //! Wire-format round-trip coverage for the postcard-encoded
    //! control-plane structs declared in this module — [`WgPeerConfig`]
    //! and [`ForwarderLease`] — lives in
    //! `crates/bibeam-protocol/tests/codec_roundtrip.rs` as the
    //! property-based strategies `arb_wg_peer_config` and
    //! `arb_forwarder_lease`, which exercise varied generated cases
    //! (random field values with shrinking on failure).

    use super::*;

    #[test]
    fn relay_frame_round_trip_at_typical_wg_mtu() {
        // Contract: encode then decode is identity for a payload
        // sized at a typical WireGuard MTU. Catches a regression
        // that misaligns the chain_id prefix or truncates the
        // payload's tail.
        let chain_id = ChainId::new();
        let frame = RelayFrame {
            chain_id,
            wg_payload: Bytes::from(vec![0x42; 1280]),
        };
        let encoded = frame.encode();
        assert_eq!(encoded.len(), RELAY_FRAME_PREFIX_LEN + 1280);
        let decoded = RelayFrame::decode(&encoded).expect("decode round-trip");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn relay_frame_round_trip_empty_payload() {
        // Contract: an empty wg_payload still round-trips — the
        // prefix alone is a syntactically valid frame even if no
        // forwarder would route it.
        let frame = RelayFrame {
            chain_id: ChainId::new(),
            wg_payload: Bytes::new(),
        };
        let encoded = frame.encode();
        assert_eq!(encoded.len(), RELAY_FRAME_PREFIX_LEN);
        let decoded = RelayFrame::decode(&encoded).expect("decode round-trip");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn relay_frame_decode_rejects_truncated_prefix() {
        // Contract: a buffer shorter than the 16-byte chain_id
        // prefix MUST surface as an Err. Catches a regression that
        // silently produced a zero-ULID chain_id for short buffers
        // (which would let a forwarder route packets it has no
        // lease for).
        for short_len in 0..RELAY_FRAME_PREFIX_LEN {
            let buf = vec![0u8; short_len];
            let result = RelayFrame::decode(&buf);
            assert!(result.is_err(), "buffer of length {short_len} must error, got {result:?}");
        }
    }
}
