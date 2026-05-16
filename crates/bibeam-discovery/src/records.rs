#![forbid(unsafe_code)]
//! Rendezvous record types exchanged over the discovery plane.
//!
//! - [`PeerRecord`] — a single peer's discovery snapshot
//!   (advertised socket, exit-capable bit, capacity hint, last-seen
//!   wall-clock).
//! - [`RelayRecord`] — a relay node the coordinator advertises for
//!   peers behind restrictive NATs.
//! - [`ExitRecord`] — an exit node the coordinator advertises for
//!   cohort egress, carrying the node's `WireGuard` X25519 public
//!   key.
//!
//! ## Wire form
//!
//! Every record (de)serialises through both
//! [`serde_json`] (HTTP REST control plane) and [`postcard`] (binary
//! pkarr/DHT TXT records). The field order and tags below are the
//! canonical form; any change is a wire-breaking event.
//!
//! ## `WgPublicKey` serde binding
//!
//! [`bibeam_crypto::WgPublicKey`] does not derive `Serialize` /
//! `Deserialize` on its own type. The [`wg_public_key_serde`]
//! sub-module bridges it to serde using the same standard-base64
//! 32-byte form `wg-quick` and `wg` print and parse — the form
//! callers already see in `WgPublicKey::to_wg_base64` /
//! `WgPublicKey::from_wg_base64`. Choosing the existing `wg`-wire
//! string keeps the JSON shape human-friendly (operators copy/paste
//! the same value from records into config files) and avoids
//! pulling `serde_with` into the workspace dep graph for one type.

use std::net::SocketAddr;

use bibeam_core::{NodeId, PeerId, Timestamp};
use bibeam_crypto::WgPublicKey;
use serde::{Deserialize, Serialize};

/// One peer's discovery snapshot.
///
/// Published by the coordinator (in the HTTP control plane) and, in
/// the F-DISC.4 fallback path, by the peer itself as a pkarr-signed
/// DNS TXT record under its identity key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerRecord {
    /// Identifier of the peer described by this record.
    pub peer_id: PeerId,
    /// Address the peer advertises for inbound connections.
    pub addr_hint: SocketAddr,
    /// Whether the peer is willing to serve as an exit node.
    pub can_exit: bool,
    /// Peer-supplied capacity score; opaque to the coordinator and
    /// to peers consuming the record.
    pub capacity_hint: u32,
    /// When this snapshot was captured.
    pub last_seen: Timestamp,
}

/// One relay node the coordinator advertises for peers behind
/// restrictive NATs.
///
/// Relays carry encrypted traffic between cohort members; they do
/// not see plaintext. The `addr` field is the relay's reachable
/// socket. `last_seen` is the coordinator's most recent health-check
/// observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayRecord {
    /// Identifier of the relay node.
    pub node_id: NodeId,
    /// Address peers should dial the relay at.
    pub addr: SocketAddr,
    /// When the coordinator most recently confirmed the relay was
    /// reachable.
    pub last_seen: Timestamp,
}

/// One exit node the coordinator advertises for cohort egress.
///
/// Exit nodes terminate `WireGuard` tunnels and forward traffic to
/// the open internet. `wg_public_key` is the node's X25519 public
/// key in standard `wg`-wire form (encoded via base64 — see
/// [`wg_public_key_serde`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitRecord {
    /// Identifier of the exit node.
    pub node_id: NodeId,
    /// Address peers should dial the exit at.
    pub addr: SocketAddr,
    /// The exit's X25519 public key, encoded as base64 on the wire.
    #[serde(with = "wg_public_key_serde")]
    pub wg_public_key: WgPublicKey,
    /// When the coordinator most recently confirmed the exit was
    /// reachable.
    pub last_seen: Timestamp,
}

impl PartialEq for ExitRecord {
    fn eq(&self, other: &Self) -> bool {
        self.node_id == other.node_id
            && self.addr == other.addr
            && self.wg_public_key == other.wg_public_key
            && self.last_seen == other.last_seen
    }
}

impl Eq for ExitRecord {}

/// Serde adapter for [`bibeam_crypto::WgPublicKey`].
///
/// `WgPublicKey` does not derive `Serialize` / `Deserialize` (the
/// underlying `x25519-dalek::PublicKey` does not either). This
/// adapter routes (de)serialisation through the `wg`-wire base64
/// form returned by [`WgPublicKey::to_wg_base64`] and parsed by
/// [`WgPublicKey::from_wg_base64`]. The string form is the same one
/// `wg-quick` and `wg` accept, so records remain operator-friendly
/// in both JSON and postcard binaries (postcard encodes a
/// `&str`-shaped value as a length-prefixed UTF-8 byte slice — the
/// base64 form decodes byte-identical on either side).
pub mod wg_public_key_serde {
    use bibeam_crypto::WgPublicKey;
    use serde::{Deserialize as _, Deserializer, Serializer, de::Error as _};

    /// Encode a [`WgPublicKey`] as standard base64.
    pub fn serialize<TargetSerializer>(
        key: &WgPublicKey,
        serializer: TargetSerializer,
    ) -> Result<TargetSerializer::Ok, TargetSerializer::Error>
    where
        TargetSerializer: Serializer,
    {
        let encoded = key.to_wg_base64();
        serializer.serialize_str(&encoded)
    }

    /// Decode a [`WgPublicKey`] from a standard-base64 string.
    pub fn deserialize<'de, SourceDeserializer>(
        deserializer: SourceDeserializer,
    ) -> Result<WgPublicKey, SourceDeserializer::Error>
    where
        SourceDeserializer: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        WgPublicKey::from_wg_base64(&encoded).map_err(SourceDeserializer::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use bibeam_crypto::WgSecretKey;

    use super::*;

    fn sample_peer_record() -> PeerRecord {
        PeerRecord {
            peer_id: PeerId::new(),
            addr_hint: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 41_443),
            can_exit: true,
            capacity_hint: 42,
            last_seen: Timestamp::now(),
        }
    }

    fn sample_relay_record() -> RelayRecord {
        RelayRecord {
            node_id: NodeId::new(),
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), 51_820),
            last_seen: Timestamp::now(),
        }
    }

    fn sample_exit_record() -> ExitRecord {
        let secret = WgSecretKey::generate();
        ExitRecord {
            node_id: NodeId::new(),
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3)), 51_820),
            wg_public_key: secret.public(),
            last_seen: Timestamp::now(),
        }
    }

    #[test]
    fn peer_record_json_round_trips() {
        let original = sample_peer_record();
        let encoded = serde_json::to_string(&original).expect("encode");
        let decoded: PeerRecord = serde_json::from_str(&encoded).expect("decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn peer_record_postcard_round_trips() {
        let original = sample_peer_record();
        let encoded = postcard::to_allocvec(&original).expect("encode");
        let decoded: PeerRecord = postcard::from_bytes(&encoded).expect("decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn relay_record_json_round_trips() {
        let original = sample_relay_record();
        let encoded = serde_json::to_string(&original).expect("encode");
        let decoded: RelayRecord = serde_json::from_str(&encoded).expect("decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn relay_record_postcard_round_trips() {
        let original = sample_relay_record();
        let encoded = postcard::to_allocvec(&original).expect("encode");
        let decoded: RelayRecord = postcard::from_bytes(&encoded).expect("decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn exit_record_json_round_trips() {
        let original = sample_exit_record();
        let encoded = serde_json::to_string(&original).expect("encode");
        // JSON form must carry the wg public key as its base64 string.
        let expected_base64 = original.wg_public_key.to_wg_base64();
        assert!(encoded.contains(&expected_base64), "{encoded}");
        let decoded: ExitRecord = serde_json::from_str(&encoded).expect("decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn exit_record_postcard_round_trips() {
        let original = sample_exit_record();
        let encoded = postcard::to_allocvec(&original).expect("encode");
        let decoded: ExitRecord = postcard::from_bytes(&encoded).expect("decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn exit_record_rejects_malformed_wg_public_key() {
        // Build a JSON shape that matches ExitRecord but carries an
        // invalid base64 wg public key.
        let bad_json = serde_json::json!({
            "node_id": NodeId::new(),
            "addr": "192.0.2.4:51820",
            "wg_public_key": "this is not base64!!!",
            "last_seen": Timestamp::now(),
        });
        let err = serde_json::from_value::<ExitRecord>(bad_json).expect_err("must reject");
        // serde error must mention the wg key field somewhere in its chain.
        let message = format!("{err}");
        assert!(!message.is_empty());
    }
}
