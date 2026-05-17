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
    /// Operator-tagged free-form region string. Recommended
    /// convention (documented in operator-runbook, not enforced
    /// here) is `<iso3166-alpha2>-<sub-region>[-<city>]`, lowercase,
    /// hyphen-separated. Empty until the coordinator populates it
    /// at registration / heartbeat time.
    pub region: String,
    /// Wall-clock instant at which the coordinator's `GeoIP`
    /// cross-check (R-REGION.2 / R-REGION.3) last confirmed that
    /// `region` matched the peer's observed address.
    pub region_last_verified_at: Timestamp,
    /// The peer's X25519 `WireGuard` public key, when it has
    /// registered one. Absent until the peer's registration carries
    /// the key (R-MULTIHOP-COORD option (c) cascading-edits).
    ///
    /// The coordinator's multi-hop path-assembler reads this field to
    /// build the client side of the client↔exit `WgPeerConfig` —
    /// see [`bibeam_protocol::multihop::WgPeerConfig`]. When this is
    /// [`None`] the assembler refuses the request rather than
    /// silently minting a key (the coord NEVER holds private key
    /// material; minting one peer-side would be unverifiable).
    ///
    /// `Option` (rather than the empty-string sentinel used by
    /// [`Self::region`]) is the right shape here: the empty case has
    /// no observably distinct "this is the empty key" form — all-
    /// zero is a valid (if useless) 32-byte WG public key, so a
    /// sentinel would alias a real-but-broken registration to the
    /// absent case. `Option` keeps the two distinguishable in the
    /// type system.
    ///
    /// On the wire the field is REQUIRED: producers MUST emit either
    /// `null` (peer has not registered a key) or the base64 string,
    /// and consumers refuse to decode a record that omits the field
    /// entirely. The previous `#[serde(default)]` shape silently
    /// filled `None` on absence; that fallback was speculative
    /// forward-compat for pre-R-MULTIHOP-COORD publishers that no
    /// longer exist (pre-1.0 MVP) and is now removed.
    #[serde(with = "wg_public_key_option_serde")]
    pub wg_public_key: Option<WgPublicKey>,
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
    /// Operator-tagged free-form region string. Recommended
    /// convention (documented in operator-runbook, not enforced
    /// here) is `<iso3166-alpha2>-<sub-region>[-<city>]`, lowercase,
    /// hyphen-separated. Empty until the coordinator populates it
    /// at registration / heartbeat time.
    pub region: String,
    /// Wall-clock instant at which the coordinator's `GeoIP`
    /// cross-check (R-REGION.2 / R-REGION.3) last confirmed that
    /// `region` matched the relay's observed address.
    pub region_last_verified_at: Timestamp,
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
    /// Operator-tagged free-form region string. Recommended
    /// convention (documented in operator-runbook, not enforced
    /// here) is `<iso3166-alpha2>-<sub-region>[-<city>]`, lowercase,
    /// hyphen-separated. Empty until the coordinator populates it
    /// at registration / heartbeat time.
    pub region: String,
    /// Wall-clock instant at which the coordinator's `GeoIP`
    /// cross-check (R-REGION.2 / R-REGION.3) last confirmed that
    /// `region` matched the exit's observed address.
    pub region_last_verified_at: Timestamp,
}

impl PartialEq for ExitRecord {
    fn eq(&self, other: &Self) -> bool {
        self.node_id == other.node_id
            && self.addr == other.addr
            && self.wg_public_key == other.wg_public_key
            && self.last_seen == other.last_seen
            && self.region == other.region
            && self.region_last_verified_at == other.region_last_verified_at
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

/// Serde adapter for `Option<bibeam_crypto::WgPublicKey>`.
///
/// Wraps [`wg_public_key_serde`] in an [`Option`] so a peer that has
/// not yet registered a `WireGuard` public key (R-MULTIHOP-COORD
/// option (c)) shows up on the wire as `null` (JSON) or the
/// option-none discriminant (postcard) — never as a 32-byte zero
/// public key. Keeping the two cases observably distinct lets the
/// multi-hop path-assembler return [`Err`] for an absent key instead
/// of silently building a `WgPeerConfig` around a useless all-zero
/// public key.
///
/// The shape is the standard "newtype helper + Option-wrapper"
/// pattern serde uses for `Option<T>` where `T` has a custom adapter
/// — `Wrapper(#[serde(with = "...")] T)` plus
/// `Option<Wrapper>::deserialize` / `serialize_some` on the way out.
pub mod wg_public_key_option_serde {
    use bibeam_crypto::WgPublicKey;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Transparent newtype that carries the [`super::wg_public_key_serde`]
    /// adapter so an `Option<Wrapper>` (de)serialises through the same
    /// `wg`-wire base64 string the non-option fields use.
    #[derive(Serialize, Deserialize)]
    #[serde(transparent)]
    struct Wrapper(#[serde(with = "super::wg_public_key_serde")] WgPublicKey);

    /// Encode an optional [`WgPublicKey`] — `None` ⇒ wire-null,
    /// `Some(key)` ⇒ the same base64 string the non-option fields use.
    pub fn serialize<TargetSerializer>(
        key: &Option<WgPublicKey>,
        serializer: TargetSerializer,
    ) -> Result<TargetSerializer::Ok, TargetSerializer::Error>
    where
        TargetSerializer: Serializer,
    {
        match key {
            Some(inner) => serializer.serialize_some(&Wrapper(inner.clone())),
            None => serializer.serialize_none(),
        }
    }

    /// Decode an optional [`WgPublicKey`] from wire-null or a
    /// base64-string body.
    pub fn deserialize<'de, SourceDeserializer>(
        deserializer: SourceDeserializer,
    ) -> Result<Option<WgPublicKey>, SourceDeserializer::Error>
    where
        SourceDeserializer: Deserializer<'de>,
    {
        let opt = Option::<Wrapper>::deserialize(deserializer)?;
        Ok(opt.map(|wrapped| wrapped.0))
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
            region: String::new(),
            region_last_verified_at: Timestamp::now(),
            wg_public_key: None,
        }
    }

    fn sample_relay_record() -> RelayRecord {
        RelayRecord {
            node_id: NodeId::new(),
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), 51_820),
            last_seen: Timestamp::now(),
            region: String::new(),
            region_last_verified_at: Timestamp::now(),
        }
    }

    fn sample_exit_record() -> ExitRecord {
        let secret = WgSecretKey::generate();
        ExitRecord {
            node_id: NodeId::new(),
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3)), 51_820),
            wg_public_key: secret.public(),
            last_seen: Timestamp::now(),
            region: String::new(),
            region_last_verified_at: Timestamp::now(),
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
    fn peer_record_with_wg_public_key_round_trips() {
        // Contract: PeerRecord carrying a registered `wg_public_key`
        // (R-MULTIHOP-COORD option (c)) round-trips through both JSON
        // and postcard. The JSON form must carry the key as its
        // base64 string (the same shape ExitRecord uses) so operators
        // can copy/paste registrations between transports.
        let secret = WgSecretKey::generate();
        let original = PeerRecord {
            wg_public_key: Some(secret.public()),
            ..sample_peer_record()
        };

        let encoded_json = serde_json::to_string(&original).expect("encode json");
        let key = original.wg_public_key.as_ref().expect("set above");
        let expected_base64 = key.to_wg_base64();
        assert!(encoded_json.contains(&expected_base64), "{encoded_json}");
        let decoded_json: PeerRecord = serde_json::from_str(&encoded_json).expect("decode json");
        assert_eq!(decoded_json, original);

        let encoded_pc = postcard::to_allocvec(&original).expect("encode postcard");
        let decoded_pc: PeerRecord = postcard::from_bytes(&encoded_pc).expect("decode postcard");
        assert_eq!(decoded_pc, original);
    }

    #[test]
    fn peer_record_missing_wg_public_key_field_is_rejected() {
        // Contract (post-Cleanup-A): the wire field is REQUIRED.
        // A JSON shape that omits `wg_public_key` entirely must
        // FAIL to deserialise — the `#[serde(default)]` fallback
        // is gone (the speculative forward-compat is removed at
        // pre-1.0 with no consumers). Catches a regression that
        // re-introduces `#[serde(default)]` on this field, which
        // would silently swallow drift between coord and peer
        // schemas.
        let json_without_wg = serde_json::json!({
            "peer_id": PeerId::new(),
            "addr_hint": "192.0.2.4:41443",
            "can_exit": false,
            "capacity_hint": 0,
            "last_seen": Timestamp::now(),
            "region": "",
            "region_last_verified_at": Timestamp::now(),
        });
        let err = serde_json::from_value::<PeerRecord>(json_without_wg)
            .expect_err("missing wg_public_key must reject");
        let message = format!("{err}");
        assert!(
            message.contains("wg_public_key") || message.contains("missing field"),
            "error must name the missing field; got: {message}",
        );
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
            "region": "",
            "region_last_verified_at": Timestamp::now(),
        });
        let err = serde_json::from_value::<ExitRecord>(bad_json).expect_err("must reject");
        // serde error must mention the wg key field somewhere in its chain.
        let message = format!("{err}");
        assert!(!message.is_empty());
    }
}
