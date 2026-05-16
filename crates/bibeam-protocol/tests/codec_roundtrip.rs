#![forbid(unsafe_code)]
#![allow(
    clippy::expect_used,
    reason = "integration-test strategies use `.expect(...)` for well-known constants; clippy.toml \
              already permits expect in tests"
)]
//! Proptest roundtrip for the wire codec.
//!
//! For any [`Frame`] value reachable by the per-variant strategies in this
//! file, `decode(encode(&frame))` must return `Ok(frame)`. This is the
//! drift gate that catches any future change to a [`Frame`] variant that
//! is not also reflected in postcard's serde derives or in the codec's
//! framing rules.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use bibeam_core::{ChainId, CohortId, NodeId, PeerId, Timestamp};
use bibeam_protocol::{
    CohortAdmit, CohortLive, CohortMessage, CohortRotate, ControlMessage, Disconnect,
    ForwarderLease, Frame, Heartbeat, MatchRequest, MatchResponse, MultiHopAssignment, Register,
    RegisterAck, SingleHopMatch, Tunnel, WG_KEY_LEN, WgPeerConfig, WgPublicKey, decode, encode,
};
use bytes::Bytes;
use ipnet::IpNet;
use proptest::collection::vec;
use proptest::prelude::*;
use time::{Duration, OffsetDateTime};
use ulid::Ulid;

/// Strategy producing an arbitrary [`PeerId`] from 16 random bytes.
fn arb_peer_id() -> impl Strategy<Value = PeerId> {
    any::<[u8; 16]>().prop_map(|bytes| PeerId(Ulid::from_bytes(bytes)))
}

/// Strategy producing an arbitrary [`NodeId`] from 16 random bytes.
fn arb_node_id() -> impl Strategy<Value = NodeId> {
    any::<[u8; 16]>().prop_map(|bytes| NodeId(Ulid::from_bytes(bytes)))
}

/// Strategy producing an arbitrary [`CohortId`] from 16 random bytes.
fn arb_cohort_id() -> impl Strategy<Value = CohortId> {
    any::<[u8; 16]>().prop_map(|bytes| CohortId(Ulid::from_bytes(bytes)))
}

/// Strategy producing an arbitrary [`ChainId`] from 16 random bytes.
fn arb_chain_id() -> impl Strategy<Value = ChainId> {
    any::<[u8; 16]>().prop_map(|bytes| ChainId(Ulid::from_bytes(bytes)))
}

/// Strategy producing an arbitrary RFC 3339-serialisable [`Timestamp`].
///
/// Bounded to the safe Unix-second range so `from_unix_timestamp` cannot
/// fail; the upper bound is well within `time`'s representable window
/// and the lower bound stays in the positive half so RFC 3339 has a
/// canonical form.
fn arb_timestamp() -> impl Strategy<Value = Timestamp> {
    (0_i64..4_102_444_800_i64).prop_map(|seconds| {
        let odt = OffsetDateTime::UNIX_EPOCH + Duration::seconds(seconds);
        Timestamp::from_offset_date_time(odt)
    })
}

/// Strategy producing an arbitrary [`SocketAddr`] across both IP families.
fn arb_socket_addr() -> impl Strategy<Value = SocketAddr> {
    let v4 = (any::<u32>(), any::<u16>())
        .prop_map(|(ip, port)| SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port));
    let v6 = (any::<u128>(), any::<u16>())
        .prop_map(|(ip, port)| SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port));
    prop_oneof![v4, v6]
}

/// Strategy producing an opaque [`Bytes`] payload of bounded length.
fn arb_bytes() -> impl Strategy<Value = Bytes> {
    vec(any::<u8>(), 0..64).prop_map(Bytes::from)
}

fn arb_register() -> impl Strategy<Value = Register> {
    (arb_peer_id(), arb_socket_addr(), any::<bool>(), any::<u32>(), arb_timestamp()).prop_map(
        |(peer_id, addr_hint, can_exit, capacity_hint, at)| Register {
            peer_id,
            addr_hint,
            can_exit,
            capacity_hint,
            at,
        },
    )
}

fn arb_register_ack() -> impl Strategy<Value = RegisterAck> {
    (arb_bytes(), arb_timestamp())
        .prop_map(|(session_token, expires_at)| RegisterAck { session_token, expires_at })
}

fn arb_match_request() -> impl Strategy<Value = MatchRequest> {
    (arb_peer_id(), arb_timestamp()).prop_map(|(peer_id, at)| MatchRequest { peer_id, at })
}

fn arb_single_hop_match() -> impl Strategy<Value = SingleHopMatch> {
    // `exit_regions` is sampled as a subset of `exit_set` keyed by
    // node id so the codec round-trip exercises a populated map (the
    // shape coord emits at R-REGION.3) without testing coordinator
    // semantics. Region strings are short ASCII slugs — same shape
    // operators tag with, but the test doesn't care about the value
    // beyond byte-for-byte equality across the serde boundary.
    (
        arb_cohort_id(),
        vec(arb_node_id(), 0..8),
        vec("[a-z]{2}-[a-z]{2,8}", 0..4),
        arb_timestamp(),
    )
        .prop_map(|(cohort, exit_set, region_pool, rotation_deadline)| {
            let mut exit_regions = std::collections::HashMap::new();
            for (idx, node) in exit_set.iter().enumerate() {
                if region_pool.is_empty() {
                    break;
                }
                if idx % 2 == 0 {
                    let region = region_pool[idx % region_pool.len()].clone();
                    exit_regions.insert(*node, region);
                }
            }
            SingleHopMatch {
                cohort,
                exit_set,
                exit_regions,
                rotation_deadline,
            }
        })
}

fn arb_wg_public_key() -> impl Strategy<Value = WgPublicKey> {
    any::<[u8; WG_KEY_LEN]>().prop_map(WgPublicKey::from_bytes)
}

fn arb_ipnet() -> impl Strategy<Value = IpNet> {
    prop_oneof![
        Just("0.0.0.0/0".parse::<IpNet>().expect("parse v4 cidr")),
        Just("::/0".parse::<IpNet>().expect("parse v6 cidr")),
        Just("10.0.0.0/8".parse::<IpNet>().expect("parse v4 private cidr")),
    ]
}

fn arb_wg_peer_config() -> impl Strategy<Value = WgPeerConfig> {
    (
        arb_wg_public_key(),
        arb_wg_public_key(),
        arb_socket_addr(),
        vec(arb_ipnet(), 0..4),
        any::<u16>(),
    )
        .prop_map(
            |(
                local_static_public,
                peer_static_public,
                peer_endpoint,
                allowed_ips,
                persistent_keepalive_secs,
            )| WgPeerConfig {
                local_static_public,
                peer_static_public,
                peer_endpoint,
                allowed_ips,
                persistent_keepalive_secs,
            },
        )
}

fn arb_forwarder_lease() -> impl Strategy<Value = ForwarderLease> {
    (
        arb_node_id(),
        arb_chain_id(),
        arb_socket_addr(),
        arb_socket_addr(),
        arb_timestamp(),
    )
        .prop_map(|(forwarder, chain_id, allowed_src, allowed_dst, lease_expires_at)| {
            ForwarderLease {
                forwarder,
                chain_id,
                allowed_src,
                allowed_dst,
                lease_expires_at,
            }
        })
}

fn arb_multi_hop_assignment() -> impl Strategy<Value = MultiHopAssignment> {
    // Chain is at least 1 element by structural invariant (validated
    // on deserialize); the strategy must respect that.
    (arb_node_id(), vec(arb_forwarder_lease(), 1..4), arb_wg_peer_config()).prop_map(
        |(exit, forwarder_chain, client_wg_config)| MultiHopAssignment {
            exit,
            forwarder_chain,
            client_wg_config,
        },
    )
}

fn arb_match_response() -> impl Strategy<Value = MatchResponse> {
    prop_oneof![
        arb_single_hop_match().prop_map(MatchResponse::SingleHop),
        arb_multi_hop_assignment().prop_map(MatchResponse::MultiHopAssignment),
    ]
}

fn arb_heartbeat() -> impl Strategy<Value = Heartbeat> {
    (arb_peer_id(), arb_timestamp()).prop_map(|(peer_id, at)| Heartbeat { peer_id, at })
}

fn arb_disconnect() -> impl Strategy<Value = Disconnect> {
    (arb_peer_id(), "[a-zA-Z0-9 ]{0,32}", arb_timestamp())
        .prop_map(|(peer_id, reason, at)| Disconnect { peer_id, reason, at })
}

fn arb_tunnel() -> impl Strategy<Value = Tunnel> {
    (arb_peer_id(), arb_bytes()).prop_map(|(peer_id, payload)| Tunnel { peer_id, payload })
}

fn arb_cohort_admit() -> impl Strategy<Value = CohortAdmit> {
    (arb_cohort_id(), arb_peer_id(), arb_timestamp()).prop_map(|(cohort, member, at)| CohortAdmit {
        cohort,
        member,
        at,
    })
}

fn arb_cohort_live() -> impl Strategy<Value = CohortLive> {
    // Keep the tuple arity unchanged: `exit_regions` is set to an
    // empty map here. The map's serde round-trip is exercised
    // implicitly via the empty-map encoding; randomising the map's
    // shape would couple this strategy to the cohort-emitter
    // (F-CLI.4b / R-REGION.3) which has not yet landed.
    (
        arb_cohort_id(),
        vec(arb_peer_id(), 0..8),
        vec(arb_node_id(), 0..8),
        arb_timestamp(),
    )
        .prop_map(|(cohort, members, exits, at)| CohortLive {
            cohort,
            members,
            exits,
            exit_regions: std::collections::HashMap::new(),
            at,
        })
}

fn arb_cohort_rotate() -> impl Strategy<Value = CohortRotate> {
    (arb_cohort_id(), arb_cohort_id(), arb_timestamp()).prop_map(|(old, new, at)| CohortRotate {
        old,
        new,
        at,
    })
}

fn arb_cohort_message() -> impl Strategy<Value = CohortMessage> {
    prop_oneof![
        arb_cohort_admit().prop_map(CohortMessage::Admit),
        arb_cohort_live().prop_map(CohortMessage::Live),
        arb_cohort_rotate().prop_map(CohortMessage::Rotate),
    ]
}

fn arb_control_message() -> impl Strategy<Value = ControlMessage> {
    prop_oneof![
        arb_register().prop_map(ControlMessage::Register),
        arb_register_ack().prop_map(ControlMessage::RegisterAck),
        arb_match_request().prop_map(ControlMessage::MatchRequest),
        arb_match_response().prop_map(ControlMessage::MatchResponse),
        arb_heartbeat().prop_map(ControlMessage::Heartbeat),
        arb_disconnect().prop_map(ControlMessage::Disconnect),
    ]
}

/// Strategy yielding any of the current [`Frame`] variants.
///
/// Each new variant introduced by a later F-PROTO sub-item plugs in here
/// — extend the alternative list, not the proptest body.
fn arb_frame() -> impl Strategy<Value = Frame> {
    prop_oneof![
        arb_control_message().prop_map(Frame::Control),
        arb_tunnel().prop_map(Frame::Tunnel),
        arb_cohort_message().prop_map(Frame::Cohort),
    ]
}

proptest! {
    /// Encoding then decoding must yield the original frame.
    #[test]
    fn encode_then_decode_is_identity(frame in arb_frame()) {
        let bytes = encode(&frame).expect("encode never fails on in-memory Frame");
        let decoded = decode(&bytes).expect("decode of fresh encode must succeed");
        prop_assert_eq!(decoded, frame);
    }
}
