#![forbid(unsafe_code)]
#![allow(
    dead_code,
    reason = "R-MULTIHOP-CLI lands the client-side multi-hop encode / decode primitive; \
              the bootstrap layer (`bibeam_discovery::bootstrap`) still rejects multi-hop \
              assignments with a typed error at `bootstrap.rs:234` — a follow-up commit \
              displaces that rejection and threads `ClientSession` through `cli::handle_up`. \
              In the meantime the module is exercised exclusively by its in-module test \
              harness; rustc's `dead_code` lint flags every `pub(crate)` item because no \
              production-path caller has landed yet. Keeping the module reachable from \
              `main.rs` ensures `cargo check` keeps the cipher / relay-frame wiring on the \
              live compile path until the follow-up wire-up commit lands."
)]
//! Client-side single end-to-end `WireGuard` session through an optional
//! forwarder chain (R-MULTIHOP-CLI).
//!
//! [`ClientSession`] owns the cipher state (one `WgTunnel`) and the
//! per-assignment routing metadata (next-hop socket + optional
//! [`ChainId`]) needed to push outbound packets onto the network and
//! pull inbound packets off it.
//!
//! ## Why a single session
//!
//! Per §11 D-6 RESOLVED option (c) cascading-edits, the client holds
//! exactly ONE [`bibeam_transport::WgTunnel`] per active assignment —
//! NOT N for an N-hop path. The cryptographic peer is always the exit;
//! the forwarder chain is a packet-routing layer above the
//! `WireGuard` cipher and never holds the session's private keys
//! (the coordinator never holds them either — see
//! [`bibeam_protocol::multihop::WgPeerConfig`]).
//!
//! Concretely:
//!
//! - On a [`bibeam_protocol::MatchResponse::MultiHopAssignment`]:
//!   the client establishes a single WG session against the exit's
//!   static public key. Outbound `WireGuard` packets are addressed
//!   at the UDP layer to the FIRST forwarder's socket (carried in
//!   [`bibeam_protocol::multihop::WgPeerConfig::peer_endpoint`]) and
//!   wrapped in a [`RelayFrame`] keyed by the FIRST forwarder's
//!   [`ChainId`] (the first entry of
//!   [`bibeam_protocol::MultiHopAssignment::forwarder_chain`]).
//!   Forwarders unwrap, demultiplex by chain id, and relay onward.
//! - On a [`bibeam_protocol::MatchResponse::SingleHop`]: there is no
//!   forwarder chain, so outbound packets are sent to the exit's
//!   socket directly with NO [`RelayFrame`] wrapping. The
//!   `WireGuard` transport datagram is the payload of the UDP packet
//!   verbatim — the pre-multi-hop happy path.
//!
//! ## Frame shapes by mode
//!
//! ```text
//! Multi-hop outbound UDP body:
//!   [chain_id (16 bytes) | wg_payload (variable)]   ← RelayFrame::encode
//!
//! Single-hop outbound UDP body:
//!   [wg_payload (variable)]                          ← bare WG transport
//! ```
//!
//! ## Packet flow
//!
//! ```text
//!   ┌─────────────┐    encode_outbound(plain IP)
//!   │ TUN device  │ ───────────────────────────────► UDP socket
//!   └─────────────┘                                  send_to(next_hop_addr)
//!
//!         ▲                                                │
//!         │ decode_inbound(udp bytes) → plain IP           │
//!         │                                                │
//!   ┌─────────────┐                                  ┌─────▼──────┐
//!   │ TUN device  │ ◄──────────── UDP socket ◄──────│ Forwarder  │
//!   └─────────────┘                  recv_from       │  chain or  │
//!                                                    │ exit direct│
//!                                                    └────────────┘
//! ```
//!
//! ## Scope
//!
//! This module owns the *encode / decode* shape ONLY: the cipher edge
//! (`WireGuard` encap/decap via `bibeam_transport::WgTunnel`) plus the
//! relay-frame wrap/unwrap. Driving the TUN ↔ socket pump and consuming
//! a real [`bibeam_protocol::MatchResponse`] from the bootstrap path
//! lands in a follow-up commit; today the consumer of
//! [`ClientSession`] is the in-module test harness only. The module is
//! reachable from `main.rs` via `mod multihop;` so `cargo check` keeps
//! it on the live compile path.

use core::net::SocketAddr;

use bibeam_core::ChainId;
use bibeam_crypto::{WgPsk, WgPublicKey, WgSecretKey};
use bibeam_protocol::multihop::{RELAY_FRAME_PREFIX_LEN, RelayFrame};
use bibeam_transport::{WgTunnel, WgTunnelError};
use bytes::Bytes;
use thiserror::Error;
use tokio::net::UdpSocket;

/// Errors emitted by [`ClientSession`].
///
/// Every variant is either a cipher-layer failure surfaced from
/// `boringtun` (via [`WgTunnelError`]) or a wire-shape rejection on
/// the inbound path (a relay frame whose 16-byte prefix is missing,
/// or a relay frame whose `chain_id` does not match the active
/// assignment's chain id).
#[derive(Debug, Error)]
pub(crate) enum ClientSessionError {
    /// `boringtun` rejected an encap or decap call.
    #[error("wireguard cipher error: {0}")]
    WireGuard(#[from] WgTunnelError),
    /// Inbound buffer was shorter than the 16-byte [`RelayFrame`]
    /// prefix in multi-hop mode, so no `chain_id` could be parsed.
    /// Caller MUST drop the datagram.
    #[error("inbound buffer shorter than relay-frame prefix; need {RELAY_FRAME_PREFIX_LEN} bytes")]
    RelayFrameTooShort,
    /// Inbound relay frame carried a `chain_id` that does not belong
    /// to the active assignment. Caller MUST drop the datagram —
    /// accepting it would let a confused forwarder wrongly deliver
    /// another chain's traffic into this session.
    #[error("inbound chain_id does not match active assignment")]
    ChainIdMismatch,
}

/// Mode discriminator for the active match assignment.
///
/// `SingleHop` is the pre-multi-hop happy path — no `RelayFrame`
/// wrapping, UDP packets address the exit directly.
///
/// `MultiHop { chain_id }` carries the first forwarder's chain id;
/// outbound UDP packets carry a [`RelayFrame`] keyed by that chain id
/// and are addressed to the first forwarder's UDP socket (which the
/// caller obtains from [`ClientSession::next_hop_addr`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AssignmentMode {
    /// Single-hop: outbound packets are bare `WireGuard` transport.
    SingleHop,
    /// Multi-hop: outbound packets are `RelayFrame { chain_id, wg_payload }`.
    MultiHop {
        /// `chain_id` of the first forwarder in the chain.
        chain_id: ChainId,
    },
}

/// Single end-to-end client↔exit `WireGuard` session, optionally
/// routed through a forwarder chain.
///
/// Construct with [`Self::new_single_hop`] or [`Self::new_multi_hop`].
/// Use [`Self::encode_outbound`] to push a plaintext IP frame onto the
/// wire (returns the bytes to UDP-send to [`Self::next_hop_addr`]);
/// use [`Self::decode_inbound`] to pull a plaintext IP frame off a
/// UDP datagram received from the network.
///
/// ## Invariant
///
/// `ClientSession` holds EXACTLY ONE [`WgTunnel`] per instance — the
/// cipher edge between the client and the final exit. There is no
/// per-hop cipher state at the client side: forwarders are routing
/// only, never `WireGuard` peers in this session's view. See module
/// docs for the cascading-edits derivation.
#[derive(Debug)]
pub(crate) struct ClientSession {
    /// Cipher edge: one `WgTunnel` per session, regardless of hop count.
    tunnel: WgTunnel,
    /// UDP address outbound packets are sent to.
    ///
    /// For multi-hop this is the first forwarder's socket; for
    /// single-hop this is the exit's socket directly. Both come from
    /// [`bibeam_protocol::multihop::WgPeerConfig::peer_endpoint`]
    /// when the coordinator-supplied config is consumed.
    next_hop_addr: SocketAddr,
    /// Assignment mode — drives whether outbound bytes get wrapped in
    /// a [`RelayFrame`] and whether inbound bytes must be unwrapped.
    mode: AssignmentMode,
}

impl ClientSession {
    /// Build a single-hop client session.
    ///
    /// The `WgTunnel` is constructed against the exit's static public
    /// key directly; outbound UDP packets address `exit_endpoint`
    /// without any [`RelayFrame`] wrapping. `local_secret` is the
    /// client's locally-held `WgSecretKey` (it never leaves the
    /// client — the coordinator does not hold the session's private
    /// key). `preshared_key` matches `boringtun`'s `Tunn::new` PSK
    /// parameter and may be `None` for the bare X25519 path.
    ///
    /// The `socket` is taken by value; the returned `ClientSession`
    /// owns it for the lifetime of the session.
    #[must_use]
    pub(crate) fn new_single_hop(
        local_secret: &WgSecretKey,
        exit_public: &WgPublicKey,
        preshared_key: Option<&WgPsk>,
        exit_endpoint: SocketAddr,
        socket: UdpSocket,
    ) -> Self {
        Self {
            tunnel: WgTunnel::new(local_secret, exit_public, preshared_key, exit_endpoint, socket),
            next_hop_addr: exit_endpoint,
            mode: AssignmentMode::SingleHop,
        }
    }

    /// Build a multi-hop client session.
    ///
    /// The `WgTunnel` is constructed against the exit's static public
    /// key (NOT a forwarder's key — there is no per-forwarder cipher
    /// state at the client side). `first_forwarder_addr` is the
    /// network destination for outbound packets — typically obtained
    /// from
    /// [`bibeam_protocol::multihop::WgPeerConfig::peer_endpoint`],
    /// which the coordinator already aimed at the first hop's socket.
    /// `chain_id` is the [`ChainId`] of the first forwarder's lease
    /// (`forwarder_chain[0].chain_id`).
    #[must_use]
    pub(crate) fn new_multi_hop(
        local_secret: &WgSecretKey,
        exit_public: &WgPublicKey,
        preshared_key: Option<&WgPsk>,
        first_forwarder_addr: SocketAddr,
        chain_id: ChainId,
        socket: UdpSocket,
    ) -> Self {
        Self {
            tunnel: WgTunnel::new(
                local_secret,
                exit_public,
                preshared_key,
                first_forwarder_addr,
                socket,
            ),
            next_hop_addr: first_forwarder_addr,
            mode: AssignmentMode::MultiHop { chain_id },
        }
    }

    /// Construct a `ClientSession` from a pre-built [`WgTunnel`].
    ///
    /// Internal hook used by the in-module test harness: tests build
    /// two `WgTunnel`s, drive the handshake via the existing
    /// pump-methods on real loopback sockets, then wrap one of the
    /// established tunnels in a `ClientSession` to exercise the
    /// encode / decode path on a live cipher state without
    /// re-implementing the handshake here. The crate-private
    /// visibility keeps it off the public surface.
    #[cfg(test)]
    const fn from_parts(tunnel: WgTunnel, next_hop_addr: SocketAddr, mode: AssignmentMode) -> Self {
        Self { tunnel, next_hop_addr, mode }
    }

    /// UDP destination outbound packets must be sent to.
    ///
    /// In multi-hop mode this is the first forwarder; in single-hop
    /// mode this is the exit.
    #[must_use]
    pub(crate) const fn next_hop_addr(&self) -> SocketAddr {
        self.next_hop_addr
    }

    /// Active assignment mode.
    #[must_use]
    pub(crate) const fn mode(&self) -> AssignmentMode {
        self.mode
    }

    /// Borrow the inner `WgTunnel`.
    ///
    /// Exposed so a higher-level data-plane loop (TUN reader / UDP
    /// recver) can access the same `UdpSocket` and cipher engine the
    /// session owns, without having to plumb every field through.
    #[must_use]
    pub(crate) const fn tunnel(&self) -> &WgTunnel {
        &self.tunnel
    }

    /// Encode one outbound plaintext IP frame as a UDP datagram body.
    ///
    /// In single-hop mode the returned bytes are the raw `WireGuard`
    /// transport datagram; the caller `send_to`s them at
    /// [`Self::next_hop_addr`]. In multi-hop mode the returned bytes
    /// are `RelayFrame { chain_id, wg_payload }`-encoded — the
    /// 16-byte chain-id prefix followed by the `WireGuard` transport
    /// payload (see [`bibeam_protocol::multihop`] for the layout).
    ///
    /// Returns an empty `Bytes` on a `boringtun::noise::TunnResult::Done`
    /// (no session yet, `boringtun` queued the frame internally for the
    /// next handshake) — the caller MUST treat the empty buffer as
    /// "nothing to send right now" rather than a zero-length UDP
    /// datagram.
    ///
    /// # Errors
    ///
    /// Returns [`ClientSessionError::WireGuard`] for any cipher-layer
    /// failure surfaced by `boringtun`.
    pub(crate) fn encode_outbound(&self, plain: &[u8]) -> Result<Bytes, ClientSessionError> {
        let wg_payload = self.encapsulate_to_bytes(plain)?;
        if wg_payload.is_empty() {
            return Ok(Bytes::new());
        }
        match self.mode {
            AssignmentMode::SingleHop => Ok(wg_payload),
            AssignmentMode::MultiHop { chain_id } => Ok(wrap_in_relay_frame(chain_id, wg_payload)),
        }
    }

    /// Decode one inbound UDP datagram body as a plaintext IP frame.
    ///
    /// In multi-hop mode the input is a [`RelayFrame`]-encoded body;
    /// the 16-byte chain-id prefix is verified against the active
    /// assignment's chain id and the `wg_payload` is fed to the
    /// cipher. In single-hop mode the input is the raw `WireGuard`
    /// transport payload.
    ///
    /// Returns [`Some`] with the plaintext IP frame when the cipher
    /// surfaces a tunnel-bound packet (`boringtun`'s
    /// `WriteToTunnelV4`/`V6`), or [`None`] when the bytes were a
    /// handshake / cookie / keepalive that did not produce inner
    /// plaintext.
    ///
    /// # Errors
    ///
    /// - [`ClientSessionError::RelayFrameTooShort`] in multi-hop mode
    ///   when the input is shorter than the 16-byte prefix.
    /// - [`ClientSessionError::ChainIdMismatch`] in multi-hop mode
    ///   when the parsed chain id does not equal the active
    ///   assignment's chain id.
    /// - [`ClientSessionError::WireGuard`] for any cipher-layer
    ///   failure surfaced by `boringtun`.
    pub(crate) fn decode_inbound(
        &self,
        udp_bytes: &[u8],
    ) -> Result<Option<Bytes>, ClientSessionError> {
        let wg_payload = match self.mode {
            AssignmentMode::SingleHop => udp_bytes,
            AssignmentMode::MultiHop { chain_id } => {
                let frame = RelayFrame::decode(udp_bytes)
                    .map_err(|_| ClientSessionError::RelayFrameTooShort)?;
                if frame.chain_id != chain_id {
                    return Err(ClientSessionError::ChainIdMismatch);
                }
                // The forwarder strips RelayFrame already; we only see
                // it here because the inbound path on the client is
                // symmetric with the outbound path (chain returns
                // wrapped frames as well). Hand the inner WG payload
                // to the cipher in a freshly allocated owned buffer
                // so the borrow scope can close cleanly.
                return self.decapsulate_owned(&frame.wg_payload);
            },
        };
        self.decapsulate_owned(wg_payload)
    }

    /// Inner: encapsulate `plain` via the WG cipher and return an
    /// owned `Bytes` view of the network-bound payload. The buffer
    /// is sized to `boringtun`'s documented floor (max of
    /// `plain.len() + 32` and 148) so encap never reports
    /// [`WgTunnelError::BufferTooSmall`].
    fn encapsulate_to_bytes(&self, plain: &[u8]) -> Result<Bytes, ClientSessionError> {
        let needed = encap_buffer_floor(plain.len());
        let mut buf = vec![0_u8; needed];
        let bytes_written = self.tunnel.encapsulate(plain, &mut buf)?;
        buf.truncate(bytes_written);
        Ok(Bytes::from(buf))
    }

    /// Inner: decapsulate `wg_payload` via the WG cipher and return
    /// the optional inner plaintext IP frame in an owned `Bytes` view.
    /// The output buffer is sized to `wg_payload.len()` since
    /// `boringtun` writes at most that many plaintext bytes (and
    /// usually fewer — the AEAD tag is stripped).
    fn decapsulate_owned(&self, wg_payload: &[u8]) -> Result<Option<Bytes>, ClientSessionError> {
        let mut out = vec![0_u8; wg_payload.len().max(1)];
        let outcome = self.tunnel.decapsulate(wg_payload, &mut out)?;
        Ok(outcome.map(|plain_len| {
            out.truncate(plain_len);
            Bytes::from(out)
        }))
    }
}

/// Size the encapsulate destination buffer up to `boringtun`'s floor.
///
/// `boringtun::noise::Tunn::encapsulate` requires the destination to be
/// at least `plain.len() + 32` bytes and at least 148 bytes (the
/// handshake-init datagram length). Sizing to the max of those two
/// values guarantees [`WgTunnel::encapsulate`] never reports
/// [`WgTunnelError::BufferTooSmall`] from this module.
fn encap_buffer_floor(plain_len: usize) -> usize {
    core::cmp::max(plain_len.saturating_add(32), 148)
}

/// Wrap an opaque `wg_payload` in a [`RelayFrame`] keyed by
/// `chain_id`. The returned [`Bytes`] is exactly
/// `RELAY_FRAME_PREFIX_LEN + wg_payload.len()` bytes long — the
/// 16-byte chain-id prefix followed by the payload verbatim.
fn wrap_in_relay_frame(chain_id: ChainId, wg_payload: Bytes) -> Bytes {
    RelayFrame { chain_id, wg_payload }.encode()
}

#[cfg(test)]
mod tests {
    use core::net::{IpAddr, Ipv4Addr, SocketAddr};

    use bibeam_crypto::WgSecretKey;
    use tokio::net::UdpSocket;

    use super::*;

    /// Loopback bind helper: bind on `127.0.0.1:0` so the kernel
    /// assigns a free port per test, avoiding port collisions in
    /// parallel test runs.
    fn loopback_unspec() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    /// Build a minimal IPv4-over-UDP datagram tests feed through the
    /// `WireGuard` tunnel. `boringtun`'s `WriteToTunnelV4` path
    /// validates the version nibble and the `Total Length` field but
    /// not the IP / UDP checksums, so both are left zero.
    fn make_ipv4_udp_packet(src_ip: [u8; 4], dst_ip: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let ip_total_len: u16 = u16::try_from(20 + 8 + payload.len()).expect("packet fits in u16");
        let udp_len: u16 = u16::try_from(8 + payload.len()).expect("udp payload fits in u16");
        let mut packet = Vec::with_capacity(usize::from(ip_total_len));
        // IPv4 header
        packet.push(0x45); // version 4, IHL 5
        packet.push(0x00); // DSCP / ECN
        packet.extend_from_slice(&ip_total_len.to_be_bytes());
        packet.extend_from_slice(&[0, 0]); // ID
        packet.extend_from_slice(&[0x40, 0x00]); // flags=DF, fragment offset 0
        packet.push(64); // TTL
        packet.push(17); // protocol UDP
        packet.extend_from_slice(&[0, 0]); // header checksum (zero — boringtun skips)
        packet.extend_from_slice(&src_ip);
        packet.extend_from_slice(&dst_ip);
        // UDP header
        packet.extend_from_slice(&1234_u16.to_be_bytes()); // src port
        packet.extend_from_slice(&5678_u16.to_be_bytes()); // dst port
        packet.extend_from_slice(&udp_len.to_be_bytes());
        packet.extend_from_slice(&[0, 0]); // UDP checksum (zero)
        packet.extend_from_slice(payload);
        packet
    }

    /// Two-party WG handshake harness: returns a pair of `WgTunnel`s
    /// (alice = "client", bob = "exit") with a completed handshake,
    /// driven through real loopback UDP sockets. Mirrors the existing
    /// `two_tunnels_complete_a_round_trip` test in
    /// `bibeam_transport::wg_tunnel`.
    async fn complete_handshake() -> (WgTunnel, WgTunnel) {
        let alice_socket = UdpSocket::bind(loopback_unspec()).await.expect("bind alice");
        let bob_socket = UdpSocket::bind(loopback_unspec()).await.expect("bind bob");
        let alice_addr = alice_socket.local_addr().expect("alice local addr");
        let bob_addr = bob_socket.local_addr().expect("bob local addr");

        let alice_secret = WgSecretKey::generate();
        let bob_secret = WgSecretKey::generate();
        let alice_public = alice_secret.public();
        let bob_public = bob_secret.public();

        let alice = WgTunnel::with_session_prefix(
            &alice_secret,
            &bob_public,
            None,
            bob_addr,
            alice_socket,
            1,
        );
        let bob = WgTunnel::with_session_prefix(
            &bob_secret,
            &alice_public,
            None,
            alice_addr,
            bob_socket,
            2,
        );

        // Drive the handshake using a small placeholder IPv4 packet
        // that boringtun queues until the session comes up. The
        // sequence is identical to wg_tunnel.rs's existing harness;
        // any deviation would surface there as a regression first.
        let placeholder = make_ipv4_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], b"hs");
        let init_len = alice
            .pump_peer_to_socket(&placeholder)
            .await
            .expect("alice -> bob handshake init send");
        assert!(init_len >= 148, "handshake init was {init_len} bytes");

        let after_init = bob.pump_socket_to_peer().await.expect("bob processes init");
        assert!(after_init.is_none(), "handshake init alone surfaces no plaintext");

        let after_response = alice.pump_socket_to_peer().await.expect("alice processes response");
        assert!(after_response.is_none(), "handshake response alone surfaces no plaintext");

        // Drain bob's queued keepalive + the placeholder packet so
        // the established cipher state on bob's side is clean before
        // tests drive their own payloads through the session.
        let bob_keepalive = bob.pump_socket_to_peer().await.expect("bob keepalive");
        assert!(bob_keepalive.is_none(), "keepalive carries no plaintext");
        let bob_queued = bob.pump_socket_to_peer().await.expect("bob queued");
        let queued_bytes = bob_queued.expect("queued placeholder must surface");
        assert_eq!(queued_bytes.as_ref(), placeholder.as_slice());

        (alice, bob)
    }

    #[tokio::test]
    async fn multi_hop_round_trip_at_typical_wg_mtu() {
        // Contract: in multi-hop mode, encode_outbound wraps the WG
        // transport payload in a RelayFrame keyed by the active
        // chain_id. The peer (decoded by the in-test "exit") strips
        // the prefix and the inner WG decapsulate surfaces the
        // original plaintext IP frame. Exercises the 1280-byte WG MTU
        // path the task explicitly calls for.
        let (alice, bob) = Box::pin(complete_handshake()).await;
        let bob_addr = bob.peer_addr();
        let chain_id = ChainId::new();

        // Build the multi-hop client session by wrapping alice's
        // already-handshaken tunnel. next_hop_addr here is whatever
        // the first forwarder's socket would be in production; the
        // address only matters to the caller doing the UDP send, not
        // to the cipher edge.
        let session =
            ClientSession::from_parts(alice, bob_addr, AssignmentMode::MultiHop { chain_id });

        let plain = make_ipv4_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], &[0x42; 1280 - 28]);
        let outbound = session.encode_outbound(&plain).expect("encode_outbound");
        assert!(
            outbound.len() > RELAY_FRAME_PREFIX_LEN,
            "multi-hop outbound must carry the relay-frame prefix plus ciphertext",
        );

        // Decode the outbound bytes as a RelayFrame, verify chain_id,
        // hand the inner wg_payload to the peer's cipher to recover
        // the plaintext.
        let decoded = RelayFrame::decode(&outbound).expect("outbound must parse as RelayFrame");
        assert_eq!(
            decoded.chain_id, chain_id,
            "outbound frame must carry the active assignment's chain_id",
        );

        let mut out = vec![0_u8; decoded.wg_payload.len()];
        let plain_len = bob
            .decapsulate(&decoded.wg_payload, &mut out)
            .expect("peer decapsulate")
            .expect("peer must surface plaintext");
        out.truncate(plain_len);
        assert_eq!(out.as_slice(), plain.as_slice());
    }

    #[tokio::test]
    async fn multi_hop_decode_inbound_round_trip() {
        // Contract: decode_inbound strips the RelayFrame wrap on the
        // inbound path and the cipher surfaces the inner plaintext.
        // Drives the symmetric direction of the outbound test above.
        let (alice, bob) = Box::pin(complete_handshake()).await;
        let bob_addr = bob.peer_addr();
        let chain_id = ChainId::new();

        let session =
            ClientSession::from_parts(alice, bob_addr, AssignmentMode::MultiHop { chain_id });

        // Build a payload, drive bob's encapsulate to produce the WG
        // transport datagram the forwarder would see on the inbound
        // direction, then wrap it as a RelayFrame ourselves (the
        // forwarder would do this in production) and feed it to
        // decode_inbound.
        let plain = make_ipv4_udp_packet([10, 0, 0, 2], [10, 0, 0, 1], b"hello-back");
        let mut wg_bytes = vec![0_u8; encap_buffer_floor(plain.len())];
        let wg_len = bob.encapsulate(&plain, &mut wg_bytes).expect("bob encapsulate");
        wg_bytes.truncate(wg_len);

        let relay_frame = RelayFrame {
            chain_id,
            wg_payload: Bytes::from(wg_bytes),
        }
        .encode();
        let recovered = session
            .decode_inbound(&relay_frame)
            .expect("decode_inbound")
            .expect("plaintext must surface");
        assert_eq!(recovered.as_ref(), plain.as_slice());
    }

    #[tokio::test]
    async fn single_hop_outbound_carries_no_relay_frame() {
        // Contract: in single-hop mode encode_outbound emits the raw
        // WireGuard transport bytes — no chain_id prefix, no
        // RelayFrame wrapping. The bytes must equal what
        // WgTunnel::encapsulate would have produced on its own.
        let (alice, bob) = Box::pin(complete_handshake()).await;
        let bob_addr = bob.peer_addr();
        let session = ClientSession::from_parts(alice, bob_addr, AssignmentMode::SingleHop);

        let plain = make_ipv4_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], b"single-hop");
        let outbound = session.encode_outbound(&plain).expect("encode_outbound");

        // The peer must be able to decapsulate the outbound bytes
        // directly with no unwrapping. If the single-hop short-circuit
        // were regressed to wrap RelayFrame, this decapsulate would
        // fail because the first 16 bytes would be interpreted as
        // WG transport header instead of a chain-id prefix.
        let mut out = vec![0_u8; outbound.len()];
        let plain_len = bob
            .decapsulate(&outbound, &mut out)
            .expect("peer decapsulate single-hop")
            .expect("peer must surface plaintext");
        out.truncate(plain_len);
        assert_eq!(out.as_slice(), plain.as_slice());
    }

    #[tokio::test]
    async fn decode_inbound_rejects_chain_id_mismatch() {
        // Contract: in multi-hop mode, decode_inbound MUST reject a
        // RelayFrame whose chain_id does not match the active
        // assignment. A regression that silently accepted the
        // wrongly keyed frame would let a confused forwarder smuggle
        // another chain's traffic into this session.
        let (alice, bob) = Box::pin(complete_handshake()).await;
        let bob_addr = bob.peer_addr();
        let chain_id = ChainId::new();
        let wrong_chain_id = ChainId::new();
        assert_ne!(chain_id, wrong_chain_id, "fresh ULIDs must differ");

        let session =
            ClientSession::from_parts(alice, bob_addr, AssignmentMode::MultiHop { chain_id });

        let plain = make_ipv4_udp_packet([10, 0, 0, 2], [10, 0, 0, 1], b"smuggle");
        let mut wg_bytes = vec![0_u8; encap_buffer_floor(plain.len())];
        let wg_len = bob.encapsulate(&plain, &mut wg_bytes).expect("bob encapsulate");
        wg_bytes.truncate(wg_len);
        let bad_frame = RelayFrame {
            chain_id: wrong_chain_id,
            wg_payload: Bytes::from(wg_bytes),
        }
        .encode();
        let outcome = session.decode_inbound(&bad_frame);
        assert!(
            matches!(outcome, Err(ClientSessionError::ChainIdMismatch)),
            "expected ChainIdMismatch, got {outcome:?}",
        );
    }

    #[tokio::test]
    async fn decode_inbound_rejects_truncated_relay_frame() {
        // Contract: a buffer shorter than the 16-byte chain_id prefix
        // surfaces as RelayFrameTooShort. Mirrors the wire-level
        // guard in bibeam_protocol::multihop::RelayFrame::decode and
        // ensures the client never invokes the cipher on a corrupt
        // wrapper.
        let (alice, bob) = Box::pin(complete_handshake()).await;
        let bob_addr = bob.peer_addr();
        let session = ClientSession::from_parts(
            alice,
            bob_addr,
            AssignmentMode::MultiHop { chain_id: ChainId::new() },
        );

        for short_len in 0..RELAY_FRAME_PREFIX_LEN {
            let buf = vec![0_u8; short_len];
            let outcome = session.decode_inbound(&buf);
            assert!(
                matches!(outcome, Err(ClientSessionError::RelayFrameTooShort)),
                "len {short_len} expected RelayFrameTooShort, got {outcome:?}",
            );
        }
    }

    #[tokio::test]
    async fn next_hop_addr_reflects_mode() {
        // Contract: next_hop_addr returns the forwarder's address in
        // multi-hop mode and the exit's address in single-hop mode.
        // A regression that mixed these up would have outbound packets
        // bypass the forwarder chain (in multi-hop) or attempt to
        // address a non-existent forwarder (in single-hop).
        let exit_addr: SocketAddr = "203.0.113.1:51820".parse().expect("parse fixture");
        let forwarder_addr: SocketAddr = "203.0.113.99:51820".parse().expect("parse fixture");

        let local_secret = WgSecretKey::generate();
        let exit_secret = WgSecretKey::generate();
        let exit_public = exit_secret.public();

        let single_socket = UdpSocket::bind(loopback_unspec()).await.expect("bind single");
        let single = ClientSession::new_single_hop(
            &local_secret,
            &exit_public,
            None,
            exit_addr,
            single_socket,
        );
        assert_eq!(single.next_hop_addr(), exit_addr);
        assert_eq!(single.mode(), AssignmentMode::SingleHop);

        let multi_socket = UdpSocket::bind(loopback_unspec()).await.expect("bind multi");
        let chain_id = ChainId::new();
        let multi = ClientSession::new_multi_hop(
            &local_secret,
            &exit_public,
            None,
            forwarder_addr,
            chain_id,
            multi_socket,
        );
        assert_eq!(multi.next_hop_addr(), forwarder_addr);
        assert_eq!(multi.mode(), AssignmentMode::MultiHop { chain_id });
    }

    #[test]
    fn encap_buffer_floor_respects_boringtun_minimum() {
        // Contract: encap_buffer_floor returns at least 148 (the
        // handshake-init datagram length) regardless of plain.len().
        // A regression that returned plain.len() + 32 unconditionally
        // would surface as BufferTooSmall on the very first
        // encapsulate call from a fresh session.
        assert_eq!(encap_buffer_floor(0), 148);
        assert_eq!(encap_buffer_floor(50), 148);
        assert_eq!(encap_buffer_floor(116), 148);
        assert_eq!(encap_buffer_floor(117), 149);
        assert_eq!(encap_buffer_floor(1280), 1312);
    }
}
