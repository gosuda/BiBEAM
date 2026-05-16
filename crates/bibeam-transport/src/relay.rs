#![forbid(unsafe_code)]
//! Relay-fallback path for cohort peers that cannot complete the
//! ICE-lite hole-punch.
//!
//! Per the F-TRANS scope: when F-TRANS.5's [`crate::simultaneous_open`]
//! does not establish a direct WG flow within the 5-second timeout
//! window, we fall back to wrapping the encrypted WG datagrams in a
//! thin envelope and forwarding via the coordinator-assigned relay
//! node. The envelope is the same [`bibeam_protocol::Frame::Tunnel`]
//! the rest of the data plane already speaks, so the relay node only
//! needs to decode the outer envelope to learn the destination peer
//! and forward the WG payload onward.
//!
//! ## Why the protocol-layer envelope and not a private one
//!
//! `bibeam_protocol` already owns the cross-crate wire shape (frame
//! prefix, codec, magic + version bytes). Reusing
//! [`bibeam_protocol::Frame::Tunnel`] for the relay path means:
//!
//! 1. The relay node uses one decoder for all traffic it sees.
//! 2. A flow that transitions from direct → relayed (or back) carries
//!    the same `peer_id` field across the boundary.
//! 3. There is no second wire shape to keep in sync.
//!
//! ## Direction and peer identities
//!
//! A `RelayPath` is parameterised by **two** distinct [`PeerId`]s:
//!
//! - `local_peer_id` — the identity that stamps every outbound
//!   envelope's `peer_id` field. Per [`bibeam_protocol::Tunnel`]'s
//!   docstring, `peer_id` is "Identifier of the peer that sealed
//!   payload" — the local sender.
//! - `remote_peer_id` — the cohort partner whose envelopes we accept
//!   on the inbound path. Anything not stamped with this peer ID is
//!   filtered out by `recv`.
//!
//! [`RelayPath::send`] is the **client → relay** direction: the local
//! peer wraps a WG-encrypted UDP datagram, stamps it with
//! `local_peer_id`, and pushes it to the relay address.
//!
//! [`RelayPath::recv`] is the **relay → client** direction: it takes
//! an already-decoded inbound [`bibeam_protocol::Frame`] (the codec
//! step happens upstream in the receive loop) and surfaces the inner
//! `payload` bytes if the frame is a `Tunnel` variant whose `peer_id`
//! matches `remote_peer_id`.

use bytes::Bytes;
use thiserror::Error;
use tokio::net::UdpSocket;

use bibeam_core::PeerId;
use bibeam_protocol::{Frame, Tunnel, encode};

/// Errors emitted by the relay path.
#[derive(Debug, Error)]
pub enum RelayError {
    /// Underlying UDP socket I/O failed.
    #[error("relay: udp i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// `bibeam_protocol::encode` failed to serialise the relay
    /// envelope — typically because postcard rejected the payload
    /// shape, which should not happen for well-formed
    /// `Frame::Tunnel`s but is surfaced as a typed error rather than
    /// a silent drop.
    #[error("relay: protocol envelope encode failed: {0}")]
    Codec(#[from] postcard::Error),
}

/// One peer's view of the assigned relay node.
///
/// Carries the relay's UDP address plus the two cohort identities
/// the relay path needs to distinguish:
///
/// - `local_peer_id` — stamps outbound `peer_id` fields.
/// - `remote_peer_id` — filter for inbound `peer_id` fields.
///
/// Both IDs must already be agreed via the coordinator session
/// bootstrap (F-DISC.7); this struct does not negotiate them.
#[derive(Debug, Clone)]
pub struct RelayPath {
    relay_addr: std::net::SocketAddr,
    local_peer_id: PeerId,
    remote_peer_id: PeerId,
}

impl RelayPath {
    /// Build a new `RelayPath` bound to `relay_addr`.
    ///
    /// `local_peer_id` is the identity that stamps every outbound
    /// envelope. `remote_peer_id` is the cohort partner whose inbound
    /// envelopes [`Self::recv`] accepts.
    #[must_use]
    pub const fn new(
        relay_addr: std::net::SocketAddr,
        local_peer_id: PeerId,
        remote_peer_id: PeerId,
    ) -> Self {
        Self {
            relay_addr,
            local_peer_id,
            remote_peer_id,
        }
    }

    /// Relay address this path forwards to.
    #[must_use]
    pub const fn relay_addr(&self) -> std::net::SocketAddr {
        self.relay_addr
    }

    /// The local peer ID stamped onto every outbound envelope.
    #[must_use]
    pub const fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    /// The remote peer ID this path accepts inbound traffic from.
    #[must_use]
    pub const fn remote_peer_id(&self) -> PeerId {
        self.remote_peer_id
    }

    /// Wrap `wg_packet` in a [`Frame::Tunnel`] stamped with
    /// `local_peer_id`, serialise via `bibeam_protocol::encode`, and
    /// send the resulting bytes to the relay over `socket`.
    ///
    /// `wg_packet` is the already-encrypted output of
    /// [`crate::WgTunnel::encapsulate`] — opaque WG bytes to the
    /// relay node and to this layer alike.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::Codec`] for postcard serialisation
    /// failures and [`RelayError::Io`] for socket failures.
    pub async fn send(&self, socket: &UdpSocket, wg_packet: &[u8]) -> Result<(), RelayError> {
        let frame = Frame::Tunnel(Tunnel {
            peer_id: self.local_peer_id,
            payload: Bytes::copy_from_slice(wg_packet),
        });
        let encoded = encode(&frame)?;
        socket.send_to(&encoded, self.relay_addr).await?;
        Ok(())
    }

    /// Inspect a `bibeam_protocol::Frame` decoded upstream and return
    /// the inner WG `payload` if the frame is a `Tunnel` stamped with
    /// `remote_peer_id`. Returns `Ok(None)` for any frame that does
    /// not match — off-cohort tunnels and any non-`Tunnel` variant
    /// (control / cohort frames travel through their own machinery).
    ///
    /// The async/`Result` signature follows the spec template and is
    /// kept stable so a future iteration that adds envelope AEAD or
    /// replay-window checks can land without an API break. Today the
    /// body is a pure filter.
    ///
    /// # Errors
    ///
    /// Currently never fails; signature reserved for forward
    /// compatibility (`RelayError::Codec` is shared with [`Self::send`]).
    #[allow(clippy::unused_async, reason = "spec signature is async — see fn rustdoc")]
    pub async fn recv(&self, frame: Frame) -> Result<Option<Bytes>, RelayError> {
        match frame {
            Frame::Tunnel(tunnel) if tunnel.peer_id == self.remote_peer_id => {
                Ok(Some(tunnel.payload))
            },
            Frame::Tunnel(_) | Frame::Control(_) | Frame::Cohort(_) => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use bibeam_protocol::{Frame, Tunnel, decode};
    use bytes::Bytes;
    use tokio::net::UdpSocket;

    use bibeam_core::PeerId;

    use super::*;

    fn loopback_v4_zero() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    #[tokio::test]
    async fn send_round_trips_through_protocol_envelope() {
        // Bind a relay impostor on loopback; the test sender writes
        // its WG payload via RelayPath::send, the impostor decodes
        // the wire bytes via bibeam_protocol::decode, and we check
        // both the peer_id stamp and the carried payload.
        let relay_socket = UdpSocket::bind(loopback_v4_zero()).await.expect("bind relay");
        let relay_addr = relay_socket.local_addr().expect("relay addr");
        let sender_socket = UdpSocket::bind(loopback_v4_zero()).await.expect("bind sender");

        let local_peer = PeerId::new();
        let remote_peer = PeerId::new();
        let path = RelayPath::new(relay_addr, local_peer, remote_peer);

        let wg_packet: &[u8] = b"opaque-wg-encrypted-bytes-here";
        path.send(&sender_socket, wg_packet).await.expect("send via relay");

        let mut buf = [0_u8; 256];
        let (recv_len, _src) = relay_socket.recv_from(&mut buf).await.expect("relay recv");
        let decoded = decode(&buf[..recv_len]).expect("frame decodes");
        match decoded {
            Frame::Tunnel(tunnel) => {
                assert_eq!(tunnel.peer_id, local_peer, "sender stamp must round-trip");
                assert_eq!(tunnel.payload.as_ref(), wg_packet, "payload must round-trip");
            },
            Frame::Control(_) | Frame::Cohort(_) => {
                panic!("send must emit a Tunnel frame")
            },
        }
    }

    #[tokio::test]
    async fn recv_returns_payload_only_for_matching_remote_peer_id() {
        let local_peer = PeerId::new();
        let remote_peer = PeerId::new();
        let stranger = PeerId::new();
        let path = RelayPath::new(loopback_v4_zero(), local_peer, remote_peer);

        // Inbound frame stamped with remote_peer -> Some.
        let matching = Frame::Tunnel(Tunnel {
            peer_id: remote_peer,
            payload: Bytes::from_static(b"wg-bytes"),
        });
        let outcome = path.recv(matching).await.expect("recv ok");
        assert_eq!(outcome.as_deref(), Some(b"wg-bytes".as_slice()));

        // Inbound frame stamped with stranger -> None.
        let off_cohort = Frame::Tunnel(Tunnel {
            peer_id: stranger,
            payload: Bytes::from_static(b"other-bytes"),
        });
        let outcome = path.recv(off_cohort).await.expect("recv ok");
        assert!(outcome.is_none(), "off-cohort tunnel frame must filter out");

        // A frame stamped with our own local_peer_id is NOT accepted
        // — that would be a loopback / reflection bug, not a real
        // remote message.
        let self_stamped = Frame::Tunnel(Tunnel {
            peer_id: local_peer,
            payload: Bytes::from_static(b"echo-bytes"),
        });
        let outcome = path.recv(self_stamped).await.expect("recv ok");
        assert!(outcome.is_none(), "self-stamped tunnel frame must not echo");
    }

    #[tokio::test]
    async fn recv_returns_none_for_non_tunnel_frames() {
        let path = RelayPath::new(loopback_v4_zero(), PeerId::new(), PeerId::new());
        let cohort_frame =
            Frame::Cohort(bibeam_protocol::CohortMessage::Live(bibeam_protocol::CohortLive {
                cohort: bibeam_core::CohortId::new(),
                members: vec![],
                exits: vec![],
                exit_regions: std::collections::HashMap::new(),
                at: bibeam_core::Timestamp::now(),
            }));
        let outcome = path.recv(cohort_frame).await.expect("recv ok");
        assert!(outcome.is_none(), "cohort frames must bypass the relay path");
    }
}
