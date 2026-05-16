#![forbid(unsafe_code)]
//! `boringtun`-backed `WireGuard` tunnel handle over a `tokio` UDP
//! socket.
//!
//! [`WgTunnel`] is the data-plane primitive `bibeam-transport` exports
//! to `bibeam-node` and `bibeam-cli`. It owns:
//!
//! - a [`tokio::net::UdpSocket`] for the UDP carrier,
//! - a [`boringtun::noise::Tunn`] state machine for the `WireGuard`
//!   Noise handshake and per-packet AEAD, and
//! - the [`std::net::SocketAddr`] of the remote peer.
//!
//! Per D-4 this crate does not implement the `WireGuard` wire format
//! itself — `boringtun` does. [`WgTunnel`] is the thin async shim that
//! drives `boringtun`'s `&mut` API from one or more `tokio` tasks
//! without holding a synchronous lock across an `await`.
//!
//! ## Concurrency
//!
//! `boringtun::noise::Tunn` is a synchronous state machine with `&mut`
//! method receivers, so calls must be serialised. We use a
//! [`parking_lot::Mutex`] for that and **never hold the guard across an
//! `await`** — each public async fn locks the mutex, drives one
//! `boringtun` call, copies the relevant bytes out, drops the guard,
//! and only then does the I/O. That's enforced by structure: every
//! call site here uses an inner scope-bound block that returns owned
//! bytes before the `await`.

use core::fmt;
use std::net::SocketAddr;

use boringtun::noise::{Tunn, TunnResult, errors::WireGuardError};
use bytes::Bytes;
use parking_lot::Mutex;
use thiserror::Error;
use tokio::net::UdpSocket;

use bibeam_crypto::{WgPsk, WgPublicKey, WgSecretKey};

/// Maximum length of a `WireGuard` UDP datagram on the wire and of
/// the work / receive buffers used by [`WgTunnel`].
///
/// `boringtun` requires the destination buffer for both encapsulation
/// and decapsulation to be at least the size of the input plus the
/// AEAD overhead. The conventional WG MTU sits at 1420 bytes; we add
/// generous headroom for the WG transport header (~32 bytes), AEAD
/// tag (16 bytes), IPv6 jumbograms, and any path-MTU surprise, yielding
/// `4096`. That is well above any realistic WG datagram and stays
/// inside one filesystem-page worth of stack frame for the small fixed
/// arrays inside the pump methods. The encap path itself heap-allocates
/// proportionally to the plaintext length, so this constant only bounds
/// the recv / drain path.
const WG_MAX_DATAGRAM: usize = 4096;

/// Default session-index prefix passed to [`boringtun::noise::Tunn::new`].
///
/// `boringtun` derives a 32-bit session index from this 24-bit prefix
/// plus an internal counter. The prefix is purely an allocation hint
/// for routing simultaneous sessions on the same peer; downstream
/// users that need to disambiguate multiple tunnels per peer should
/// pass a distinct prefix via [`WgTunnel::with_session_prefix`].
const DEFAULT_SESSION_PREFIX: u32 = 0;

/// Errors emitted by [`WgTunnel`].
///
/// Failures fall into three classes: caller-provided buffer too small
/// for the `boringtun` operation, an underlying [`std::io::Error`] from
/// the UDP socket, or a [`WireGuardError`] surfaced by `boringtun` from
/// the Noise state machine.
#[derive(Debug, Error)]
pub enum WgTunnelError {
    /// Caller's output buffer is below `boringtun`'s minimum size for
    /// the requested operation (148 bytes for encap, 32 bytes for
    /// decap headroom).
    #[error("output buffer too small: have {have} bytes, need at least {need}")]
    BufferTooSmall {
        /// Bytes available in the caller's buffer.
        have: usize,
        /// Bytes `boringtun` requires for the operation.
        need: usize,
    },
    /// Underlying UDP socket I/O failed.
    #[error("udp i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// `boringtun` rejected the operation — invalid packet, expired
    /// session, etc. See [`WireGuardError`] for the discriminants.
    #[error("wireguard error: {0:?}")]
    WireGuard(WireGuardError),
}

/// Async, [`Send`] `WireGuard` tunnel handle backed by `boringtun`.
///
/// Construct with [`WgTunnel::new`], then drive the data plane with the
/// `pump_*` methods below (`pump_socket_to_peer` reads a UDP datagram
/// off the socket, hands it to `boringtun` for decap, and surfaces the
/// decrypted IP frame upward; `pump_peer_to_socket` takes an IP frame,
/// hands it to `boringtun` for encap, and sends the resulting `WireGuard`
/// UDP datagram out the socket).
///
/// The lower-level [`WgTunnel::encapsulate`] and [`WgTunnel::decapsulate`]
/// methods expose `boringtun`'s buffer-out shape directly for callers
/// (tests, the relay-fallback path) that need to drive the cipher
/// independently of the socket.
pub struct WgTunnel {
    socket: UdpSocket,
    inner: Mutex<Tunn>,
    peer_addr: SocketAddr,
}

impl fmt::Debug for WgTunnel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WgTunnel")
            .field("peer_addr", &self.peer_addr)
            .finish_non_exhaustive()
    }
}

impl WgTunnel {
    /// Build a new `WgTunnel` with the default session-index prefix.
    ///
    /// `local_secret` and `peer_public` are the X25519 long-term keys
    /// minted by `bibeam-crypto::WgSecretKey::generate` and exchanged
    /// out-of-band via the coordinator. `preshared_key` is the
    /// per-rotation `WgPsk` derived by F-CRYPTO.5 (and threaded through
    /// `boringtun` as the WG PSK), or [`None`] for the bare X25519 key
    /// exchange.
    ///
    /// `peer_addr` is the remote peer's `SocketAddr` discovered via
    /// F-TRANS.4's STUN client. `socket` is the local UDP socket the
    /// tunnel owns for its lifetime.
    ///
    /// Keys are taken by reference; this fn copies their raw 32-byte
    /// values into `boringtun`'s internal `StaticSecret` /
    /// `PublicKey` / PSK representations and never retains the
    /// caller's [`WgSecretKey`] / [`WgPublicKey`] / [`WgPsk`].
    ///
    /// This constructor is infallible: `Tunn::new` itself is infallible
    /// in `boringtun` 0.7, and every other input is already a typed,
    /// well-formed value at this point.
    #[must_use]
    pub fn new(
        local_secret: &WgSecretKey,
        peer_public: &WgPublicKey,
        preshared_key: Option<&WgPsk>,
        peer_addr: SocketAddr,
        socket: UdpSocket,
    ) -> Self {
        Self::with_session_prefix(
            local_secret,
            peer_public,
            preshared_key,
            peer_addr,
            socket,
            DEFAULT_SESSION_PREFIX,
        )
    }

    /// Build a `WgTunnel` with a caller-chosen 24-bit session-index
    /// prefix.
    ///
    /// Pass a distinct prefix per concurrent tunnel that shares a
    /// single peer to keep `boringtun`'s session-index allocation
    /// non-overlapping. The prefix is opaque to the wire and only
    /// affects internal routing.
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "boringtun's Tunn::new takes 6 inputs (two keys, optional PSK, \
                  keepalive, session prefix, rate limiter); this fn plus the \
                  socket + peer-addr already exceeds the 5-arg threshold. \
                  Wrapping in a builder struct hides the dependencies and adds \
                  no real ergonomic win at the one call-site this has."
    )]
    pub fn with_session_prefix(
        local_secret: &WgSecretKey,
        peer_public: &WgPublicKey,
        preshared_key: Option<&WgPsk>,
        peer_addr: SocketAddr,
        socket: UdpSocket,
        session_index_prefix: u32,
    ) -> Self {
        let secret: boringtun::x25519::StaticSecret =
            boringtun::x25519::StaticSecret::from(local_secret.to_bytes());
        let peer: boringtun::x25519::PublicKey =
            boringtun::x25519::PublicKey::from(*peer_public.as_bytes());
        let psk_bytes: Option<[u8; 32]> = preshared_key.map(|psk| *psk.as_bytes());
        let tunn = Tunn::new(secret, peer, psk_bytes, None, session_index_prefix, None);
        Self {
            socket,
            inner: Mutex::new(tunn),
            peer_addr,
        }
    }

    /// Remote peer's UDP address.
    #[must_use]
    pub const fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Borrow the underlying UDP socket.
    ///
    /// Exposed for the STUN client (F-TRANS.4) and the relay-fallback
    /// path (F-TRANS.6), both of which need to share the same socket
    /// with the tunnel.
    #[must_use]
    pub const fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    /// Encapsulate one plaintext IP frame in `plain` into a
    /// `WireGuard` UDP payload written to `out`.
    ///
    /// Returns the number of bytes written to `out`. `out` must be
    /// at least `plain.len() + 32` bytes and at least 148 bytes —
    /// see [`boringtun::noise::Tunn::encapsulate`].
    ///
    /// If no session is established yet, `boringtun` queues `plain`
    /// internally and writes a handshake-initiation packet to `out`
    /// instead; the caller MUST still send those bytes — they are
    /// the first message of the WG handshake.
    ///
    /// # Errors
    ///
    /// Returns [`WgTunnelError::BufferTooSmall`] if `out` is below the
    /// minimum size and [`WgTunnelError::WireGuard`] for any error
    /// surfaced by `boringtun`.
    pub fn encapsulate(&self, plain: &[u8], out: &mut [u8]) -> Result<usize, WgTunnelError> {
        let needed = core::cmp::max(plain.len().saturating_add(32), 148);
        if out.len() < needed {
            return Err(WgTunnelError::BufferTooSmall { have: out.len(), need: needed });
        }
        let mut guard = self.inner.lock();
        match guard.encapsulate(plain, out) {
            TunnResult::WriteToNetwork(slice) => Ok(slice.len()),
            TunnResult::Done => Ok(0),
            TunnResult::Err(err) => Err(WgTunnelError::WireGuard(err)),
            TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => {
                // encapsulate is the IP-frame -> UDP direction; boringtun
                // does not surface tunnel writes from this path.
                Ok(0)
            },
        }
    }

    /// Decapsulate one `WireGuard` UDP payload in `encrypted` into a
    /// plaintext IP frame written to `out`.
    ///
    /// Returns `Some(n)` with the number of plaintext bytes written
    /// to `out` (a real inner IP frame), or [`None`] when `boringtun`
    /// completed handshake / cookie work without producing a tunnel
    /// frame (the caller may still need to send a network response —
    /// see the lower-level pump methods which handle that automatically).
    ///
    /// `out` must be at least `encrypted.len()` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`WgTunnelError::BufferTooSmall`] if `out` is smaller
    /// than `encrypted`, and [`WgTunnelError::WireGuard`] for any
    /// `boringtun` error.
    pub fn decapsulate(
        &self,
        encrypted: &[u8],
        out: &mut [u8],
    ) -> Result<Option<usize>, WgTunnelError> {
        if out.len() < encrypted.len() {
            return Err(WgTunnelError::BufferTooSmall {
                have: out.len(),
                need: encrypted.len(),
            });
        }
        let mut guard = self.inner.lock();
        match guard.decapsulate(Some(self.peer_addr.ip()), encrypted, out) {
            TunnResult::WriteToTunnelV4(slice, _) | TunnResult::WriteToTunnelV6(slice, _) => {
                Ok(Some(slice.len()))
            },
            TunnResult::Done | TunnResult::WriteToNetwork(_) => Ok(None),
            TunnResult::Err(err) => Err(WgTunnelError::WireGuard(err)),
        }
    }

    /// Read one UDP datagram off the socket, feed it to `boringtun`,
    /// and on a [`TunnResult::WriteToNetwork`] result send the
    /// response back. If `boringtun` produced a plaintext IP frame,
    /// return it; otherwise return [`None`].
    ///
    /// **Source-address binding:** the MVP rejects any datagram whose
    /// source `SocketAddr` does not exactly match [`Self::peer_addr`]
    /// — the datagram is dropped, no `boringtun` work happens, and the
    /// call returns `Ok(None)`. WireGuard-style authenticated endpoint
    /// roaming (where the kernel rebinds the peer's address after a
    /// successful AEAD authentication) is deliberately deferred to a
    /// follow-up task. Until that lands, downstream callers MUST
    /// rebuild the tunnel on a peer-address change (e.g. after a
    /// fresh STUN discovery from F-TRANS.4).
    ///
    /// Drains queued packets via the documented re-call loop
    /// (`boringtun` requires calling `decapsulate` again with an empty
    /// datagram to flush queued handshake bytes).
    ///
    /// # Errors
    ///
    /// Returns [`WgTunnelError::Io`] for socket failures and
    /// [`WgTunnelError::WireGuard`] for boringtun-surfaced errors.
    pub async fn pump_socket_to_peer(&self) -> Result<Option<Bytes>, WgTunnelError> {
        let mut recv_buf = [0_u8; WG_MAX_DATAGRAM];
        let (recv_len, src) = self.socket.recv_from(&mut recv_buf).await?;
        if src != self.peer_addr {
            tracing::debug!(
                expected = %self.peer_addr,
                got = %src,
                "wg_tunnel: dropping udp datagram from unexpected source",
            );
            return Ok(None);
        }
        let outcome = self.decap_and_collect_network(&recv_buf[..recv_len])?;
        for network_chunk in outcome.network_writes {
            self.socket.send_to(&network_chunk, self.peer_addr).await?;
        }
        Ok(outcome.tunnel_frame)
    }

    /// Take a plaintext IP frame, encapsulate it via `boringtun`, and
    /// send the resulting `WireGuard` UDP datagram out the socket.
    ///
    /// On a [`TunnResult::Done`] result (no session yet — boringtun
    /// queued the frame for the next handshake), no UDP send happens
    /// and the call returns `Ok(0)`. On a normal encap, returns the
    /// number of bytes sent to the network.
    ///
    /// # Errors
    ///
    /// Returns [`WgTunnelError::Io`] for socket failures and
    /// [`WgTunnelError::WireGuard`] for boringtun-surfaced errors.
    pub async fn pump_peer_to_socket(&self, plain: &[u8]) -> Result<usize, WgTunnelError> {
        // boringtun requires the encap destination to be at least
        // plain.len() + 32 bytes and at least 148 bytes. We size the
        // owned buffer up to that floor (allowing for boringtun's WG
        // overhead) rather than capping at WG_MAX_DATAGRAM — the latter
        // is the receive-side ceiling, not the encapsulate-side bound.
        let needed = core::cmp::max(plain.len().saturating_add(32), 148);
        let mut send_buf = vec![0_u8; needed];
        let bytes_written = self.encapsulate(plain, &mut send_buf)?;
        if bytes_written == 0 {
            return Ok(0);
        }
        let sent = self.socket.send_to(&send_buf[..bytes_written], self.peer_addr).await?;
        Ok(sent)
    }

    /// Inner: feed `incoming` to `boringtun::decapsulate` and collect
    /// all network-bound chunks plus an optional inner-tunnel frame.
    ///
    /// Separated from [`Self::pump_socket_to_peer`] so the mutex guard
    /// is fully scoped to a synchronous block and does NOT cross any
    /// `.await`. The returned values are fully owned `Vec<u8>` /
    /// `Bytes`, so the caller can release the lock before doing socket
    /// I/O.
    ///
    /// Allocation: one [`WG_MAX_DATAGRAM`]-sized buffer is held on the
    /// stack of this fn and reused across every drain-loop iteration.
    /// `classify_step` copies the bytes it needs to keep into either
    /// `outcome.network_writes` or `outcome.tunnel_frame` BEFORE the
    /// next call overwrites them, so the shared buffer is safe to
    /// reuse.
    fn decap_and_collect_network(&self, incoming: &[u8]) -> Result<DecapOutcome, WgTunnelError> {
        let mut work_buf = [0_u8; WG_MAX_DATAGRAM];
        let mut outcome = DecapOutcome::default();
        let mut guard = self.inner.lock();
        let first = guard.decapsulate(Some(self.peer_addr.ip()), incoming, &mut work_buf);
        Self::classify_step(first, &mut outcome)?;
        // boringtun's decapsulate emits queued-packet WG datagrams
        // and any pending handshake bytes only when re-driven with
        // an empty slice (this is how boringtun signals "give me a
        // chance to push the deferred queue"). The drain helper
        // re-drives decapsulate until it returns `Done`. The work
        // buffer is reused across iterations; classify_step copies
        // the bytes it keeps into owned `Vec` / `Bytes` fields
        // BEFORE the next decapsulate call overwrites the buffer.
        Self::drain_pending(&mut guard, &mut work_buf, &mut outcome)?;
        drop(guard);
        Ok(outcome)
    }

    /// Inner: keep calling `boringtun::decapsulate` with an empty
    /// datagram until it stops producing tunnel or network bytes.
    /// boringtun signals "no more queued work" by returning `Done`
    /// (or `Err`, which we surface to the caller).
    fn drain_pending(
        guard: &mut Tunn,
        work_buf: &mut [u8],
        outcome: &mut DecapOutcome,
    ) -> Result<(), WgTunnelError> {
        loop {
            let step = guard.decapsulate(None, &[], work_buf);
            let keep_draining = matches!(
                step,
                TunnResult::WriteToNetwork(_)
                    | TunnResult::WriteToTunnelV4(_, _)
                    | TunnResult::WriteToTunnelV6(_, _),
            );
            Self::classify_step(step, outcome)?;
            if !keep_draining {
                return Ok(());
            }
        }
    }

    /// Inner: convert one `TunnResult` step into either a queued
    /// network-bound chunk, a captured tunnel frame, an error, or a
    /// no-op.
    fn classify_step(
        step: TunnResult<'_>,
        outcome: &mut DecapOutcome,
    ) -> Result<(), WgTunnelError> {
        match step {
            TunnResult::Done => Ok(()),
            TunnResult::WriteToNetwork(slice) => {
                outcome.network_writes.push(slice.to_vec());
                Ok(())
            },
            TunnResult::WriteToTunnelV4(slice, _) | TunnResult::WriteToTunnelV6(slice, _) => {
                outcome.tunnel_frame = Some(Bytes::copy_from_slice(slice));
                Ok(())
            },
            TunnResult::Err(err) => Err(WgTunnelError::WireGuard(err)),
        }
    }
}

/// Outcome of one `boringtun::decapsulate` round, plus drain loop.
///
/// `network_writes` are the UDP datagrams to send back to the peer
/// (handshake-response, cookie reply, queued data). `tunnel_frame`,
/// if `Some`, is the plaintext IP frame surfaced upward by the
/// `WriteToTunnelV4` / `WriteToTunnelV6` variants.
#[derive(Debug, Default)]
struct DecapOutcome {
    network_writes: Vec<Vec<u8>>,
    tunnel_frame: Option<Bytes>,
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use tokio::net::UdpSocket;

    use bibeam_crypto::WgSecretKey;

    use super::*;

    fn loopback_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    /// Build a minimal byte sequence that boringtun's
    /// `WriteToTunnelV4` path accepts as plaintext: a 20-byte IPv4
    /// header followed by an 8-byte UDP header and `payload`.
    ///
    /// boringtun inspects the IP version nibble plus the
    /// `Total Length` field; it does NOT validate header / UDP
    /// checksums (those are the kernel's job once the packet leaves
    /// the tunnel). Tests therefore leave both checksum fields zero
    /// and rely on boringtun's permissive parse path.
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
        packet.extend_from_slice(&[0, 0]); // header checksum (left zero; boringtun does not check)
        packet.extend_from_slice(&src_ip);
        packet.extend_from_slice(&dst_ip);
        // UDP header
        packet.extend_from_slice(&1234_u16.to_be_bytes()); // src port
        packet.extend_from_slice(&5678_u16.to_be_bytes()); // dst port
        packet.extend_from_slice(&udp_len.to_be_bytes());
        packet.extend_from_slice(&[0, 0]); // UDP checksum (left zero)
        packet.extend_from_slice(payload);
        packet
    }

    async fn build_tunnel(peer_addr: SocketAddr) -> WgTunnel {
        let socket = UdpSocket::bind(loopback_addr()).await.expect("bind udp");
        let local_secret = WgSecretKey::generate();
        let peer_secret = WgSecretKey::generate();
        let peer_public = peer_secret.public();
        WgTunnel::new(&local_secret, &peer_public, None, peer_addr, socket)
    }

    #[tokio::test]
    async fn encapsulate_buffer_too_small_is_reported() {
        let tunnel = build_tunnel(loopback_addr()).await;
        let mut tiny_out = [0_u8; 16];
        let outcome = tunnel.encapsulate(b"hello", &mut tiny_out);
        assert!(matches!(outcome, Err(WgTunnelError::BufferTooSmall { .. })));
    }

    #[tokio::test]
    async fn decapsulate_buffer_too_small_is_reported() {
        let tunnel = build_tunnel(loopback_addr()).await;
        let scratch = [0_u8; 64];
        let mut tiny_out = [0_u8; 8];
        let outcome = tunnel.decapsulate(&scratch, &mut tiny_out);
        assert!(matches!(outcome, Err(WgTunnelError::BufferTooSmall { .. })));
    }

    #[tokio::test]
    async fn handshake_init_emerges_from_first_encapsulate() {
        // boringtun has no session at construction time; the first
        // call to encapsulate must emit a handshake-init UDP datagram
        // (148 bytes), per the boringtun API contract documented on
        // Tunn::encapsulate.
        let tunnel = build_tunnel(loopback_addr()).await;
        let mut out_buf = [0_u8; WG_MAX_DATAGRAM];
        let bytes_written = tunnel
            .encapsulate(&[1, 2, 3, 4], &mut out_buf)
            .expect("first encap must succeed");
        assert!(
            bytes_written >= 148,
            "first encap output was {bytes_written} bytes, expected handshake-init >= 148",
        );
    }

    #[tokio::test]
    async fn peer_addr_round_trips_through_constructor() {
        let target: SocketAddr = "127.0.0.1:51820".parse().expect("parse fixture");
        let tunnel = build_tunnel(target).await;
        assert_eq!(tunnel.peer_addr(), target);
    }

    #[tokio::test]
    async fn two_tunnels_complete_a_round_trip() {
        // Local <-> Peer over loopback UDP. We drive boringtun by hand
        // (no socket reads) — each side feeds the other's wire bytes
        // back through pump_peer_to_socket / decapsulate until a
        // plaintext IP frame surfaces on the listener side.
        let alice_socket = UdpSocket::bind(loopback_addr()).await.expect("bind alice");
        let bob_socket = UdpSocket::bind(loopback_addr()).await.expect("bind bob");
        let alice_addr = alice_socket.local_addr().expect("local addr alice");
        let bob_addr = bob_socket.local_addr().expect("local addr bob");

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

        // Alice's first encap emits the handshake-init. Send it via
        // pump_peer_to_socket so Bob actually receives it on his
        // socket. The plaintext must be a parseable IPv4 (or IPv6)
        // datagram: boringtun's WriteToTunnelV4 path inspects the
        // version nibble and total-length field, and surfaces
        // `WireGuardError::InvalidPacket` if the bytes don't look
        // like an IP packet. Tests therefore always feed a built
        // IPv4 frame.
        let placeholder = make_ipv4_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], b"hi");
        let init_len = alice
            .pump_peer_to_socket(&placeholder)
            .await
            .expect("alice -> bob handshake init send");
        assert!(init_len >= 148, "handshake init was {init_len} bytes");

        // Bob reads the init, decaps, sends the handshake-response.
        let bob_plain_after_init =
            bob.pump_socket_to_peer().await.expect("bob processes alice's init");
        assert!(
            bob_plain_after_init.is_none(),
            "no plaintext should surface from a handshake-init alone",
        );

        // Alice reads the response, completes the handshake. After
        // that, the drain loop in decap_and_collect_network re-drives
        // decapsulate with empty input — boringtun's
        // `send_queued_packet` then surfaces the queued plaintext as
        // an outbound WG datagram. boringtun also emits a 32-byte
        // keepalive when the handshake completes, so two distinct UDP
        // datagrams land on Bob's socket (keepalive first, queued
        // payload second).
        let alice_plain_after_response =
            alice.pump_socket_to_peer().await.expect("alice processes bob's response");
        assert!(
            alice_plain_after_response.is_none(),
            "no plaintext should surface from a handshake-response alone",
        );

        // Bob's first post-handshake recv is the keepalive (no
        // plaintext payload). The second is the queued IPv4 packet.
        let bob_keepalive = bob.pump_socket_to_peer().await.expect("bob recvs keepalive");
        assert!(bob_keepalive.is_none(), "keepalive should not surface as tunnel data");
        let bob_recv_queued =
            bob.pump_socket_to_peer().await.expect("bob recvs queued placeholder");
        let placeholder_bytes = bob_recv_queued.expect("queued placeholder must surface");
        assert_eq!(placeholder_bytes.as_ref(), placeholder.as_slice());

        // Now alice sends a fresh real frame; Bob decaps it.
        let payload = make_ipv4_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], b"second-message");
        let send_len = alice.pump_peer_to_socket(&payload).await.expect("alice sends data");
        assert!(send_len > payload.len(), "expected WG overhead");

        let bob_recv = bob.pump_socket_to_peer().await.expect("bob recvs data");
        let bytes = bob_recv.expect("plaintext frame must surface");
        assert_eq!(bytes.as_ref(), payload.as_slice());
    }
}
