#![forbid(unsafe_code)]
//! Exit-mode packet egress (F-NODE.4 — per D-3 + D-1).
//!
//! The exit `bibeam-node` terminates the client↔exit `WireGuard` session
//! (the data plane lives in [`bibeam_transport::wg_tunnel`]) and forwards
//! the resulting plaintext IP packets onto the public Internet. This
//! module is the seam between "decrypted IP bytes off the WG tunnel" and
//! "bytes leaving the host". It owns no crypto state — the AEAD has
//! already been peeled by `boringtun` upstream — and it owns no
//! kernel-NAT configuration (operator runbook concern; see below).
//!
//! ## D-3: L3 forwarding mechanism
//!
//! Per [`docs/architecture.md`](../../../docs/architecture.md) *Operational
//! decisions — Exit-mode L3 forwarding*, the picked posture at MVP is
//! **OS-level NAT** (Linux `nftables` / `iptables MASQUERADE`, macOS `pf`,
//! Windows ICS) configured by the operator out-of-band. Userspace
//! `smoltcp` is dismissed at MVP and revisited as a Phase-3 enhancement
//! once operator-isolation pressure is real.
//!
//! With OS-NAT picked, the exit's L3 code path collapses to one step:
//! after [`bibeam_tun::parse`] validates that the slice is a well-formed
//! IPv4 or IPv6 packet, the bytes are written to a [`bibeam_tun::TunDevice`]
//! (via a module-private `TunPacketSink` trait so tests can substitute
//! a recording mock). The host kernel sees the packet on the TUN
//! interface, runs the operator-configured NAT rule, and emits it onto
//! the upstream interface. No `setsockopt`, no raw sockets, no
//! `iptables` mutation happens inside this process — those are operator
//! responsibilities documented in `docs/operator-runbook.md`.
//!
//! ## L4 fallback: SOCKS5
//!
//! Some operator environments cannot stand up a TUN device — CI runners
//! without `CAP_NET_ADMIN`, container deployments with restricted
//! capabilities, rootless setups. In those, the exit falls back to an
//! L4 SOCKS5 server (bound on `listener_addr`, typically `0.0.0.0:1080`
//! reachable only over the WG tunnel) and lets the kernel's outbound
//! socket layer handle the egress without any NAT-table mutation. The
//! actual SOCKS5 state machine is the one already used by
//! [`bibeam_transport::socks5::run_socks5_listener`] (F-TRANS.7); this
//! module simply dispatches into it for L4 mode.
//!
//! Note on the L4 channel contract: the `decrypted_packets` channel is
//! *received* but unused in L4 mode. In an L4 deployment the client side
//! does not send IP frames over the WG tunnel — it speaks SOCKS5 to the
//! exit's listener directly. The argument is kept on the run loop so
//! the caller wiring is identical for both modes (one call site, mode
//! picked by config). The L4 branch closes the receiver immediately
//! before awaiting the SOCKS5 listener — this causes any upstream
//! `Sender::send` to return `Err` rather than blocking on a bounded
//! channel that will never drain, which preserves backpressure
//! liveness if a misconfigured caller still wires WG packets to an
//! L4-mode exit.
//!
//! ## D-1: ECH plumbing — NOT this module's concern
//!
//! Per [`docs/architecture.md`](../../../docs/architecture.md) *SNI-confidentiality
//! layers*, user-app ECH is end-to-end (browser ↔ destination) and
//! BiBeam-transparent. The exit only sees plaintext IP packets after WG
//! decryption — it never terminates the user-app TLS, so it cannot inject
//! ECH and would not want to (a TLS-terminating exit is explicitly
//! rejected by `docs/threat-model.md`). The control-plane ECH (CLI / node
//! → coordinator HTTPS) is wired in [`bibeam_transport::tls`] (F-TRANS.2)
//! and consumed at session bootstrap, not at packet egress.
//!
//! ## What this module does
//!
//! 1. Construct an [`ExitMode`] (L3 or L4) from operator config.
//! 2. Pump decrypted IP packets off a `tokio::sync::mpsc::Receiver` —
//!    populated by the WG-session handler in
//!    [`bibeam_transport::wg_tunnel`] (F-TRANS.1).
//! 3. For L3: parse each packet (drop malformed) and write to the TUN sink.
//! 4. For L4: ignore the packet channel and run the SOCKS5 listener until
//!    cancellation.
//!
//! ## What this module does NOT do
//!
//! - Decrypt WG packets — that is `boringtun` inside `bibeam-transport`.
//! - Configure kernel NAT tables — operator runbook concern.
//! - Terminate user-app TLS — explicitly forbidden by threat-model.
//! - Implement the SOCKS5 state machine — reuses `bibeam-transport`'s.
//! - Track per-flow state — `bibeam-tun::flow` owns flow tracking.

use std::net::SocketAddr;

use async_trait::async_trait;
use bibeam_tun::{ParseError, TunDevice, TunError, parse};
use thiserror::Error;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Failure modes for the exit-mode packet-egress loop.
///
/// L3 write errors propagate as [`ExitModeError::Sink`]; L4 listener
/// errors propagate as [`ExitModeError::Socks5`]. Parse failures on an
/// individual packet do NOT terminate the loop — they are logged and
/// counted as drops (per the "one bad packet must not stop egress"
/// invariant) and therefore have no variant on this enum.
#[derive(Debug, Error)]
pub enum ExitModeError {
    /// L3 sink (TUN device) write failed in a non-recoverable way.
    #[error("exit-mode: tun sink write failed: {0}")]
    Sink(#[source] TunError),
    /// L4 SOCKS5 listener failed to bind or fatally errored.
    #[error("exit-mode: socks5 listener failed: {0}")]
    Socks5(#[source] bibeam_transport::Socks5Error),
}

impl From<ExitModeError> for bibeam_core::Error {
    fn from(err: ExitModeError) -> Self {
        // Both variants of `ExitModeError` are I/O-class failures on the
        // exit data path: a TUN write failure or a SOCKS5 listener
        // failure. `bibeam_core::Error::Transport` is the closest class
        // — the exit is one half of a transport session.
        Self::Transport(err.to_string())
    }
}

/// Module-private trait abstracting the "write one IP packet" operation.
///
/// Exists so tests can substitute a recording mock (see
/// [`tests::RecordingSink`]) for the real [`TunDevice`] without
/// opening a public surface on `bibeam-tun`. Async-trait is used here
/// because we need `dyn TunPacketSink` storage inside the
/// [`ExitMode::L3`] variant — AFIT without `dyn` would force generics
/// to leak into the public enum's type parameters. The trait stays
/// `pub(crate)` so the public [`L3Sink`] newtype below can carry a
/// `Box<dyn TunPacketSink>` without `private_interfaces` firing.
#[async_trait]
pub(crate) trait TunPacketSink: Send {
    /// Write one IP packet to the underlying sink.
    async fn write_packet(&mut self, buf: &[u8]) -> Result<(), TunError>;
}

#[async_trait]
impl TunPacketSink for TunDevice {
    async fn write_packet(&mut self, buf: &[u8]) -> Result<(), TunError> {
        // Disambiguate against this trait's same-named method: call
        // [`TunDevice::write_packet`] via UFCS so the inherent method
        // is selected unambiguously and we do not recurse into the
        // trait impl. Discard the byte count — `bibeam-tun`'s
        // contract is that a well-behaved driver writes the whole
        // packet; the L3 forwarding path has no use for partial-write
        // recovery: an IP packet is either delivered intact or dropped.
        let _ = Self::write_packet(self, buf).await?;
        Ok(())
    }
}

/// Opaque wrapper carrying the L3-mode packet sink across the
/// public [`ExitMode::L3`] surface.
///
/// The inner trait object is module-private — callers cannot
/// construct one directly. The two entry points are
/// [`ExitMode::l3`] (production: from a [`TunDevice`]) and the
/// test-only constructor inside this module's tests.
pub struct L3Sink {
    inner: Box<dyn TunPacketSink>,
}

impl core::fmt::Debug for L3Sink {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The boxed trait object has no `Debug` bound; render opaque.
        formatter.write_str("L3Sink(<opaque>)")
    }
}

/// Selected exit-mode posture.
///
/// Construct one of the two variants from operator config, then call
/// [`ExitMode::run`] to drive the egress loop. The variant is picked
/// once at startup and is not switched at runtime — a posture change
/// requires a daemon restart.
pub enum ExitMode {
    /// L3 path: decrypted IP packets are written to a kernel TUN device,
    /// which the operator-configured NAT layer forwards to the upstream
    /// interface (per D-3). The boxed sink is generic-erased to keep the
    /// enum's type signature free of parameters.
    L3 {
        /// Sink receiving validated IP packets. Production wiring stores
        /// a [`TunDevice`]; tests substitute a recording mock. The inner
        /// trait object is module-private — see [`L3Sink`].
        sink: L3Sink,
    },
    /// L4 fallback: ignore decrypted IP packets and run a SOCKS5 server
    /// bound to `listener_addr` for clients that cannot install a TUN
    /// device. Per the module-level rustdoc, the `decrypted_packets`
    /// channel is held but unused in this mode.
    L4Socks5 {
        /// `SocketAddr` the SOCKS5 listener binds. Typical operator
        /// values: `127.0.0.1:1080` for a co-located client, or a
        /// WG-tunnel-internal address (e.g. `10.x.y.1:1080`) reachable
        /// only over the cohort's WG session.
        listener_addr: SocketAddr,
    },
}

impl core::fmt::Debug for ExitMode {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The sink is `dyn`-typed — it has no `Debug` bound, so we
        // render the L3 variant as opaque the way `TunDevice` itself
        // renders. L4 has only the addr, which is straightforward.
        match self {
            Self::L3 { .. } => {
                formatter.debug_struct("ExitMode::L3").field("sink", &"<opaque>").finish()
            },
            Self::L4Socks5 { listener_addr } => formatter
                .debug_struct("ExitMode::L4Socks5")
                .field("listener_addr", listener_addr)
                .finish(),
        }
    }
}

impl ExitMode {
    /// Build an L3 mode from a TUN device.
    ///
    /// Wraps the device in the module-private sink trait. Production
    /// wiring (in `main.rs`) calls this once at startup after
    /// [`TunDevice::new`] succeeds.
    #[must_use]
    pub fn l3(device: TunDevice) -> Self {
        Self::L3 {
            sink: L3Sink { inner: Box::new(device) },
        }
    }

    /// Build an L4 SOCKS5 mode bound to `listener_addr`.
    ///
    /// Used as the fallback when TUN device creation fails (no
    /// privilege, CI environment, restricted container).
    #[must_use]
    pub const fn l4_socks5(listener_addr: SocketAddr) -> Self {
        Self::L4Socks5 { listener_addr }
    }

    /// Drive the egress loop until `cancel` fires or a fatal error
    /// surfaces.
    ///
    /// `decrypted_packets` is the channel populated by the upstream
    /// WG-session handler; each `Vec<u8>` is one already-decrypted IP
    /// packet (IPv4 or IPv6). L3 mode consumes packets and writes them
    /// to the TUN sink; L4 mode drops them and runs the SOCKS5 listener.
    ///
    /// # Errors
    ///
    /// Returns [`ExitModeError::Sink`] if the TUN sink fails a write in
    /// L3 mode, or [`ExitModeError::Socks5`] if the SOCKS5 listener
    /// fails to bind. Per-packet parse errors are logged + dropped, not
    /// raised.
    pub async fn run(
        self,
        decrypted_packets: mpsc::Receiver<Vec<u8>>,
        cancel: CancellationToken,
    ) -> Result<(), ExitModeError> {
        match self {
            Self::L3 { sink } => run_l3(sink, decrypted_packets, cancel).await,
            Self::L4Socks5 { listener_addr } => {
                // Close the receiver up-front so any upstream
                // `Sender::send` fails fast rather than blocking on a
                // bounded channel we will never drain. See the
                // module-level rustdoc for the rationale.
                drop(decrypted_packets);
                run_l4_socks5(listener_addr, cancel).await
            },
        }
    }
}

/// L3 run loop: drain the channel, parse + write each packet, exit on
/// cancel or channel close.
///
/// Per-packet errors (parse failure or sink write failure) are routed
/// through [`handle_l3_packet`] so the loop body stays under the
/// cognitive-complexity ceiling. A sink write failure terminates the
/// loop (it's a non-recoverable I/O failure on the egress device); a
/// parse failure does not (one malformed packet from a misbehaving
/// peer should not abort egress for the whole cohort).
async fn run_l3(
    sink: L3Sink,
    mut packets: mpsc::Receiver<Vec<u8>>,
    cancel: CancellationToken,
) -> Result<(), ExitModeError> {
    let mut inner = sink.inner;
    loop {
        tokio::select! {
            () = cancel.cancelled() => return Ok(()),
            pkt = packets.recv() => match pkt {
                Some(buf) => handle_l3_packet(inner.as_mut(), &buf).await?,
                None => return Ok(()),
            }
        }
    }
}

/// Validate one decrypted IP packet and write it to the L3 sink.
///
/// Validation is delegated to [`bibeam_tun::parse`], which dispatches
/// between IPv4 and IPv6 internally and rejects malformed slices. A
/// parse failure is counted as a drop (logged + ignored); a sink-write
/// failure is escalated to the loop body via [`ExitModeError::Sink`].
async fn handle_l3_packet(sink: &mut dyn TunPacketSink, buf: &[u8]) -> Result<(), ExitModeError> {
    match parse(buf) {
        Ok(parsed) => {
            tracing::trace!(
                target: "bibeam_node::exit_mode",
                src = %parsed.src,
                dst = %parsed.dst,
                proto = parsed.proto,
                bytes = buf.len(),
                "exit-mode L3: writing decrypted IP packet to TUN sink",
            );
            sink.write_packet(buf).await.map_err(ExitModeError::Sink)
        },
        Err(err) => {
            drop_invalid_packet(&err, buf.len());
            Ok(())
        },
    }
}

/// Log + drop one malformed packet.
///
/// Separated from [`handle_l3_packet`] so the drop branch is named at
/// the call site and the cognitive-complexity score stays low. The
/// tracing target matches the rest of the module so operators can
/// filter on `bibeam_node::exit_mode=warn` to see drops without the
/// happy-path trace noise.
fn drop_invalid_packet(err: &ParseError, bytes: usize) {
    tracing::warn!(
        target: "bibeam_node::exit_mode",
        error = %err,
        bytes,
        "exit-mode L3: dropped malformed IP packet (parse failed)",
    );
}

/// L4 run loop: ignore the packet channel, delegate to the SOCKS5
/// listener already provided by [`bibeam_transport::socks5`].
///
/// The packet channel is not even bound — the L4 deployment posture is
/// that clients speak SOCKS5 directly over the WG tunnel rather than
/// pushing IP frames. Keeping the channel argument on
/// [`ExitMode::run`] (and dropping it here) avoids a mode-dependent
/// call-site signature, which would force every caller to branch on
/// mode before dispatching.
async fn run_l4_socks5(
    listener_addr: SocketAddr,
    cancel: CancellationToken,
) -> Result<(), ExitModeError> {
    tracing::info!(
        target: "bibeam_node::exit_mode",
        %listener_addr,
        "exit-mode L4: starting SOCKS5 listener (packet channel ignored)",
    );
    bibeam_transport::socks5::run_socks5_listener(listener_addr, cancel)
        .await
        .map_err(ExitModeError::Socks5)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::Duration;

    use fast_socks5::client::{Config as ClientConfig, Socks5Stream};
    use parking_lot::Mutex;
    use tokio::net::TcpListener;
    use tokio::time::timeout;

    use super::*;

    /// Recording mock: records the byte-for-byte buffers passed to
    /// [`TunPacketSink::write_packet`] so the L3 byte-identity test can
    /// compare against the channel input.
    #[derive(Debug, Default, Clone)]
    struct RecordingSink {
        written: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    /// Accept one connection on `echo`, then park holding it until
    /// `cancel` fires. Used by the L4 SOCKS5 handshake test so the echo
    /// destination stays alive across the SOCKS5 reply window. Lifted to
    /// a free fn to keep the test body under the cognitive-complexity
    /// and excessive-nesting clippy ceilings.
    async fn echo_accept_once(echo: TcpListener, cancel: CancellationToken) {
        tokio::select! {
            accepted = echo.accept() => {
                if let Ok((stream, _peer)) = accepted {
                    cancel.cancelled().await;
                    drop(stream);
                }
                // On accept failure, fall through — the task ends here
                // rather than re-arming the select (one-shot semantics).
            },
            () = cancel.cancelled() => {},
        }
    }

    #[async_trait]
    impl TunPacketSink for RecordingSink {
        async fn write_packet(&mut self, buf: &[u8]) -> Result<(), TunError> {
            self.written.lock().push(buf.to_vec());
            Ok(())
        }
    }

    /// One valid IPv4 packet (TCP/80 → 1.2.3.4) — small enough to fit
    /// in any reasonable TUN buffer, well-formed enough for
    /// [`bibeam_tun::parse`] to accept.
    ///
    /// Layout: 20-byte IPv4 header + 20-byte TCP header. Source
    /// `10.0.0.1`, dest `1.2.3.4`. The IPv4 total-length field is
    /// 40; the IPv4 header checksum is hand-computed; the TCP-side
    /// has no checksum (parsing only requires the header layout to be
    /// valid).
    fn ipv4_tcp_packet() -> Vec<u8> {
        let mut pkt = Vec::with_capacity(40);
        // IPv4 header — version=4, IHL=5, no TOS, total_len=40, id=0,
        // flags=0, frag_off=0, TTL=64, proto=6 (TCP), checksum=0 (we
        // fix below), src=10.0.0.1, dst=1.2.3.4.
        pkt.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x28, // ver/ihl, tos, total_len
            0x00, 0x00, 0x00, 0x00, // id, flags, frag_off
            0x40, 0x06, 0x00, 0x00, // ttl, proto=tcp, checksum=0
            10, 0, 0, 1, // src
            1, 2, 3, 4, // dst
        ]);
        // IPv4 checksum — sum the 16-bit words of the 20-byte header
        // with checksum=0, fold the carries, and one's-complement.
        let cksum_bytes = ipv4_checksum(&pkt[..20]).to_be_bytes();
        pkt[10] = cksum_bytes[0];
        pkt[11] = cksum_bytes[1];
        // TCP header — src_port=12345, dst_port=80, seq=0, ack=0,
        // data_offset=5 (20 bytes), flags=SYN, window=65535,
        // checksum=0, urgent=0.
        pkt.extend_from_slice(&[
            0x30, 0x39, 0x00, 0x50, // src_port, dst_port
            0x00, 0x00, 0x00, 0x00, // seq
            0x00, 0x00, 0x00, 0x00, // ack
            0x50, 0x02, 0xff, 0xff, // data_off/flags, window
            0x00, 0x00, 0x00, 0x00, // checksum, urgent
        ]);
        pkt
    }

    /// One's-complement IPv4 header checksum over a 20-byte slice.
    /// Same algorithm RFC 791 / RFC 1071 prescribe — used only inside
    /// the test fixture builder so the synthesized packet survives the
    /// `etherparse` validator on real platforms.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "the carry-fold loop above leaves `sum` in the 0..=0xffff range, so \
                  truncating to u16 is exact, not lossy. Using `try_from + expect` \
                  here would replace a proven cast with a panic path the workspace \
                  lint policy disallows in non-test code."
    )]
    fn ipv4_checksum(header: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut idx = 0;
        while idx + 1 < header.len() {
            let word = (u32::from(header[idx]) << 8) | u32::from(header[idx + 1]);
            sum = sum.wrapping_add(word);
            idx += 2;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff).wrapping_add(sum >> 16);
        }
        !(sum as u16)
    }

    /// L3 byte-identity contract — every byte the WG channel hands the
    /// exit must arrive at the TUN sink intact, in order.
    ///
    /// Bug-injection: if the L3 path mutated the buffer (e.g., stripping
    /// the IP header before `write_packet`), the assertion fails.
    #[tokio::test]
    async fn l3_writes_decrypted_packet_to_tun_byte_identical() {
        let sink = RecordingSink::default();
        let sink_handle = sink.clone();
        let mode = ExitMode::L3 {
            sink: L3Sink { inner: Box::new(sink) },
        };

        let (tx, rx) = mpsc::channel::<Vec<u8>>(8);
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        let pkt = ipv4_tcp_packet();
        let pkt_clone = pkt.clone();

        let run_handle = tokio::spawn(async move { mode.run(rx, cancel_clone).await });

        tx.send(pkt.clone()).await.expect("send packet through channel");
        // Drain time before cancel — let the run loop consume the packet.
        tokio::time::sleep(Duration::from_millis(50)).await;
        cancel.cancel();
        let outcome = timeout(Duration::from_millis(500), run_handle)
            .await
            .expect("run loop must exit before timeout");
        let outcome = outcome.expect("join handle must not panic");
        assert!(outcome.is_ok(), "L3 run must shut down cleanly: {outcome:?}");

        let recorded = sink_handle.written.lock().clone();
        assert_eq!(recorded.len(), 1, "exactly one packet must reach the sink");
        assert_eq!(recorded[0], pkt_clone, "L3 must write the packet byte-for-byte");
    }

    /// Parse-failure → drop contract.
    ///
    /// A buffer that is not a valid IPv4 or IPv6 packet (here: a single
    /// `0xff` byte, which fails the version-bit probe inside
    /// `etherparse`) must be silently dropped without aborting the
    /// loop and without writing anything to the sink.
    #[tokio::test]
    async fn exit_mode_drops_invalid_ip_packet() {
        let sink = RecordingSink::default();
        let sink_handle = sink.clone();
        let mode = ExitMode::L3 {
            sink: L3Sink { inner: Box::new(sink) },
        };

        let (tx, rx) = mpsc::channel::<Vec<u8>>(8);
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        let bogus = vec![0xff_u8]; // not a valid IP packet
        let valid = ipv4_tcp_packet();

        let run_handle = tokio::spawn(async move { mode.run(rx, cancel_clone).await });

        tx.send(bogus).await.expect("send bogus");
        tx.send(valid.clone()).await.expect("send valid");
        tokio::time::sleep(Duration::from_millis(50)).await;
        cancel.cancel();
        let outcome = timeout(Duration::from_millis(500), run_handle)
            .await
            .expect("run loop must exit before timeout");
        let outcome = outcome.expect("join handle must not panic");
        assert!(outcome.is_ok(), "run loop must NOT abort on parse failure: {outcome:?}");

        // The bogus packet must NOT have been written; the valid one MUST.
        let recorded = sink_handle.written.lock().clone();
        assert_eq!(recorded.len(), 1, "only the valid packet reaches the sink");
        assert_eq!(recorded[0], valid, "the valid packet survives byte-identical");
    }

    /// L4 SOCKS5 mode: the negotiation handshake must succeed against
    /// the listener that [`run_l4_socks5`] stands up.
    ///
    /// We bind a sacrificial TCP echo on `127.0.0.1:0`, ask the SOCKS5
    /// client to CONNECT through the exit's listener to that echo, and
    /// require the client handshake to succeed. Bytes-through-the-tunnel
    /// is out of scope (covered by `bibeam-transport::socks5`'s own
    /// suite); this test only smoke-tests that the exit-mode dispatcher
    /// brings the listener up.
    #[tokio::test]
    async fn l4_socks5_connect_handshake() {
        // 1. Sacrificial echo destination — accepts one TCP connect and
        //    shuts down.
        let echo = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let echo_cancel = CancellationToken::new();
        let echo_cancel_clone = echo_cancel.clone();
        let echo_task = tokio::spawn(echo_accept_once(echo, echo_cancel_clone));

        // 2. Exit-mode SOCKS5 listener on a kernel-assigned port.
        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("listener bind");
        let listener_addr = listener.local_addr().expect("listener addr");
        drop(listener); // free the port for the SOCKS5 listener to take

        let mode = ExitMode::l4_socks5(listener_addr);
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let (_tx, rx) = mpsc::channel::<Vec<u8>>(8);
        let run_handle = tokio::spawn(async move { mode.run(rx, cancel_clone).await });

        // 3. Give the listener a moment to bind, then drive a SOCKS5 CONNECT.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let stream = timeout(
            Duration::from_secs(2),
            Socks5Stream::connect(
                listener_addr,
                echo_addr.ip().to_string(),
                echo_addr.port(),
                ClientConfig::default(),
            ),
        )
        .await
        .expect("socks5 handshake must complete before timeout");
        assert!(stream.is_ok(), "socks5 negotiation must succeed: {stream:?}");

        // 4. Tear down — cancel both the SOCKS5 listener and the echo
        //    holder; join both so neither task lingers.
        cancel.cancel();
        echo_cancel.cancel();
        let outcome = timeout(Duration::from_millis(500), run_handle)
            .await
            .expect("L4 run must exit before timeout");
        let outcome = outcome.expect("L4 join handle must not panic");
        assert!(outcome.is_ok(), "L4 clean shutdown must return Ok: {outcome:?}");
        let echo_outcome = timeout(Duration::from_millis(500), echo_task)
            .await
            .expect("echo task must exit before timeout");
        assert!(echo_outcome.is_ok(), "echo task must exit cleanly: {echo_outcome:?}");
    }
}
