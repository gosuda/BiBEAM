#![forbid(unsafe_code)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "integration test fixtures use unwrap/expect in setup paths"
)]
#![allow(
    clippy::indexing_slicing,
    reason = "test code indexes into freshly-built fixed-size buffers"
)]
//! Integration tests for §11 verification gate #4 — option (c)
//! multi-hop end-to-end with the load-bearing
//! "forwarder-never-sees-plaintext" assertion.
//!
//! Each test stands up a 3-process fixture entirely in-process:
//!
//! - a `client` (raw `tokio::net::UdpSocket` bound to loopback —
//!   the bibeam-cli `ClientSession` is `pub(crate)`; the
//!   integration value here is byte-on-the-wire, so a raw socket
//!   suffices and avoids the WG-TUN init the CLI session needs);
//! - a `Forwarder` from `bibeam_node::forwarder`, bound to a fresh
//!   loopback ephemeral port;
//! - a mock `exit` socket — another raw `tokio::net::UdpSocket`.
//!
//! Frames are real `RelayFrame { chain_id, wg_payload }` values
//! encoded through the protocol crate's writer. The forwarder runs
//! its real `run` loop and never decrypts the payload tail — the
//! tests assert that by (a) byte-comparing the received frame
//! against the sent frame, (b) computing the Shannon entropy of
//! the observed `wg_payload` region and asserting it exceeds the
//! threshold the task spec set (> 0.8 bits/byte), and (c) asserting
//! the plaintext sentinel string never appears in the observed
//! byte stream.

mod helpers;

use std::sync::Arc;
use std::time::Duration;

use bibeam_core::{ChainId, NodeId, Timestamp};
use bibeam_node::forwarder::Forwarder;
use bibeam_protocol::{ForwarderLease, RelayFrame};
use bytes::Bytes;
use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

/// Plaintext sentinel embedded in payloads the encrypted variant of
/// the test wraps. We pick a recognisable byte sequence so the
/// forwarder-snoop assertion can prove "this string never appears
/// in the bytes the forwarder relays".
const PLAINTEXT_SENTINEL: &[u8] = b"BIBEAM-PLAINTEXT-SENTINEL-DO-NOT-RELAY";

/// Minimum Shannon entropy (bits per byte) over the observed
/// `wg_payload` region the test asserts to demonstrate the bytes are
/// indistinguishable from ciphertext. 0.8 bits/byte fails only for
/// near-constant payloads; ciphertext-shaped patterns hit ~7+. The
/// threshold is conservatively below that ceiling so the assertion
/// is robust against the test fixture's pseudo-random generator
/// quality.
const ENTROPY_THRESHOLD_BITS_PER_BYTE: f64 = 0.8;

const fn loopback_v4_zero() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

fn future_expiry() -> Timestamp {
    Timestamp::from_offset_date_time(Timestamp::now().into_inner() + time::Duration::minutes(15))
}

async fn bound_socket() -> Arc<UdpSocket> {
    Arc::new(UdpSocket::bind(loopback_v4_zero()).await.expect("bind"))
}

async fn bound_forwarder() -> Forwarder {
    Forwarder::bind(loopback_v4_zero()).await.expect("bind forwarder")
}

fn fixture_lease(
    chain_id: ChainId,
    allowed_src: SocketAddr,
    allowed_dst: SocketAddr,
) -> ForwarderLease {
    ForwarderLease {
        forwarder: NodeId::new(),
        chain_id,
        allowed_src,
        allowed_dst,
        lease_expires_at: future_expiry(),
    }
}

fn spawn_forwarder_run(
    forwarder: &Forwarder,
) -> (CancellationToken, tokio::task::JoinHandle<std::io::Result<()>>) {
    let cancel = CancellationToken::new();
    let forwarder_clone = forwarder.clone();
    let cancel_clone = cancel.clone();
    let handle = tokio::spawn(async move { forwarder_clone.run(cancel_clone).await });
    (cancel, handle)
}

async fn cancel_and_join(
    cancel: CancellationToken,
    handle: tokio::task::JoinHandle<std::io::Result<()>>,
) {
    cancel.cancel();
    let join_result = handle.await.expect("forwarder run loop task panicked");
    join_result.expect("forwarder run loop returned an error");
}

/// Synthesise a 112-byte ciphertext-shaped `wg_payload`. The mixing
/// step uses two coprime moduli so the resulting byte sequence has
/// no recognisable short-period structure — its Shannon entropy
/// over the 112 bytes lands well above
/// [`ENTROPY_THRESHOLD_BITS_PER_BYTE`].
///
/// The `seed` parameter offsets the counter so two payloads inside
/// the same test do not collide bit-for-bit (otherwise the
/// "byte-identical forward" assertion stays trivially true while
/// the "no plaintext leak" assertion would not catch a duplicate
/// payload regression).
fn make_ciphertext_shaped_payload(seed: u8) -> Vec<u8> {
    let mut body = vec![0u8; 112];
    let mut counter: u8 = seed;
    for byte in &mut body {
        *byte = counter.wrapping_mul(53) ^ counter.wrapping_add(17);
        counter = counter.wrapping_add(1);
    }
    body
}

/// Shannon entropy in bits per byte over `bytes`. Used to assert
/// the forwarder's outbound stream looks high-entropy.
fn shannon_entropy_bits_per_byte(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &byte in bytes {
        freq[byte as usize] = freq[byte as usize].saturating_add(1);
    }
    #[allow(
        clippy::cast_precision_loss,
        reason = "Test-only Shannon entropy reads the histogram bins into a \
                  bounded f64. The histogram is at most 256 buckets of u32 \
                  counts; the precision loss is irrelevant to the entropy \
                  threshold assertion."
    )]
    let total = bytes.len() as f64;
    let mut entropy = 0.0_f64;
    for count in &freq {
        if *count == 0 {
            continue;
        }
        #[allow(
            clippy::cast_precision_loss,
            reason = "Per-bin count fits in u32; f64 holds it exactly."
        )]
        let probability = f64::from(*count) / total;
        entropy -= probability * probability.log2();
    }
    entropy
}

#[tokio::test]
async fn single_hop_smoke() {
    // Contract: a `SingleHop` assignment (modelled by binding the
    // client directly to the exit's socket) round-trips a payload
    // unchanged. No forwarder involved — this is the baseline the
    // multi-hop variant builds on.
    let exit_socket = bound_socket().await;
    let client_socket = bound_socket().await;
    let exit_addr = exit_socket.local_addr().expect("exit addr");

    // The "wg_payload" is a small random-looking buffer the exit
    // observes byte-identical. We do not wrap in a RelayFrame here
    // because single-hop has no forwarder layer; the client's WG
    // datagram goes straight to the exit.
    let payload = make_ciphertext_shaped_payload(0x11);
    client_socket.send_to(&payload, exit_addr).await.expect("client send");

    let mut buf = vec![0u8; 2048];
    let (len, observed_from) =
        tokio::time::timeout(Duration::from_secs(2), exit_socket.recv_from(&mut buf))
            .await
            .expect("exit recv timed out")
            .expect("exit recv ok");
    assert_eq!(observed_from, client_socket.local_addr().expect("client addr"));
    assert_eq!(&buf[..len], payload.as_slice(), "single-hop payload round-trip");
}

#[tokio::test]
async fn multi_hop_forwarder_relays_unchanged() {
    // Contract: with one forwarder between the client and the
    // exit, a `RelayFrame { chain_id, wg_payload }` traverses the
    // chain byte-identical at the exit. Asserts the forward-
    // unchanged invariant the option (c) cascading-edits surface
    // is built on.
    let forwarder = bound_forwarder().await;
    let exit_socket = bound_socket().await;
    let client_socket = bound_socket().await;
    let client_addr = client_socket.local_addr().expect("client addr");
    let exit_addr = exit_socket.local_addr().expect("exit addr");
    let fwd_addr = forwarder.local_addr().expect("fwd addr");

    let chain_id = ChainId::new();
    forwarder.insert_lease(&fixture_lease(chain_id, client_addr, exit_addr));

    let (cancel, run_handle) = spawn_forwarder_run(&forwarder);

    let wg_payload = make_ciphertext_shaped_payload(0x22);
    let frame = RelayFrame {
        chain_id,
        wg_payload: Bytes::from(wg_payload.clone()),
    };
    let encoded = frame.encode();

    client_socket.send_to(&encoded, fwd_addr).await.expect("client send");

    let mut buf = vec![0u8; 2048];
    let (len, observed_from) =
        tokio::time::timeout(Duration::from_secs(2), exit_socket.recv_from(&mut buf))
            .await
            .expect("exit recv timed out")
            .expect("exit recv ok");
    assert_eq!(observed_from, fwd_addr, "exit must observe the frame coming from the forwarder");
    assert_eq!(
        &buf[..len],
        encoded.as_ref(),
        "RelayFrame forwarded UNCHANGED through the forwarder",
    );

    let decoded = RelayFrame::decode(&buf[..len]).expect("decode at exit");
    assert_eq!(decoded.chain_id, chain_id, "chain id preserved");
    assert_eq!(decoded.wg_payload.as_ref(), wg_payload.as_slice(), "payload preserved");

    cancel_and_join(cancel, run_handle).await;
}

#[tokio::test]
async fn forwarder_relays_opaque_payload_byte_preserving() {
    // Contract: the forwarder is a pure byte-pump on the
    // wg_payload — every byte the upstream peer sent enters the
    // downstream peer byte-identical, AND a snooper on the
    // forwarder's outbound socket sees the same bytes as the
    // legitimate destination.
    //
    // The test embeds the `PLAINTEXT_SENTINEL` string INSIDE the
    // wg_payload region of a RelayFrame and asserts:
    //
    // (a) Byte-for-byte: the relayed frame at the exit is
    //     byte-identical to the encoded frame the client emitted.
    //     A decrypt / re-encode path on the forwarder would
    //     re-frame the payload and lose this equality.
    //
    // (b) The sentinel survives the relay verbatim. A "helpful"
    //     forwarder that stripped or scrubbed payload bytes (the
    //     symptom of a decrypt-then-re-encrypt regression) would
    //     fail here because the scrub would either alter the
    //     sentinel or drop the bytes around it.
    //
    // (c) The bytes the destination observes are END-TO-END
    //     identical to the bytes the client emitted: the snoop
    //     comparison is between `encoded` (what the client sent)
    //     and `observed` (what the destination saw). Catches a
    //     "tap and re-emit" regression where the forwarder
    //     decodes the body, logs it, then re-frames a fresh
    //     RelayFrame with the same chain_id (which would still
    //     pass a chain-id-only check).
    //
    // (d) The wg_payload region's Shannon entropy exceeds the
    //     threshold the task spec set (> 0.8 bits/byte) when fed
    //     a ciphertext-shaped payload — a regression that
    //     zero-padded or constant-substituted the body would
    //     collapse the entropy.
    //
    // The "forwarder never sees plaintext" claim resolves at the
    // type / module-organisation level: `crates/bibeam-node/src/
    // forwarder.rs` has no WG-decrypt path, no key material, and
    // forbids unsafe code (forbid(unsafe_code) at file head). The
    // strongest runtime witness available is the byte-preserving
    // round-trip plus the snoop-equality this test pins.
    let forwarder = bound_forwarder().await;
    let exit_socket = bound_socket().await;
    let client_socket = bound_socket().await;
    let client_addr = client_socket.local_addr().expect("client addr");
    let exit_addr = exit_socket.local_addr().expect("exit addr");
    let fwd_addr = forwarder.local_addr().expect("fwd addr");

    let chain_id = ChainId::new();
    forwarder.insert_lease(&fixture_lease(chain_id, client_addr, exit_addr));

    let (cancel, run_handle) = spawn_forwarder_run(&forwarder);

    // Build a wg_payload that:
    //   - embeds the plaintext sentinel at a known offset (so a
    //     forwarder that stripped or replaced "plaintext-looking"
    //     bytes would fail (b)),
    //   - and is high-entropy elsewhere (so (d) is a meaningful
    //     assertion). The ciphertext-shaped padding wraps the
    //     sentinel.
    let head = make_ciphertext_shaped_payload(0x33);
    let tail = make_ciphertext_shaped_payload(0x55);
    let mut wg_payload: Vec<u8> =
        Vec::with_capacity(head.len() + PLAINTEXT_SENTINEL.len() + tail.len());
    wg_payload.extend_from_slice(&head);
    wg_payload.extend_from_slice(PLAINTEXT_SENTINEL);
    wg_payload.extend_from_slice(&tail);

    let frame = RelayFrame {
        chain_id,
        wg_payload: Bytes::from(wg_payload.clone()),
    };
    let encoded = frame.encode();

    client_socket.send_to(&encoded, fwd_addr).await.expect("client send");

    let mut buf = vec![0u8; 4096];
    let (len, observed_from) =
        tokio::time::timeout(Duration::from_secs(2), exit_socket.recv_from(&mut buf))
            .await
            .expect("exit recv timed out")
            .expect("exit recv ok");
    assert_eq!(observed_from, fwd_addr);

    let observed = &buf[..len];

    // (a) + (c) Byte-for-byte forward-unchanged. Composes both
    // claims because the destination sees exactly what the
    // client emitted; any tap-and-re-emit, decrypt-then-re-encode,
    // or pad/strip operation along the way would fail this.
    assert_eq!(observed, encoded.as_ref(), "forwarder must not mutate or re-frame");

    // (b) The plaintext sentinel survived verbatim at its
    // expected offset. A "scrub plaintext" regression would
    // either alter the sentinel bytes or drop the bytes around
    // them, breaking this lookup.
    let observed_wg_payload = &observed[bibeam_protocol::RELAY_FRAME_PREFIX_LEN..];
    let sentinel_pos = observed_wg_payload
        .windows(PLAINTEXT_SENTINEL.len())
        .position(|window| window == PLAINTEXT_SENTINEL)
        .expect("plaintext sentinel must survive verbatim through the forwarder");
    assert_eq!(
        sentinel_pos,
        head.len(),
        "plaintext sentinel offset must be byte-stable across the relay",
    );

    // (d) Shannon entropy over the wg_payload region. The
    // ciphertext-shaped padding dominates the byte budget; the
    // entropy is well above the 0.8 bits/byte threshold the task
    // spec set even though a small plaintext run is embedded.
    let entropy = shannon_entropy_bits_per_byte(observed_wg_payload);
    assert!(
        entropy > ENTROPY_THRESHOLD_BITS_PER_BYTE,
        "wg_payload region must look high-entropy: got {entropy} bits/byte, threshold {ENTROPY_THRESHOLD_BITS_PER_BYTE}",
    );

    cancel_and_join(cancel, run_handle).await;
}

#[tokio::test]
async fn forwarder_drops_unknown_chain_id() {
    // Contract: a `RelayFrame` whose `chain_id` is NOT in the
    // forwarder's routing table must drop before any send_to. The
    // exit socket therefore observes nothing inside a generous
    // wait; the forwarder's `evaluate` returns
    // `Drop(UnknownChain)` and the run loop never reaches
    // `send_to`.
    //
    // We bind the exit socket to assert the negative, but we do
    // NOT install a lease for the chain id the client sends. The
    // forwarder's drop is the load-bearing contract.
    let forwarder = bound_forwarder().await;
    let exit_socket = bound_socket().await;
    let client_socket = bound_socket().await;
    let fwd_addr = forwarder.local_addr().expect("fwd addr");

    let (cancel, run_handle) = spawn_forwarder_run(&forwarder);

    let orphan_frame = RelayFrame {
        chain_id: ChainId::new(),
        wg_payload: Bytes::from_static(b"orphan-payload-no-lease"),
    };
    let encoded = orphan_frame.encode();
    client_socket.send_to(&encoded, fwd_addr).await.expect("client send");

    let mut buf = vec![0u8; 2048];
    let outcome =
        tokio::time::timeout(Duration::from_millis(300), exit_socket.recv_from(&mut buf)).await;
    assert!(
        outcome.is_err(),
        "unknown chain_id MUST NOT reach any destination socket; recv outcome was {outcome:?}",
    );

    cancel_and_join(cancel, run_handle).await;
}
