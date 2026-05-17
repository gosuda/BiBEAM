#![forbid(unsafe_code)]
#![allow(
    clippy::expect_used,
    reason = "integration-test setup uses `.expect(...)` on well-known constants; clippy.toml \
              already permits expect in tests"
)]
//! Adversarial L3 packet-parser tests.
//!
//! [`dual_stack.rs`] proves the parser handles well-formed IPv4 and
//! IPv6 UDP packets. This file proves the complementary contract: for
//! any byte sequence that is NOT a well-formed IP packet,
//! [`bibeam_tun::parse`] returns an explicit [`ParseError`] variant
//! rather than panicking or unwinding through the L3 pipeline.
//!
//! The `proptest_parse_never_panics` case is the totality contract:
//! [`bibeam_tun::parse`] is a total function over `&[u8]`.

use bibeam_tun::{ParseError, parse};
use etherparse::PacketBuilder;
use proptest::collection::vec;
use proptest::prelude::*;

const PAYLOAD: &[u8] = &[0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];

/// Build a complete, well-formed IPv4 UDP packet. The caller can then
/// slice it at any length to exercise the parser's truncation paths.
fn build_v4_udp_packet() -> Vec<u8> {
    let builder = PacketBuilder::ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64).udp(1234, 5678);
    let mut buf = Vec::with_capacity(builder.size(PAYLOAD.len()));
    builder.write(&mut buf, PAYLOAD).expect("serialize v4");
    buf
}

/// Build a complete, well-formed IPv6 UDP packet.
fn build_v6_udp_packet() -> Vec<u8> {
    let src_v6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
    let dst_v6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02];
    let builder = PacketBuilder::ipv6(src_v6, dst_v6, 64).udp(4321, 8765);
    let mut buf = Vec::with_capacity(builder.size(PAYLOAD.len()));
    builder.write(&mut buf, PAYLOAD).expect("serialize v6");
    buf
}

/// An IPv4 header is at least 20 bytes (IHL = 5, no options). For
/// every truncated length between 1 (just the version nibble) and 19
/// (one byte short of a header), the parser must return an error.
/// The exact variant is [`ParseError::Slice`] — `etherparse`'s slicer
/// rejects, and `bibeam-tun` passes the rejection through via
/// `#[from]`. Length 0 is covered by [`ParseError::TooShort`] and
/// tested separately for clarity.
#[test]
fn rejects_packet_below_ipv4_header_size() {
    let full = build_v4_udp_packet();
    for len in 1..20 {
        let truncated = &full[..len];
        let err = parse(truncated).expect_err(&format!("len={len} must error"));
        assert!(
            matches!(err, ParseError::Slice(_)),
            "len={len}: expected ParseError::Slice, got {err:?}",
        );
    }
}

/// An IPv6 header is exactly 40 bytes. Truncations of an otherwise
/// valid IPv6 UDP packet between length 1 and 39 inclusive must
/// surface as [`ParseError::Slice`].
#[test]
fn rejects_packet_below_ipv6_header_size() {
    let full = build_v6_udp_packet();
    for len in 1..40 {
        let truncated = &full[..len];
        let err = parse(truncated).expect_err(&format!("len={len} must error"));
        assert!(
            matches!(err, ParseError::Slice(_)),
            "len={len}: expected ParseError::Slice, got {err:?}",
        );
    }
}

/// `etherparse::PacketHeaders::from_ip_slice` dispatches between v4
/// and v6 on the first nibble of the slice. For any nibble that is
/// neither 4 nor 6 the slicer rejects the buffer, regardless of how
/// many bytes follow. The parser must surface that rejection as
/// [`ParseError::Slice`].
#[test]
fn rejects_invalid_ip_version_nibble() {
    // Every nibble value 0..=15 except 4 (IPv4) and 6 (IPv6). The
    // filter form avoids the drift hazard of a hand-written list
    // (Codex caught the prior version omitting 15).
    for nibble in (0_u8..=15).filter(|n| !matches!(n, 4 | 6)) {
        let mut buf = vec![0_u8; 64];
        // Upper nibble is the version; lower nibble (IHL on v4) can
        // be anything for this test — the slicer never gets past the
        // version dispatch.
        buf[0] = nibble << 4;
        let err = parse(&buf).expect_err(&format!("nibble={nibble} must error"));
        assert!(
            matches!(err, ParseError::Slice(_)),
            "nibble={nibble}: expected ParseError::Slice, got {err:?}",
        );
    }
}

/// A UDP header is 8 bytes. A packet with a valid 20-byte IPv4 header
/// claiming `proto = 17` (UDP) but fewer than 8 bytes after must be
/// rejected by `etherparse`'s transport-layer slicer; the parser
/// surfaces that rejection as [`ParseError::Slice`]. Iterates over
/// every truncation between IPv4 header + 0 bytes and IPv4 header +
/// 7 bytes — every length below the minimum UDP header.
#[test]
fn rejects_truncated_udp_header_after_valid_ip() {
    let full = build_v4_udp_packet();
    // The IPv4 header occupies bytes 0..20. The UDP header occupies
    // bytes 20..28. Truncate inside the UDP header.
    for udp_len in 0..8 {
        let truncated = &full[..20 + udp_len];
        let err = parse(truncated).expect_err(&format!("udp_len={udp_len} must error"));
        assert!(
            matches!(err, ParseError::Slice(_)),
            "udp_len={udp_len}: expected ParseError::Slice, got {err:?}",
        );
    }
}

proptest! {
    /// [`parse`] is total over `&[u8]`: for any byte sequence up to
    /// 1600 bytes (well above the workspace's `DEFAULT_MTU`
    /// + tunnel overhead) the function returns either `Ok(_)` or
    /// `Err(_)`, never panics. The 1600-byte bound matches the
    /// realistic upper bound on packets seen on a TUN device.
    #[test]
    fn proptest_parse_never_panics(buf in vec(any::<u8>(), 0..1600)) {
        // The contract is "no panic"; the call's outcome is discarded.
        // `drop(...)` over `let _ =` keeps the workspace
        // `let-underscore-drop` lint quiet (`ParsedPacket` holds a
        // borrow, but the discarded `Result` itself is `Drop`).
        drop(parse(&buf));
    }
}
