#![forbid(unsafe_code)]
#![allow(
    clippy::expect_used,
    reason = "integration-test setup uses `.expect(...)` on well-known constants; clippy.toml \
              already permits expect in tests"
)]
//! Adversarial decoder tests for the wire codec.
//!
//! [`codec_roundtrip.rs`] proves `decode(encode(x)) == x` for any
//! reachable [`Frame`]. This file proves the *complementary* contract:
//! for any byte sequence that is NOT a well-formed encoding,
//! [`bibeam_protocol::decode`] surfaces an explicit
//! [`ProtocolError`] variant rather than a panic or a generic codec
//! error that callers must string-sniff.
//!
//! Every test names what it violates (`rejects_<violation>`). The
//! `proptest_decode_never_panics` case is the totality contract:
//! [`bibeam_protocol::decode`] is a total function over `&[u8]`.

use bibeam_protocol::{MAGIC, ProtocolError, VERSION, decode};
use proptest::collection::vec;
use proptest::prelude::*;

const PREFIX_LEN: usize = MAGIC.len() + 1;

/// Buffers shorter than `MAGIC || VERSION` (5 bytes) must surface as
/// [`ProtocolError::Codec`] with the postcard `DeserializeUnexpectedEnd`
/// variant — the codec routes the too-short case through postcard's
/// error rather than minting a dedicated truncation variant, so the
/// caller sees one unified short-buffer signal.
#[test]
fn rejects_truncated_buffer_below_header() {
    for len in 0..PREFIX_LEN {
        let buf = vec![0_u8; len];
        let err = decode(&buf).expect_err("short buffer must error");
        assert!(
            matches!(err, ProtocolError::Codec(_)),
            "len={len}: expected ProtocolError::Codec, got {err:?}",
        );
    }
}

/// First four bytes do not equal [`MAGIC`] — the codec rejects before
/// looking at the version byte, so the version byte is free to be
/// valid (1) and the error must still surface as
/// [`ProtocolError::BadMagic`].
#[test]
fn rejects_bad_magic_with_exact_error_variant() {
    let mut buf = [0_u8; PREFIX_LEN + 4];
    buf[..MAGIC.len()].copy_from_slice(b"XXXX");
    buf[MAGIC.len()] = VERSION;
    let err = decode(&buf).expect_err("bad magic must error");
    assert!(
        matches!(err, ProtocolError::BadMagic),
        "expected ProtocolError::BadMagic, got {err:?}",
    );
}

/// Magic is correct but the version byte is not [`VERSION`]. The
/// caller must see [`ProtocolError::BadVersion`] carrying the exact
/// `got` byte it saw on the wire, so observability can distinguish
/// "wrong protocol family" (`BadMagic`) from "newer/older deployment"
/// (`BadVersion`) without string-sniffing.
#[test]
fn rejects_future_version_byte() {
    let bad_version = VERSION.wrapping_add(1);
    let mut buf = [0_u8; PREFIX_LEN + 4];
    buf[..MAGIC.len()].copy_from_slice(&MAGIC);
    buf[MAGIC.len()] = bad_version;
    let err = decode(&buf).expect_err("bad version must error");
    match err {
        ProtocolError::BadVersion { got, expected } => {
            assert_eq!(got, bad_version, "got byte must mirror the wire value");
            assert_eq!(expected, VERSION, "expected byte must equal the constant");
        },
        other => panic!("expected ProtocolError::BadVersion, got {other:?}"),
    }
}

/// Valid magic, valid version, but no payload — postcard fails to
/// deserialise a [`Frame`] from zero bytes and the codec surfaces
/// [`ProtocolError::Codec`] (wrapping the underlying postcard
/// `DeserializeUnexpectedEnd`).
#[test]
fn rejects_valid_header_with_empty_payload() {
    let mut buf = [0_u8; PREFIX_LEN];
    buf[..MAGIC.len()].copy_from_slice(&MAGIC);
    buf[MAGIC.len()] = VERSION;
    let err = decode(&buf).expect_err("empty payload must error");
    assert!(
        matches!(err, ProtocolError::Codec(_)),
        "expected ProtocolError::Codec, got {err:?}",
    );
}

proptest! {
    /// [`decode`] is total over `&[u8]`: for any byte sequence up to
    /// 64 KiB the function returns either `Ok(_)` or `Err(_)`, never
    /// panics. The 64-KiB bound is a generous superset of any real
    /// wire frame (well above the QUIC MTU domain the protocol
    /// targets) and keeps individual proptest iterations fast.
    #[test]
    fn proptest_decode_never_panics(buf in vec(any::<u8>(), 0..65_536)) {
        // `decode` returns Result; the proptest fails if the call
        // panics (unwinding aborts the test process). Discarding the
        // value is intentional — the contract is "no panic", not "a
        // specific error". `drop(...)` is used over `let _ =` to keep
        // the workspace-wide `let-underscore-drop` lint quiet (Frame
        // carries `Bytes`, which has a destructor).
        drop(decode(&buf));
    }
}
