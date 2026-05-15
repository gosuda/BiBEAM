#![forbid(unsafe_code)]
//! Proptest roundtrip for the wire codec.
//!
//! For any [`Frame`] value reachable by the per-variant strategies in this
//! file, `decode(encode(&frame))` must return `Ok(frame)`. This is the
//! drift gate that catches any future change to a [`Frame`] variant that
//! is not also reflected in postcard's serde derives or in the codec's
//! framing rules.

use bibeam_protocol::{Frame, decode, encode};
use proptest::prelude::*;

/// Strategy yielding any of the current [`Frame`] variants.
///
/// Each new variant introduced by a later F-PROTO sub-item plugs in here
/// — extend the alternative list, not the proptest body.
fn arb_frame() -> impl Strategy<Value = Frame> {
    prop_oneof![Just(Frame::Control), Just(Frame::Tunnel), Just(Frame::Cohort),]
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
