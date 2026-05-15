#![forbid(unsafe_code)]
//! Wire-frame envelope shared by every `BiBEAM` transport.
//!
//! Every message on the wire begins with [`MAGIC`] (`b"BIBM"`) followed by
//! the one-byte [`VERSION`] tag. The remaining bytes are a postcard-encoded
//! [`Frame`]. Keeping the prefix outside of the postcard payload lets the
//! receiver reject mismatched protocol families before reaching for a
//! serde-aware decoder.
//!
//! The three [`Frame`] variants are placeholders at this stage of the
//! protocol stack:
//!
//! - [`Frame::Control`] will carry the discovery / coordinator control
//!   messages introduced in F-PROTO.3,
//! - [`Frame::Tunnel`] will carry the Noise-sealed IP datagram introduced
//!   in F-PROTO.4, and
//! - [`Frame::Cohort`] will carry the cohort lifecycle messages introduced
//!   in F-PROTO.5.
//!
//! Codec helpers land alongside this module in F-PROTO.2; this module is
//! wire-shape only.

use serde::{Deserialize, Serialize};

/// Four-byte magic prefix written at the start of every `BiBEAM` frame.
///
/// Spelled `BIBM` so a packet capture of any `BiBEAM` flow is recognisable
/// without consulting a decoder. The receiver MUST reject any buffer whose
/// first four bytes do not match this constant.
pub const MAGIC: [u8; 4] = *b"BIBM";

/// Current wire-format version.
///
/// Incremented on any breaking change to the [`Frame`] layout or to the
/// codec framing rules. A receiver MUST reject any buffer whose version
/// byte does not match the version it speaks.
pub const VERSION: u8 = 1;

/// Top-level wire frame.
///
/// Concrete payloads land in later sub-items of F-PROTO; for now each
/// variant is a unit placeholder so the codec and the dispatch machinery
/// can be wired up against a stable shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Frame {
    /// Control-plane traffic. Concrete payload lands in F-PROTO.3.
    Control,
    /// Data-plane tunnel datagram. Concrete payload lands in F-PROTO.4.
    Tunnel,
    /// Cohort lifecycle traffic. Concrete payload lands in F-PROTO.5.
    Cohort,
}
