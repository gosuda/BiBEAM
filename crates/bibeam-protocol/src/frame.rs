#![forbid(unsafe_code)]
//! Wire-frame envelope shared by every `BiBEAM` transport.
//!
//! Every message on the wire begins with [`MAGIC`] (`b"BIBM"`) followed by
//! the one-byte [`VERSION`] tag. The remaining bytes are a postcard-encoded
//! [`Frame`]. Keeping the prefix outside of the postcard payload lets the
//! receiver reject mismatched protocol families before reaching for a
//! serde-aware decoder.
//!
//! The three [`Frame`] variants stage payloads incrementally as the
//! protocol stack lands:
//!
//! - [`Frame::Control`] carries the discovery / coordinator control
//!   messages added in F-PROTO.3,
//! - [`Frame::Tunnel`] will carry the Noise-sealed IP datagram introduced
//!   in F-PROTO.4, and
//! - [`Frame::Cohort`] will carry the cohort lifecycle messages introduced
//!   in F-PROTO.5.
//!
//! Codec helpers live in [`crate::codec`]; this module is wire-shape only.

use serde::{Deserialize, Serialize};

use crate::control::ControlMessage;

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
/// Concrete payloads land in later sub-items of F-PROTO. The
/// [`Frame::Control`] variant now carries a [`ControlMessage`]
/// (F-PROTO.3); the remaining variants are still unit placeholders
/// awaiting their respective F-PROTO sub-items.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Frame {
    /// Control-plane traffic carrying one [`ControlMessage`].
    Control(ControlMessage),
    /// Data-plane tunnel datagram. Concrete payload lands in F-PROTO.4.
    Tunnel,
    /// Cohort lifecycle traffic. Concrete payload lands in F-PROTO.5.
    Cohort,
}
