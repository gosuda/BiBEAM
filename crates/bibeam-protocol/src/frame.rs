#![forbid(unsafe_code)]
//! Wire-frame envelope shared by every `BiBeam` transport.
//!
//! Every message on the wire begins with [`MAGIC`] (`b"BIBM"`) followed by
//! the one-byte [`VERSION`] tag. The remaining bytes are a postcard-encoded
//! [`Frame`]. Keeping the prefix outside of the postcard payload lets the
//! receiver reject mismatched protocol families before reaching for a
//! serde-aware decoder.
//!
//! The three [`Frame`] variants now each carry their concrete payload:
//!
//! - [`Frame::Control`] carries the discovery / coordinator control
//!   messages added in F-PROTO.3,
//! - [`Frame::Tunnel`] carries the WG-sealed IP datagram added in
//!   F-PROTO.4, and
//! - [`Frame::Cohort`] carries the cohort lifecycle messages added in
//!   F-PROTO.5.
//!
//! Codec helpers live in [`crate::codec`]; this module is wire-shape only.

use serde::{Deserialize, Serialize};

use crate::cohort::CohortMessage;
use crate::control::ControlMessage;
use crate::tunnel::Tunnel;

/// Four-byte magic prefix written at the start of every `BiBeam` frame.
///
/// Spelled `BIBM` so a packet capture of any `BiBeam` flow is recognisable
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
/// Each variant carries the payload introduced by its matching F-PROTO
/// sub-item: [`Frame::Control`] holds a [`ControlMessage`] (F-PROTO.3),
/// [`Frame::Tunnel`] holds a [`Tunnel`] datagram (F-PROTO.4), and
/// [`Frame::Cohort`] holds a [`CohortMessage`] (F-PROTO.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Frame {
    /// Control-plane traffic carrying one [`ControlMessage`].
    Control(ControlMessage),
    /// Data-plane traffic carrying one [`Tunnel`] datagram.
    Tunnel(Tunnel),
    /// Cohort-plane traffic carrying one [`CohortMessage`].
    Cohort(CohortMessage),
}
