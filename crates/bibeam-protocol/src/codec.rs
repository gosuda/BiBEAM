#![forbid(unsafe_code)]
//! Postcard codec for [`Frame`].
//!
//! On the wire every `BiBEAM` message is laid out as:
//!
//! ```text
//! MAGIC (4 bytes) || VERSION (1 byte) || postcard-serialised Frame
//! ```
//!
//! [`encode`] produces that exact byte layout. [`decode`] validates both
//! [`MAGIC`] and [`VERSION`] before invoking the postcard deserializer; a
//! mismatched prefix yields a dedicated `postcard::Error` so callers can
//! reject the buffer without speculatively running serde over potentially
//! adversarial input.
//!
//! Once F-PROTO.7 lands, [`decode`] will surface bad-magic and bad-version
//! cases through a richer `ProtocolError` enum. For now the signature
//! returns `postcard::Error` directly to keep the public surface compact
//! while later sub-items wire up the protocol-level error type.

use bytes::Bytes;
use postcard::Error as PostcardError;

use crate::frame::{Frame, MAGIC, VERSION};

/// Size of the fixed envelope prefix written ahead of every postcard
/// payload: four magic bytes followed by one version byte.
const PREFIX_LEN: usize = MAGIC.len() + 1;

/// Encode `frame` into the canonical `BiBEAM` wire layout.
///
/// The output is `MAGIC || VERSION || postcard(frame)`. The returned
/// [`Bytes`] is freshly allocated; callers may share it across tasks
/// cheaply because [`Bytes`] is reference-counted.
pub fn encode(frame: &Frame) -> Result<Bytes, PostcardError> {
    let payload = postcard::to_stdvec(frame)?;
    let mut buf = Vec::with_capacity(PREFIX_LEN + payload.len());
    buf.extend_from_slice(&MAGIC);
    buf.push(VERSION);
    buf.extend_from_slice(&payload);
    Ok(Bytes::from(buf))
}

/// Decode a wire buffer into a [`Frame`].
///
/// Returns an error if the buffer is shorter than the prefix, if the
/// first four bytes are not [`MAGIC`], or if the version byte does not
/// equal [`VERSION`]. On a structurally valid prefix the remaining bytes
/// are handed to `postcard::from_bytes` and any failure there is
/// propagated unchanged.
pub fn decode(buf: &[u8]) -> Result<Frame, PostcardError> {
    if buf.len() < PREFIX_LEN {
        return Err(PostcardError::DeserializeUnexpectedEnd);
    }
    if buf[..MAGIC.len()] != MAGIC {
        // No purpose-built bad-magic variant exists until F-PROTO.7; until
        // then a generic deserialize error is the closest match in
        // postcard::Error.
        return Err(PostcardError::DeserializeBadEncoding);
    }
    if buf[MAGIC.len()] != VERSION {
        return Err(PostcardError::DeserializeBadEncoding);
    }
    postcard::from_bytes(&buf[PREFIX_LEN..])
}
