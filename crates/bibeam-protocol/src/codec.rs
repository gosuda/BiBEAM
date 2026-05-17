#![forbid(unsafe_code)]
//! Postcard codec for [`Frame`].
//!
//! On the wire every `BiBeam` message is laid out as:
//!
//! ```text
//! MAGIC (4 bytes) || VERSION (1 byte) || postcard-serialised Frame
//! ```
//!
//! [`encode`] produces that exact byte layout. [`decode`] validates both
//! [`MAGIC`] and [`VERSION`] before invoking the postcard deserializer
//! and surfaces the two bad-prefix cases as first-class
//! [`ProtocolError::BadMagic`] and [`ProtocolError::BadVersion`]
//! variants, so callers do not need to string-sniff a generic codec
//! error to find the root cause.

use bytes::Bytes;
use postcard::Error as PostcardError;

use crate::error::ProtocolError;
use crate::frame::{Frame, MAGIC, VERSION};

/// Size of the fixed envelope prefix written ahead of every postcard
/// payload: four magic bytes followed by one version byte.
const PREFIX_LEN: usize = MAGIC.len() + 1;

/// Encode `frame` into the canonical `BiBeam` wire layout.
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
/// Returns [`ProtocolError::BadMagic`] if the first four bytes are not
/// [`MAGIC`], [`ProtocolError::BadVersion`] if the version byte does
/// not equal [`VERSION`], and [`ProtocolError::Codec`] for any
/// underlying postcard failure (including a buffer shorter than the
/// prefix, which postcard surfaces as `DeserializeUnexpectedEnd`).
pub fn decode(buf: &[u8]) -> Result<Frame, ProtocolError> {
    if buf.len() < PREFIX_LEN {
        return Err(ProtocolError::Codec(PostcardError::DeserializeUnexpectedEnd));
    }
    if buf[..MAGIC.len()] != MAGIC {
        return Err(ProtocolError::BadMagic);
    }
    let version = buf[MAGIC.len()];
    if version != VERSION {
        return Err(ProtocolError::BadVersion {
            got: version,
            expected: VERSION,
        });
    }
    let frame = postcard::from_bytes(&buf[PREFIX_LEN..])?;
    Ok(frame)
}
