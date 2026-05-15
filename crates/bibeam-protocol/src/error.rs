#![forbid(unsafe_code)]
//! Protocol-layer error type.
//!
//! [`ProtocolError`] surfaces the two bad-prefix cases the codec checks
//! before invoking postcard ([`ProtocolError::BadMagic`] and
//! [`ProtocolError::BadVersion`]) as first-class variants, alongside
//! transparent passthroughs for the underlying `postcard::Error` and
//! [`bibeam_core::Error`].
//!
//! Lifting bad-magic / bad-version out of the generic
//! `postcard::Error::DeserializeBadEncoding` bucket lets callers (the
//! transport layer, the coordinator, observability code) match on the
//! root cause without string-sniffing.

use thiserror::Error;

/// Protocol-layer error returned by [`crate::decode`] and by callers
/// that wrap codec failures.
#[derive(Debug, Error)]
pub enum ProtocolError {
    /// Underlying postcard serialise / deserialise failure.
    #[error("postcard codec error: {0}")]
    Codec(#[from] postcard::Error),
    /// Underlying core-layer error.
    #[error("core error: {0}")]
    Core(#[from] bibeam_core::Error),
    /// First four bytes did not match the [`crate::MAGIC`] constant.
    #[error("invalid magic bytes (expected BIBM)")]
    BadMagic,
    /// Version byte did not match the [`crate::VERSION`] constant.
    #[error("unsupported wire version: got {got}, expected {expected}")]
    BadVersion {
        /// Version byte observed on the wire.
        got: u8,
        /// Version byte this implementation speaks.
        expected: u8,
    },
}
