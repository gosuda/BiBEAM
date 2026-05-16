#![forbid(unsafe_code)]
//! Top-level error type for the `BiBEAM` core crate.
//!
//! [`enum@Error`] groups failures by class — config / crypto / transport /
//! protocol / storage / geoip / io — so downstream callers can match on the
//! cause without needing to know the precise sub-error type. Each variant
//! carries a human-readable string except [`Error::Io`], which re-wraps
//! [`std::io::Error`] losslessly via `#[from]`.

use thiserror::Error;

/// Class-tagged error type for the core crate.
///
/// Higher layers convert their own error types into one of these classes
/// (typically `Crypto`, `Protocol`, or `Transport`) so the surface presented
/// to applications stays compact.
#[derive(Debug, Error)]
pub enum Error {
    /// Configuration could not be loaded, validated, or applied.
    #[error("config error: {0}")]
    Config(String),
    /// A cryptographic primitive or handshake failed.
    #[error("crypto error: {0}")]
    Crypto(String),
    /// A transport-layer failure (QUIC, TCP, UDP, etc.).
    #[error("transport error: {0}")]
    Transport(String),
    /// A protocol-layer violation or unexpected message.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// Persistent storage failed (read, write, schema, etc.).
    #[error("storage error: {0}")]
    Storage(String),
    /// `GeoIP` DB open / parse / lookup failed (R-REGION.2 / D-5).
    ///
    /// Surfaces failures from the operator-supplied
    /// `GeoLite2-Country` `.mmdb` file — both file-open / I/O errors
    /// and structural (`InvalidDatabase` / `Decoding`) errors fold
    /// into the same `String` form so downstream callers can match
    /// on the variant without depending on the upstream `maxminddb`
    /// crate. Per D-5, the cross-check is warn-only at MVP —
    /// callers convert this error class into an audit-log entry
    /// rather than refusing admission.
    #[error("geoip error: {0}")]
    Geoip(String),
    /// An underlying [`std::io::Error`] propagated unchanged.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
