#![forbid(unsafe_code)]
//! UTC timestamp wrapper around [`time::OffsetDateTime`].
//!
//! All `BiBeam` core types that need a "when did this happen" field hold a
//! [`Timestamp`] rather than reaching for [`time::OffsetDateTime`] directly.
//! That keeps wire/serde encoding uniform (RFC 3339) and gives us a single
//! choke point if we ever need to swap the underlying representation.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::OffsetDateTime;
use time::serde::rfc3339;

/// A UTC timestamp serialised as RFC 3339.
///
/// Wraps a [`time::OffsetDateTime`] and forces serde to round-trip through
/// the RFC 3339 string form, so every encoded `Timestamp` on the wire and on
/// disk looks the same regardless of which subsystem produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(OffsetDateTime);

impl Timestamp {
    /// Capture the current UTC time.
    #[must_use]
    pub fn now() -> Self {
        Self(OffsetDateTime::now_utc())
    }

    /// Build a [`Timestamp`] from an existing [`OffsetDateTime`].
    ///
    /// The wrapped value is preserved verbatim; no timezone conversion is
    /// applied. Callers who want UTC normalisation should convert before
    /// passing the value in.
    #[must_use]
    pub const fn from_offset_date_time(value: OffsetDateTime) -> Self {
        Self(value)
    }

    /// Consume the wrapper and return the underlying [`OffsetDateTime`].
    #[must_use]
    pub const fn into_inner(self) -> OffsetDateTime {
        self.0
    }

    /// Borrow the underlying [`OffsetDateTime`].
    #[must_use]
    pub const fn as_offset_date_time(&self) -> &OffsetDateTime {
        &self.0
    }
}

impl Serialize for Timestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        rfc3339::serialize(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        rfc3339::deserialize(deserializer).map(Self)
    }
}
