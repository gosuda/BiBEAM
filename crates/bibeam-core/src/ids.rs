#![forbid(unsafe_code)]
//! ULID newtypes for the `BiBEAM` identity space.
//!
//! Four distinct wrappers — [`PeerId`], [`NodeId`], [`CohortId`], [`ChainId`]
//! — sit over [`ulid::Ulid`] so the type system can distinguish a peer from a
//! node from a cohort from a multi-hop forwarder chain, even though they all
//! share the same wire encoding (a 128-bit Crockford-Base32 ULID).

use core::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use ulid::Ulid;

macro_rules! ulid_newtype {
    (
        $(#[$doc:meta])*
        $name:ident
    ) => {
        $(#[$doc])*
        #[derive(
            Clone,
            Copy,
            Debug,
            PartialEq,
            Eq,
            Hash,
            PartialOrd,
            Ord,
            Serialize,
            Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(pub Ulid);

        impl $name {
            /// Generate a fresh identifier using the system clock plus
            /// [`ulid::Ulid::new`]'s default RNG.
            #[must_use]
            #[allow(
                clippy::new_without_default,
                reason = "Default::default() returns Ulid::nil() — a zero ULID — \
                          which is observably different from a freshly generated ULID; \
                          we deliberately do not derive Default to avoid that surprise."
            )]
            pub fn new() -> Self {
                Self(Ulid::new())
            }

            /// Borrow the underlying [`Ulid`].
            #[must_use]
            pub const fn as_ulid(&self) -> &Ulid {
                &self.0
            }

            /// Consume the newtype and return the underlying [`Ulid`].
            #[must_use]
            pub const fn into_ulid(self) -> Ulid {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl FromStr for $name {
            type Err = ulid::DecodeError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ulid::from_string(s).map(Self)
            }
        }
    };
}

ulid_newtype! {
    /// Identifier for a single remote peer in the `BiBEAM` mesh.
    PeerId
}

ulid_newtype! {
    /// Identifier for a local node (this process's view of itself).
    NodeId
}

ulid_newtype! {
    /// Identifier for a cohort — a logical grouping of peers that share a
    /// trust or routing scope.
    CohortId
}

ulid_newtype! {
    /// Identifier for a multi-hop forwarder chain.
    ///
    /// Coordinator-issued opaque handle that every forwarder along a
    /// `MatchResponse::MultiHopAssignment` chain uses to look up the
    /// row in its lease table that authorises a given packet flow.
    /// Lives independently of [`CohortId`] because one cohort can have
    /// many concurrent multi-hop assignments, and one chain may serve
    /// peers from different cohorts at different times.
    ChainId
}
