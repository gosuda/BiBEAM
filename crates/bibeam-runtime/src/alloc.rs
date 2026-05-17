#![forbid(unsafe_code)]
//! Optional re-export of [`mimalloc::MiMalloc`] for the server-side binary.
//!
//! `BiBeam`'s server-side binary (`bibeam-node` — merged coord + data-plane
//! role per §11 R-1) and the client-side daemon (`bibeam-cli`) want a faster
//! global allocator than the platform default `malloc` under sustained
//! connection churn. mimalloc gives a consistent throughput uplift on the
//! kinds of small-object allocations our control plane produces (postcard
//! codecs, token materialisation, per-peer state allocations).
//!
//! Library crates MUST NOT set a `#[global_allocator]` — only binary
//! crates can, and only one per process. This module therefore re-
//! exports the allocator type behind a `mimalloc` feature flag,
//! leaving the actual `#[global_allocator]` declaration to each
//! binary so the choice is local to that binary's main.
//!
//! ## Usage in a binary
//!
//! ```ignore
//! // in `crates/bibeam-node/src/main.rs`
//! #[cfg(feature = "mimalloc")]
//! #[global_allocator]
//! static GLOBAL: bibeam_runtime::alloc::MiMalloc = bibeam_runtime::alloc::MiMalloc;
//! ```
//!
//! The binary opts in by declaring its own `mimalloc` feature that
//! activates `bibeam-runtime/mimalloc`; CI / release artefacts ship
//! with the feature on, while dev builds default off so an opt-in
//! mismatch is loud.

/// Re-export of [`mimalloc::MiMalloc`] gated on the `mimalloc`
/// feature.
///
/// Set as the binary's `#[global_allocator]`; see the module docs.
#[cfg(feature = "mimalloc")]
pub use mimalloc::MiMalloc;
