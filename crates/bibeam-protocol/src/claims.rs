#![forbid(unsafe_code)]
//! Backward-compatible [`SessionClaims`] re-export.
//!
//! The canonical claim set lives in `bibeam-core` so the protocol
//! crate and crypto issuer/verifier both depend only on the core
//! domain shape. This module preserves the historical
//! `bibeam_protocol::claims::SessionClaims` import path for callers.

pub use bibeam_core::claims::SessionClaims;
