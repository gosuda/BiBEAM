#![forbid(unsafe_code)]
//! F-CRYPTO.7 audit: the secret-bearing newtypes that
//! [F-CRYPTO.1, F-CRYPTO.3, F-CRYPTO.6] introduce all implement
//! [`zeroize::ZeroizeOnDrop`] at the type level today.
//!
//! This is a static, enumerated check — one assertion per current
//! secret type. The list is not generated; future contributors who
//! add a new secret newtype to this crate are expected to add it
//! here too, but nothing in this test forces them to. We accept that
//! limitation rather than reach for a derive macro: in safe Rust,
//! the only stronger guarantee is a build-time registry, and the
//! review cost of one explicit assertion per secret type is lower
//! than the cost of a custom proc-macro.
//!
//! What this test does guarantee: if a workspace upgrade
//! (`x25519-dalek` flipping a feature flag, an `ed25519-dalek`
//! version bump, a refactor that swaps a newtype's inner type for
//! something less zeroizing) breaks the trait projection for any of
//! the enumerated types below, this file stops compiling.
//!
//! `forbid(unsafe_code)` rules out pointer-poking after-drop checks,
//! so the trait-level proof on the current type set is the strongest
//! available compile-time guarantee.

use bibeam_crypto::{
    IdentitySecretKey, InviteCode, MasterInviteKey, SessionPsk, WgPsk, WgSecretKey,
};

const fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

#[test]
fn wg_secret_key_zeroizes_on_drop() {
    assert_zeroize_on_drop::<WgSecretKey>();
}

#[test]
fn identity_secret_key_zeroizes_on_drop() {
    assert_zeroize_on_drop::<IdentitySecretKey>();
}

#[test]
fn session_psk_zeroizes_on_drop() {
    assert_zeroize_on_drop::<SessionPsk>();
}

#[test]
fn wg_psk_zeroizes_on_drop() {
    assert_zeroize_on_drop::<WgPsk>();
}

#[test]
fn master_invite_key_zeroizes_on_drop() {
    assert_zeroize_on_drop::<MasterInviteKey>();
}

#[test]
fn invite_code_zeroizes_on_drop() {
    assert_zeroize_on_drop::<InviteCode>();
}
