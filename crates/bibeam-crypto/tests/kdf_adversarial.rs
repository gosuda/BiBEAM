#![forbid(unsafe_code)]
#![allow(
    clippy::expect_used,
    reason = "integration-test setup uses `.expect(...)` on well-known constants; clippy.toml \
              already permits expect in tests"
)]
//! Known-vector pin for [`bibeam_crypto::derive_wg_psk`].
//!
//! The inline `#[cfg(test)]` module in `kdf.rs` already covers
//! determinism, divergence by rotation counter, and divergence by
//! source PRK. What it does NOT cover is a *bit-exact* expected
//! output: a silent change to the HKDF info encoding (e.g. switching
//! `to_le_bytes` to `to_be_bytes`, or bumping the `WG_PSK_LABEL`
//! constant) would still satisfy the determinism property because
//! both endpoints compute the same wrong value.
//!
//! This test pins one (PRK, counter) → output triple. Any deviation
//! in the HKDF chain (algorithm, label, counter encoding) breaks it
//! loud — which is the point: the WG PSK is shared across two
//! independent implementations (issuer and verifier), and an
//! undetected schedule change desynchronises the fleet.

use bibeam_crypto::{SessionPsk, WG_KEY_LEN, derive_wg_psk};

/// Pinned input: PRK is 32 repeated `0x42` bytes; rotation counter
/// is 7. The expected output was captured from the very first
/// passing run of this test against the workspace's HKDF-SHA256
/// implementation, with `info = "bibeam/wg-psk/v1" ||
/// 7u64.to_le_bytes()` per `derive_wg_psk` rustdoc.
///
/// If this vector ever needs to change (algorithm upgrade, label
/// version bump), update *both* the expected bytes and the schedule
/// version (`WG_PSK_LABEL` ends in `.v1` today). Do NOT silently
/// flip the bytes — that would mask a real desync.
#[test]
fn derive_wg_psk_pins_a_known_vector() {
    // Captured by running this test once against the workspace's
    // HKDF-SHA256 implementation at the schedule version
    // `WG_PSK_LABEL = "bibeam/wg-psk/v1"` with `info = label ||
    // 7u64.to_le_bytes()`. Independently reproducible: HKDF-Expand
    // over PRK = 32 × 0x42, info = "bibeam/wg-psk/v1" || [7,0,0,0,
    // 0,0,0,0], L = 32, hash = SHA-256.
    const EXPECTED: [u8; WG_KEY_LEN] = [
        0xef, 0x10, 0x04, 0x9f, 0x33, 0x5c, 0xb5, 0xc4, 0xaf, 0x52, 0xa1, 0x00, 0x24, 0x7e, 0x75,
        0x48, 0xe0, 0x92, 0xec, 0x3e, 0xe9, 0xa4, 0x18, 0xd9, 0x98, 0xbe, 0xe4, 0xdd, 0x52, 0x80,
        0xdb, 0xf7,
    ];

    let prk = SessionPsk::new([0x42; WG_KEY_LEN]);
    let rotation_counter = 7_u64;
    let actual = derive_wg_psk(&prk, rotation_counter).expect("derive");

    assert_eq!(
        actual.as_bytes(),
        &EXPECTED,
        "derive_wg_psk output drifted from the pinned vector — \
         update both EXPECTED and the schedule version label if intentional",
    );
}
