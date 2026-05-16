#![forbid(unsafe_code)]
//! Long-term Ed25519 identity keypair plus PKCS#8 PEM persistence
//! (F-CRYPTO.3).
//!
//! Distinct from F-CRYPTO.1's X25519 `WireGuard`-peer keys. Ed25519
//! is the **long-term identity** algorithm: the coordinator side
//! holds an [`IdentitySecretKey`] and signs invite codes; the client
//! side holds the matching [`IdentityPublicKey`] and verifies them.
//!
//! Persistence uses PKCS#8 v2 PEM via the `pkcs8` and `pem` features
//! of `ed25519-dalek`. PEM is the right interop choice: `openssl
//! pkey`, `step-cli`, every cloud KMS export tool, and the `ssh-keygen
//! -m PKCS8` family all speak this form. DER is available via
//! `to_pkcs8_der` / `from_pkcs8_der` if a caller wants the binary
//! form but is not exposed on this wrapper today.

use ed25519_dalek::pkcs8::{
    DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey,
    spki::der::pem::LineEnding,
};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey, ed25519::signature::Signer};
use thiserror::Error;
use zeroize::Zeroizing;

/// Long-term Ed25519 signing key.
///
/// Used by the coordinator side to sign invite codes and the matching
/// session metadata. The wrapped [`SigningKey`] already implements
/// `ZeroizeOnDrop`, so dropping this value scrubs the underlying
/// scalar bytes.
pub struct IdentitySecretKey(SigningKey);

impl core::fmt::Debug for IdentitySecretKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("IdentitySecretKey").finish_non_exhaustive()
    }
}

impl IdentitySecretKey {
    /// Generate a fresh Ed25519 identity keypair using the OS-seeded
    /// thread RNG.
    ///
    /// 32 raw bytes are drawn from `rand::random` (cryptographic
    /// thread-local RNG seeded from the OS on first use) and passed
    /// to [`SigningKey::from_bytes`]. We avoid threading a
    /// `RngCore` impl through `ed25519-dalek` directly because the
    /// `rand_core` ecosystem currently spans two major versions and a
    /// once-off 32-byte draw is simpler than picking a bridge.
    #[must_use]
    pub fn generate() -> Self {
        // Wrap the seed in `Zeroizing` so the stack buffer is
        // scrubbed when this function returns; without this the raw
        // 32-byte seed would linger in the frame until overwritten.
        let bytes: Zeroizing<[u8; 32]> = Zeroizing::new(rand::random());
        Self(SigningKey::from_bytes(&bytes))
    }

    /// Derive the matching [`IdentityPublicKey`].
    #[must_use]
    pub fn public(&self) -> IdentityPublicKey {
        IdentityPublicKey(self.0.verifying_key())
    }

    /// Sign `message` with this identity key.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.0.sign(message)
    }

    /// Serialise this secret key as PKCS#8 v2 PEM.
    ///
    /// Output begins with `-----BEGIN PRIVATE KEY-----`. The
    /// underlying `ed25519-dalek` API returns a `Zeroizing<String>`;
    /// this wrapper consumes that envelope and surfaces a plain
    /// `String`, so callers should zeroise their copy themselves if
    /// they keep it on disk or in memory past the immediate write.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityKeyError::Pkcs8`] on the (vanishingly
    /// unlikely) case where DER/PEM encoding fails.
    pub fn to_pem(&self) -> Result<String, IdentityKeyError> {
        let pem = self.0.to_pkcs8_pem(LineEnding::LF).map_err(IdentityKeyError::pkcs8)?;
        Ok(pem.to_string())
    }

    /// Decode a PKCS#8 v2 PEM-encoded secret key.
    ///
    /// Accepts `-----BEGIN PRIVATE KEY-----` blocks as produced by
    /// [`Self::to_pem`], `openssl pkey -outform PEM`, or any other
    /// PKCS#8 PEM source.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityKeyError::Pkcs8`] if the input is not
    /// well-formed PKCS#8 PEM or does not encode an Ed25519 key.
    pub fn from_pem(pem: &str) -> Result<Self, IdentityKeyError> {
        let key = SigningKey::from_pkcs8_pem(pem).map_err(IdentityKeyError::pkcs8)?;
        Ok(Self(key))
    }
}

/// Long-term Ed25519 verification key.
///
/// The client-side counterpart to [`IdentitySecretKey`]. Used to
/// verify invite codes and session metadata signed by the coordinator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityPublicKey(VerifyingKey);

impl IdentityPublicKey {
    /// Verify `signature` over `message`.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityKeyError::BadSignature`] if the signature is
    /// not valid for this key and message.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), IdentityKeyError> {
        use ed25519_dalek::ed25519::signature::Verifier;
        self.0.verify(message, signature).map_err(|_| IdentityKeyError::BadSignature)
    }

    /// Serialise this public key as SPKI PEM
    /// (`-----BEGIN PUBLIC KEY-----`).
    ///
    /// # Errors
    ///
    /// Returns [`IdentityKeyError::Pkcs8`] on the (vanishingly
    /// unlikely) case where DER/PEM encoding fails.
    pub fn to_pem(&self) -> Result<String, IdentityKeyError> {
        self.0.to_public_key_pem(LineEnding::LF).map_err(IdentityKeyError::pkcs8)
    }

    /// Decode a SPKI PEM-encoded public key.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityKeyError::Pkcs8`] if the input is not
    /// well-formed SPKI PEM or does not encode an Ed25519 key.
    pub fn from_pem(pem: &str) -> Result<Self, IdentityKeyError> {
        let key = VerifyingKey::from_public_key_pem(pem).map_err(IdentityKeyError::pkcs8)?;
        Ok(Self(key))
    }

    /// Borrow the raw 32 public-key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

/// Errors raised by [`IdentitySecretKey`] / [`IdentityPublicKey`].
#[derive(Debug, Error)]
pub enum IdentityKeyError {
    /// PEM / PKCS#8 encode or decode failed.
    #[error("PKCS#8 PEM encode/decode failed: {0}")]
    Pkcs8(String),
    /// Signature verification failed.
    #[error("Ed25519 signature did not verify")]
    BadSignature,
}

impl IdentityKeyError {
    fn pkcs8<E: core::fmt::Display>(err: E) -> Self {
        Self::Pkcs8(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_round_trip() {
        let sk = IdentitySecretKey::generate();
        let pk = sk.public();
        let msg = b"identity-bound payload";
        let sig = sk.sign(msg);
        pk.verify(msg, &sig).expect("verify must pass");
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let sk = IdentitySecretKey::generate();
        let pk = sk.public();
        let sig = sk.sign(b"original");
        let err = pk.verify(b"tampered", &sig).expect_err("must reject");
        assert!(matches!(err, IdentityKeyError::BadSignature));
    }

    #[test]
    fn secret_pem_round_trip() {
        let sk = IdentitySecretKey::generate();
        let pem = sk.to_pem().expect("encode");
        assert!(pem.contains("-----BEGIN PRIVATE KEY-----"));
        let parsed = IdentitySecretKey::from_pem(&pem).expect("decode");
        // Signing with each should produce verifying with the
        // re-derived public key for the same payload.
        let msg = b"pem-round-trip";
        let sig = parsed.sign(msg);
        sk.public().verify(msg, &sig).expect("public key must match");
    }

    #[test]
    fn public_pem_round_trip() {
        let sk = IdentitySecretKey::generate();
        let pk = sk.public();
        let pem = pk.to_pem().expect("encode");
        assert!(pem.contains("-----BEGIN PUBLIC KEY-----"));
        let parsed = IdentityPublicKey::from_pem(&pem).expect("decode");
        assert_eq!(pk, parsed, "public key bytes must round-trip");
    }

    #[test]
    fn rejects_malformed_pem() {
        let err = IdentitySecretKey::from_pem("not a real pem").expect_err("must error");
        assert!(matches!(err, IdentityKeyError::Pkcs8(_)));
    }

    #[test]
    fn debug_redacts_secret_material() {
        let sk = IdentitySecretKey::generate();
        let dbg = format!("{sk:?}");
        assert!(!dbg.chars().any(|byte| byte.is_ascii_digit()), "{dbg}");
    }
}
