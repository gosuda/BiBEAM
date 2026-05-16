#![forbid(unsafe_code)]
//! Coordinator registration via `SignedInvite` → PASETO bootstrap
//! (F-CLI.3).
//!
//! This module ships pure helpers; the `up` subcommand wires the
//! invite-parse and stdin-prompt bits in today, and F-CLI.5 / F-CLI.6
//! light up the rest as configuration plumbing lands.
//!
//! ## Invite wire form
//!
//! [`bibeam_discovery::SignedInvite`] derives `Serialize` /
//! `Deserialize` over postcard; for a human-typeable invite we
//! base64-armour the postcard bytes (URL-safe-no-pad). Operators
//! copy a 100-200 character string into the prompt; the wire form
//! is binary-equivalent on either side.
//!
//! ## On-disk session-token state
//!
//! After [`bibeam_discovery::SessionBootstrap::bootstrap`] returns a
//! verified PASETO v4 token, the daemon must remember it across the
//! daemon's own restarts (so a coordinator can correlate
//! `/heartbeat` calls back to the registration). The token is
//! sensitive — anyone with a copy can call coordinator endpoints as
//! this peer. We therefore encrypt it at rest with
//! [`bibeam_crypto::ControlAead`]:
//!
//! - **Key.** 32 random bytes, generated on first use and persisted
//!   at `<config_dir>/state.key`. On unix the file is chmod'd
//!   `0o600` so only the owning user can read it. The key is
//!   loaded once at startup and reused for every seal / open.
//! - **Nonce.** 96-bit random, generated fresh per seal call via
//!   [`rand::random`]. Stored alongside the ciphertext in the
//!   state file (12-byte prefix). The fresh-nonce-per-seal
//!   discipline keeps rotation in F-CLI.5 safe — the rotation loop
//!   rewrites the state file with a new nonce every time.
//! - **AAD.** A fixed domain-separator string (see
//!   [`STATE_AAD_DOMAIN`]). Rotation keeps the same domain; only
//!   the nonce and ciphertext change between writes.
//!
//! Layout in `state/session.bin`:
//!
//! ```text
//! [12 bytes nonce] [ciphertext + 16-byte Poly1305 tag]
//! ```
//!
//! The state directory and key file are created on first use; both
//! [`persist_session`] and [`load_session`] are idempotent against
//! re-creation.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as INVITE_BASE64;
use bibeam_crypto::{AEAD_KEY_LEN, AEAD_NONCE_LEN, ControlAead};
use bibeam_discovery::{BootstrappedSession, PeerProfile, SessionBootstrap, SignedInvite};
use thiserror::Error;

/// AEAD AAD domain-separator bound at seal time so a state-file
/// blob cannot be replayed against a future state-file format or
/// against another sealed-blob format the same key signs.
const STATE_AAD_DOMAIN: &[u8] = b"bibeam.cli.session.v1";

/// Filename (under `<config_dir>`) of the on-disk AEAD key.
const STATE_KEY_FILENAME: &str = "state.key";

/// Sub-directory under `<config_dir>` where the encrypted session
/// blob lives.
const STATE_SUBDIR: &str = "state";

/// Filename (under `<state_subdir>`) of the encrypted session
/// token.
const SESSION_BLOB_FILENAME: &str = "session.bin";

/// Errors emitted by the register / persist helpers in this module.
#[allow(
    clippy::redundant_pub_crate,
    reason = "binary-only crate: rustc's `unreachable_pub` rejects bare `pub` on items \
              consumed only by sibling private modules; clippy disagrees. We side with \
              rustc, the load-bearing lint."
)]
#[derive(Debug, Error)]
pub(crate) enum RegisterError {
    /// The invite string did not decode as base64-URL-safe-no-pad.
    #[error("invite parse: base64 decode failed: {0}")]
    InviteBase64(String),
    /// The decoded bytes did not deserialise as a
    /// [`SignedInvite`] postcard payload.
    #[error("invite parse: postcard decode failed: {0}")]
    InvitePostcard(String),
    /// `stdin().read_line` failed (terminal not attached, EOF
    /// before any input, etc.).
    #[error("invite prompt: stdin read failed: {0}")]
    InvitePrompt(#[source] std::io::Error),
    /// The encrypted state blob was shorter than one nonce — a
    /// truncated or corrupted file.
    #[error("session state: blob too short (have {have} bytes, need at least {need})")]
    StateBlobTooShort {
        /// Bytes the blob actually carried.
        have: usize,
        /// Minimum bytes required ([`AEAD_NONCE_LEN`] + one tag).
        need: usize,
    },
    /// AEAD seal / open failed.
    #[error("session state: AEAD operation failed: {0}")]
    StateAead(String),
    /// State-file I/O failed.
    #[error("session state: I/O failed: {0}")]
    StateIo(#[source] std::io::Error),
    /// The decrypted token bytes were empty. The bootstrap path
    /// never persists an empty token, so this means the on-disk
    /// blob is corrupt or was written by a buggy build.
    #[error("session state: decrypted token is empty")]
    EmptyToken,
}

/// Parse a base64-URL-safe-no-pad invite string into a typed
/// [`SignedInvite`].
///
/// Invite codes are copy-pastable text; the base64 ASCII wrapping
/// keeps shells and terminal scrollback happy. The inner wire
/// form is `postcard`-encoded [`SignedInvite`] (matching its
/// derived `Serialize`).
///
/// # Errors
///
/// Returns [`RegisterError::InviteBase64`] for malformed armouring,
/// [`RegisterError::InvitePostcard`] for malformed inner payload.
#[allow(
    clippy::redundant_pub_crate,
    reason = "binary-only crate: see RegisterError for the rustc-vs-clippy rationale."
)]
pub(crate) fn parse_invite(armoured: &str) -> Result<SignedInvite, RegisterError> {
    let trimmed = armoured.trim();
    let bytes = INVITE_BASE64
        .decode(trimmed.as_bytes())
        .map_err(|err| RegisterError::InviteBase64(err.to_string()))?;
    postcard::from_bytes::<SignedInvite>(&bytes)
        .map_err(|err| RegisterError::InvitePostcard(err.to_string()))
}

/// Encode a [`SignedInvite`] back into its armoured wire form.
///
/// Round-trips through `parse_invite`. Used by tests and by
/// operator-side tooling (future); kept here so the encode /
/// decode pair lives in one place.
///
/// # Errors
///
/// Returns [`RegisterError::InvitePostcard`] when postcard
/// encoding fails (in practice only on out-of-memory).
#[allow(
    clippy::redundant_pub_crate,
    reason = "binary-only crate: see RegisterError for the rustc-vs-clippy rationale."
)]
#[allow(
    dead_code,
    reason = "Round-trip companion to `parse_invite`; used by tests today. F-CLI.6 \
              will surface it through the `init`-helper path that writes a sample \
              invite alongside the default config."
)]
pub(crate) fn encode_invite(invite: &SignedInvite) -> Result<String, RegisterError> {
    let bytes = postcard::to_allocvec(invite)
        .map_err(|err| RegisterError::InvitePostcard(err.to_string()))?;
    Ok(INVITE_BASE64.encode(&bytes))
}

/// Read one line from stdin and trim whitespace.
///
/// Used when the `up` subcommand was invoked without `--invite`;
/// the daemon prompts the operator interactively.
///
/// # Errors
///
/// Returns [`RegisterError::InvitePrompt`] when stdin is closed or
/// the read syscall fails.
#[allow(
    clippy::redundant_pub_crate,
    reason = "binary-only crate: see RegisterError for the rustc-vs-clippy rationale."
)]
#[allow(
    clippy::print_stdout,
    reason = "user-facing CLI output: the prompt is the only way an operator knows \
              the daemon is waiting for an invite. The tracing subscriber's JSON \
              shape is wrong for an interactive prompt."
)]
pub(crate) fn read_invite_from_stdin() -> Result<String, RegisterError> {
    use std::io::{BufRead as _, Write as _};
    print!("invite> ");
    std::io::stdout().flush().map_err(RegisterError::InvitePrompt)?;
    let stdin = std::io::stdin();
    let mut buf = String::new();
    stdin.lock().read_line(&mut buf).map_err(RegisterError::InvitePrompt)?;
    Ok(buf.trim().to_owned())
}

/// Run the [`SessionBootstrap`] flow against the coordinator pool
/// and surface the verified session.
///
/// Free fn rather than a method so F-CLI.5's rotation loop can
/// call it repeatedly with a different exit pick without rebuilding
/// the orchestrator.
///
/// # Errors
///
/// Forwards any [`bibeam_discovery::DiscoveryError`] verbatim. The
/// bootstrap is not retriable at this layer; the caller decides.
#[allow(
    clippy::redundant_pub_crate,
    reason = "binary-only crate: see RegisterError for the rustc-vs-clippy rationale."
)]
#[allow(
    dead_code,
    reason = "wired into the up flow after F-CLI.6 lands real config (CoordinatorPool \
              + PasetoVerifier come from config). Reachable through the integration \
              tests at the bottom of this file today."
)]
pub(crate) async fn run_bootstrap(
    bootstrap: &SessionBootstrap,
    invite: &SignedInvite,
    profile: PeerProfile,
    verifier: &bibeam_crypto::PasetoVerifier,
) -> Result<BootstrappedSession> {
    bootstrap
        .bootstrap(invite, profile, verifier)
        .await
        .context("coordinator bootstrap failed")
}

/// Inputs for the state-file persistence helpers.
///
/// Bundled into a struct so the path-derivation helpers in this
/// module stay testable without spelunking through a `directories`
/// project handle (tests pass a temp-dir override).
#[allow(
    clippy::redundant_pub_crate,
    reason = "binary-only crate: see RegisterError for the rustc-vs-clippy rationale."
)]
#[derive(Debug, Clone)]
pub(crate) struct StatePaths {
    /// `<config_dir>/state.key` — the 32-byte AEAD key file.
    pub(crate) key_path: PathBuf,
    /// `<config_dir>/state/session.bin` — the encrypted token blob.
    #[allow(
        dead_code,
        reason = "wired into the up flow after F-CLI.6 lands real config. Reachable \
                  through this module's integration tests today."
    )]
    pub(crate) session_blob_path: PathBuf,
}

impl StatePaths {
    /// Derive the on-disk paths under `config_dir`.
    pub(crate) fn under(config_dir: &Path) -> Self {
        Self {
            key_path: config_dir.join(STATE_KEY_FILENAME),
            session_blob_path: config_dir.join(STATE_SUBDIR).join(SESSION_BLOB_FILENAME),
        }
    }

    /// Resolve the platform-standard `<config_dir>` via
    /// `directories::ProjectDirs::from`. Returns [`None`] on
    /// platforms with no home directory.
    #[allow(
        dead_code,
        reason = "F-CLI.6 (config persistence) wires this into the runtime startup. \
                  Today's integration tests use `StatePaths::under` with a temp dir."
    )]
    pub(crate) fn default_for_platform() -> Option<Self> {
        let dirs = directories::ProjectDirs::from("", "BiBEAM", "bibeam")?;
        Some(Self::under(dirs.config_dir()))
    }
}

/// Load or create the 32-byte AEAD key at [`StatePaths::key_path`].
///
/// First call: generates a fresh 32-byte key, writes it with mode
/// `0o600` on unix, returns it. Subsequent calls: reads the file
/// and returns its bytes (must be exactly [`AEAD_KEY_LEN`]).
///
/// # Errors
///
/// - [`RegisterError::StateIo`] on filesystem failures.
/// - [`RegisterError::StateBlobTooShort`] if the key file exists
///   but is the wrong length — likely an externally tampered file.
#[allow(
    clippy::redundant_pub_crate,
    reason = "binary-only crate: see RegisterError for the rustc-vs-clippy rationale."
)]
#[allow(
    dead_code,
    reason = "wired into the up flow after F-CLI.6 lands. Today's integration tests \
              call this directly to seed the persist helpers."
)]
pub(crate) fn load_or_create_state_key(
    paths: &StatePaths,
) -> Result<[u8; AEAD_KEY_LEN], RegisterError> {
    if paths.key_path.exists() {
        let bytes = std::fs::read(&paths.key_path).map_err(RegisterError::StateIo)?;
        if bytes.len() != AEAD_KEY_LEN {
            return Err(RegisterError::StateBlobTooShort {
                have: bytes.len(),
                need: AEAD_KEY_LEN,
            });
        }
        let mut key = [0_u8; AEAD_KEY_LEN];
        key.copy_from_slice(&bytes);
        return Ok(key);
    }
    let key: [u8; AEAD_KEY_LEN] = rand::random();
    write_state_key(&paths.key_path, &key)?;
    Ok(key)
}

/// Persist a PASETO session token to the on-disk encrypted blob.
///
/// `aead` is the [`ControlAead`] built from
/// [`load_or_create_state_key`]'s output; `token` is the verified
/// PASETO string; `blob_path` is the target file path.
///
/// Overwrites any existing blob — F-CLI.5's rotation loop calls
/// this on every rotation with a fresh nonce.
///
/// # Errors
///
/// - [`RegisterError::StateAead`] on seal failure (vanishingly
///   unlikely with `ChaCha20-Poly1305`).
/// - [`RegisterError::StateIo`] on filesystem failures.
#[allow(
    clippy::redundant_pub_crate,
    reason = "binary-only crate: see RegisterError for the rustc-vs-clippy rationale."
)]
#[allow(
    dead_code,
    reason = "wired into the up flow after F-CLI.6 lands. Today's integration tests \
              exercise persist_session / load_session as a pair."
)]
pub(crate) fn persist_session(
    aead: &ControlAead,
    token: &str,
    blob_path: &Path,
) -> Result<(), RegisterError> {
    let nonce: [u8; AEAD_NONCE_LEN] = rand::random();
    let ciphertext = aead
        .seal(&nonce, STATE_AAD_DOMAIN, token.as_bytes())
        .map_err(|err| RegisterError::StateAead(err.to_string()))?;
    let mut blob = Vec::with_capacity(AEAD_NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    if let Some(parent) = blob_path.parent() {
        std::fs::create_dir_all(parent).map_err(RegisterError::StateIo)?;
    }
    std::fs::write(blob_path, blob).map_err(RegisterError::StateIo)
}

/// Decrypt the on-disk session blob and return the PASETO token.
///
/// # Errors
///
/// - [`RegisterError::StateBlobTooShort`] on a truncated blob.
/// - [`RegisterError::StateAead`] on auth-tag verify failure
///   (wrong key, tampered blob, or wrong AAD).
/// - [`RegisterError::StateIo`] on filesystem failures.
#[allow(
    clippy::redundant_pub_crate,
    reason = "binary-only crate: see RegisterError for the rustc-vs-clippy rationale."
)]
#[allow(
    dead_code,
    reason = "wired into the up flow after F-CLI.6 lands. Today's integration tests \
              exercise persist_session / load_session as a pair."
)]
pub(crate) fn load_session(aead: &ControlAead, blob_path: &Path) -> Result<String, RegisterError> {
    let blob = std::fs::read(blob_path).map_err(RegisterError::StateIo)?;
    if blob.len() < AEAD_NONCE_LEN {
        return Err(RegisterError::StateBlobTooShort {
            have: blob.len(),
            need: AEAD_NONCE_LEN,
        });
    }
    let (nonce_bytes, ciphertext) = blob.split_at(AEAD_NONCE_LEN);
    let nonce: &[u8; AEAD_NONCE_LEN] =
        nonce_bytes.try_into().map_err(|_| RegisterError::StateBlobTooShort {
            have: blob.len(),
            need: AEAD_NONCE_LEN,
        })?;
    let plaintext = aead
        .open(nonce, STATE_AAD_DOMAIN, ciphertext)
        .map_err(|err| RegisterError::StateAead(err.to_string()))?;
    let token = String::from_utf8(plaintext)
        .map_err(|err| RegisterError::StateAead(format!("token bytes not utf-8: {err}")))?;
    if token.is_empty() {
        return Err(RegisterError::EmptyToken);
    }
    Ok(token)
}

/// Write the 32-byte AEAD key to `path`.
///
/// On unix the file is created with `O_CREAT | O_EXCL` and mode
/// `0o600` *atomically* — there is no window during which the
/// file exists but a permissions-set syscall has not yet run.
/// `create_new(true)` plus `OpenOptionsExt::mode` is the canonical
/// shape for sensitive-key files on Linux/macOS. On non-unix
/// (Windows) the underlying ACL model is different; we still
/// create with `create_new(true)` so a pre-existing key file is
/// rejected, and rely on the standard user-profile ACL.
///
/// Returns the I/O error verbatim if the file already exists —
/// callers (`load_or_create_state_key`) check `path.exists()`
/// before invoking this fn, so a race that lands here is an
/// integrity violation worth surfacing.
fn write_state_key(path: &Path, key: &[u8; AEAD_KEY_LEN]) -> Result<(), RegisterError> {
    use std::io::Write as _;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(RegisterError::StateIo)?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(RegisterError::StateIo)?;
    file.write_all(key).map_err(RegisterError::StateIo)?;
    file.sync_all().map_err(RegisterError::StateIo)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use bibeam_core::Timestamp;
    use bibeam_crypto::{IdentitySecretKey, InviteCode};
    use bibeam_discovery::signing_payload;

    use super::*;

    /// Simple per-test scratch directory under
    /// [`std::env::temp_dir`]. Avoids pulling `tempfile` into the
    /// workspace dep graph for one helper.
    struct ScratchDir {
        path: PathBuf,
    }

    impl ScratchDir {
        fn new(tag: &str) -> Self {
            let salt: u64 = rand::random();
            let path = std::env::temp_dir().join(format!("bibeam-cli-test-{tag}-{salt:016x}"));
            std::fs::create_dir_all(&path).expect("create scratch dir");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            // Best-effort cleanup; failure to remove a temp dir
            // on a busy CI runner is not worth panicking over.
            // `drop(...)` discards the result without tripping
            // `let_underscore_must_use` / `let_underscore_drop`.
            drop(std::fs::remove_dir_all(&self.path));
        }
    }

    fn fixture_signed_invite() -> SignedInvite {
        let secret = IdentitySecretKey::generate();
        let issuer = secret.public();
        let code = InviteCode::new([0xAB; 16]);
        let issued_at = Timestamp::now();
        let signature = secret.sign(&signing_payload(&code, &issued_at, None)).to_bytes().to_vec();
        SignedInvite {
            code,
            issuer,
            issued_at,
            expires_at: None,
            signature,
        }
    }

    #[test]
    fn invite_round_trips_through_base64_armour() {
        let invite = fixture_signed_invite();
        let armoured = encode_invite(&invite).expect("encode");
        let recovered = parse_invite(&armoured).expect("decode");
        assert_eq!(recovered, invite);
    }

    #[test]
    fn parse_invite_rejects_garbage_base64() {
        let err = parse_invite("not valid base64 +/=").expect_err("must reject");
        assert!(matches!(err, RegisterError::InviteBase64(_)));
    }

    #[test]
    fn parse_invite_rejects_truncated_postcard() {
        // Valid base64, but not a valid SignedInvite payload.
        let bad = INVITE_BASE64.encode([0_u8; 4]);
        let err = parse_invite(&bad).expect_err("must reject");
        assert!(matches!(err, RegisterError::InvitePostcard(_)));
    }

    #[test]
    fn state_paths_are_under_supplied_config_dir() {
        let tmp = ScratchDir::new("tmp");
        let paths = StatePaths::under(tmp.path());
        assert_eq!(paths.key_path, tmp.path().join("state.key"));
        assert_eq!(paths.session_blob_path, tmp.path().join("state").join("session.bin"));
    }

    #[test]
    fn load_or_create_state_key_is_idempotent() {
        // First call creates the file and returns a fresh key;
        // second call reads it back unchanged.
        let tmp = ScratchDir::new("tmp");
        let paths = StatePaths::under(tmp.path());
        let first = load_or_create_state_key(&paths).expect("first load");
        let second = load_or_create_state_key(&paths).expect("second load");
        assert_eq!(first, second, "key must round-trip");
    }

    #[cfg(unix)]
    #[test]
    fn load_or_create_state_key_chmods_0600_on_unix() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = ScratchDir::new("tmp");
        let paths = StatePaths::under(tmp.path());
        let _ = load_or_create_state_key(&paths).expect("load");
        let meta = std::fs::metadata(&paths.key_path).expect("metadata");
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "state.key must be 0600 on unix");
    }

    #[test]
    fn persist_then_load_round_trips_token() {
        let tmp = ScratchDir::new("tmp");
        let paths = StatePaths::under(tmp.path());
        let key = load_or_create_state_key(&paths).expect("key");
        let aead = ControlAead::new(&key);
        let token = "v4.public.example-token-bytes".to_owned();
        persist_session(&aead, &token, &paths.session_blob_path).expect("persist");
        let recovered = load_session(&aead, &paths.session_blob_path).expect("load");
        assert_eq!(recovered, token);
    }

    #[test]
    fn persist_overwrites_previous_blob() {
        // Contract: F-CLI.5's rotation loop overwrites the same
        // blob path on every rotation. Verify the second write
        // wins and is decryptable.
        let tmp = ScratchDir::new("tmp");
        let paths = StatePaths::under(tmp.path());
        let key = load_or_create_state_key(&paths).expect("key");
        let aead = ControlAead::new(&key);
        persist_session(&aead, "first-token", &paths.session_blob_path).expect("first");
        persist_session(&aead, "second-token", &paths.session_blob_path).expect("second");
        let recovered = load_session(&aead, &paths.session_blob_path).expect("load");
        assert_eq!(recovered, "second-token");
    }

    #[test]
    fn load_session_rejects_truncated_blob() {
        let tmp = ScratchDir::new("tmp");
        let blob_path = tmp.path().join("trunc.bin");
        std::fs::write(&blob_path, [0_u8; 4]).expect("write");
        let key = [0_u8; AEAD_KEY_LEN];
        let aead = ControlAead::new(&key);
        let err = load_session(&aead, &blob_path).expect_err("must reject");
        assert!(matches!(err, RegisterError::StateBlobTooShort { .. }));
    }

    #[test]
    fn load_session_rejects_tampered_blob() {
        // Contract: an AEAD tag mismatch (modified ciphertext)
        // surfaces as StateAead. This catches the contract that
        // the on-disk blob is integrity-protected, not just
        // confidentiality-protected.
        let tmp = ScratchDir::new("tmp");
        let paths = StatePaths::under(tmp.path());
        let key = load_or_create_state_key(&paths).expect("key");
        let aead = ControlAead::new(&key);
        persist_session(&aead, "tamper-me", &paths.session_blob_path).expect("persist");
        // Flip the last byte (Poly1305 tag region) and reload.
        let mut blob = std::fs::read(&paths.session_blob_path).expect("read");
        if let Some(last) = blob.last_mut() {
            *last = last.wrapping_add(1);
        }
        std::fs::write(&paths.session_blob_path, &blob).expect("rewrite");
        let err = load_session(&aead, &paths.session_blob_path).expect_err("must reject");
        assert!(matches!(err, RegisterError::StateAead(_)));
    }
}
