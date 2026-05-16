#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod aead;
pub mod identity_key;
pub mod invite;
pub mod kdf;
pub mod token;
pub mod wg_keys;

pub use aead::{AeadError, ControlAead, KEY_LEN as AEAD_KEY_LEN, NONCE_LEN as AEAD_NONCE_LEN};
pub use identity_key::{IdentityKeyError, IdentityPublicKey, IdentitySecretKey};
pub use invite::{
    INVITE_CODE_LEN, InviteCode, InviteCodeError, MASTER_INVITE_KEY_LEN, MasterInviteKey,
    derive_session_psk,
};
pub use kdf::{KdfError, derive_subkey, derive_wg_psk};
pub use token::{PasetoIssuer, PasetoVerifier, TokenError};
pub use wg_keys::{SessionPsk, WG_KEY_LEN, WgKeyError, WgPsk, WgPublicKey, WgSecretKey};
