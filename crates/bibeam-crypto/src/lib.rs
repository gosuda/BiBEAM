#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod aead;
pub mod identity_key;
pub mod token;
pub mod wg_keys;

pub use aead::{AeadError, ControlAead, KEY_LEN as AEAD_KEY_LEN, NONCE_LEN as AEAD_NONCE_LEN};
pub use identity_key::{IdentityKeyError, IdentityPublicKey, IdentitySecretKey};
pub use token::{PasetoIssuer, PasetoVerifier, TokenError};
pub use wg_keys::{SessionPsk, WG_KEY_LEN, WgKeyError, WgPsk, WgPublicKey, WgSecretKey};
