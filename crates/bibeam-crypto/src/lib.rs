#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod wg_keys;

pub use wg_keys::{SessionPsk, WG_KEY_LEN, WgKeyError, WgPsk, WgPublicKey, WgSecretKey};
