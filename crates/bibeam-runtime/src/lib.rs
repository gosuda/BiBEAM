#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod log;
pub mod redaction_layer;

pub use log::{LogInitError, init_json_logging};
pub use redaction_layer::{Pii, PiiRedactionLayer, REDACTION_AUDIT_TARGET, redact};
