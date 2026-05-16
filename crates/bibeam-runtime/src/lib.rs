#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod log;
pub mod metrics;
pub mod redaction_layer;

pub use log::{LogInitError, init_json_logging};
pub use metrics::{MetricsError, router as metrics_router};
pub use redaction_layer::{Pii, PiiRedactionLayer, REDACTION_AUDIT_TARGET, redact};
