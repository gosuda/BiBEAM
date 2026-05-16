#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod alloc;
pub mod config;
pub mod health;
pub mod log;
pub mod metrics;
pub mod redaction_layer;
pub mod shutdown;
pub mod signal;

pub use config::{ConfigError, GeoipConfig, load as load_config};
pub use health::{ReadyLatch, router as health_router};
pub use log::{LogInitError, init_json_logging};
pub use metrics::{MetricsError, router as metrics_router};
pub use redaction_layer::{Pii, PiiRedactionLayer, REDACTION_AUDIT_TARGET, redact};
pub use shutdown::Shutdown;
pub use signal::shutdown_signal;
