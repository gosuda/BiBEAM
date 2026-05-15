#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

use anyhow::Result;
use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = env!("CARGO_PKG_NAME"), version, about)]
struct Cli {
    /// Path to config file
    #[arg(long, env = "BIBEAM_CONFIG")]
    config: Option<std::path::PathBuf>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let _cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "bootstrap");
    Ok(())
}
