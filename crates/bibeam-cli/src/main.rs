#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

mod cli;
mod config;
mod ech;
mod exit_pick;
mod register;
mod rotation;
mod tun_setup;

use anyhow::Result;
use clap::Parser as _;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let parsed = cli::Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "bootstrap");
    cli::dispatch(parsed).await
}
