#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

use anyhow::Result;
use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = env!("CARGO_PKG_NAME"), version, about)]
struct Cli {}

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
    // The library crate exposes the route surface (F-COORD.1); a
    // follow-up sub-item wires the listener + redb + ReadyLatch flip
    // into this bin's startup sequence (F-COORD.11). Until then,
    // `main` only constructs the router to prove the bin links
    // against the library, then exits cleanly.
    let _router = bibeam_coordinator::server::build_router(
        bibeam_runtime::ReadyLatch::new(),
        axum::Router::new(),
    );
    Ok(())
}
