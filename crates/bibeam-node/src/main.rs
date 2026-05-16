#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

use anyhow::Result;
use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = env!("CARGO_PKG_NAME"), version, about)]
struct Cli {
    /// Run with the coordinator (control-plane) role mounted alongside
    /// the data-plane role. Per §11 R-1 the single `bibeam-node`
    /// binary services both roles; this flag gates the control-plane
    /// route surface (rendezvous / admission / rotation) from the
    /// [`bibeam_node::coordinator`] sub-module.
    ///
    /// Full boot orchestration (listener + redb + `ReadyLatch`) is a
    /// follow-up task; today the flag is wired to a placeholder so
    /// the workspace compiles cleanly with the module reachable.
    #[arg(long, env = "BIBEAM_IS_COORDINATOR")]
    is_coordinator: bool,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        is_coordinator = cli.is_coordinator,
        "bootstrap"
    );
    if cli.is_coordinator {
        // Control-plane mount-point scaffold. The full boot sequence
        // (axum listener bind, redb open, ReadyLatch flip, rate-limit
        // store wiring) is a follow-up task; this commit only needs
        // the `bibeam_node::coordinator` module reachable so the
        // workspace builds clean with the dissolved crate's sources.
        let _router = bibeam_node::coordinator::server::build_router(
            bibeam_runtime::ReadyLatch::new(),
            axum::Router::new(),
        );
    }
    Ok(())
}
