#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

use std::net::SocketAddr;

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

    /// Run with the intermediate-node stateful UDP forwarder
    /// (R-MULTIHOP-NODE) mounted alongside the data-plane role.
    ///
    /// The forwarder binds [`forwarder_bind`][Cli::forwarder_bind],
    /// holds a per-pair routing table keyed by
    /// [`bibeam_protocol::RelayFrame::chain_id`], and relays UDP
    /// between coord-authorised peers gated by lease expiry. The
    /// coord-WS lease ingestion path (`Forwarder::insert_lease`
    /// driven by the WS event handler) is wired by the
    /// R-MULTIHOP-COORD sweep; this commit only mounts the run-loop
    /// scaffold behind the flag.
    #[arg(long, env = "BIBEAM_FORWARDER_ENABLED")]
    forwarder: bool,

    /// UDP bind address for the forwarder mode. Ignored when
    /// [`forwarder`][Cli::forwarder] is `false`.
    #[arg(long, env = "BIBEAM_FORWARDER_BIND_ADDR", default_value = "0.0.0.0:51820")]
    forwarder_bind: SocketAddr,
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
        forwarder = cli.forwarder,
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
    if cli.forwarder {
        // Forwarder mount-point scaffold (R-MULTIHOP-NODE). The
        // coord-WS lease ingestion path is wired by the
        // R-MULTIHOP-COORD sweep; this commit only constructs the
        // forwarder so the binary surface is reachable and the
        // module is exercised by `cargo build`.
        let config = bibeam_node::forwarder::ForwarderConfig::new(cli.forwarder_bind);
        let forwarder = bibeam_node::forwarder::Forwarder::bind(config.bind_addr).await?;
        tracing::info!(
            bind_addr = %forwarder.local_addr()?,
            "forwarder bound (run-loop spawn deferred to R-MULTIHOP-COORD wire-up)",
        );
        drop(forwarder);
    }
    Ok(())
}
