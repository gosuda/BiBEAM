//! Control-plane (coordinator) sub-module of the `bibeam-node` daemon.
//!
//! Previously the standalone `bibeam-coordinator` crate; dissolved
//! into `bibeam-node` per §11 R-1 so a single binary services both
//! data-plane (relay / exit / forwarder) and control-plane
//! (rendezvous / admission / rotation) roles, gated by the
//! `is_coordinator` config flag.
//!
//! The coordinator is the rendezvous + matchmaker service. Peers POST
//! [`bibeam_protocol::control::Register`] / `MatchRequest` /
//! `Heartbeat` / `Disconnect` to the routes mounted by
//! [`server::build_router`], and subscribe to a coordinator-pushed
//! event stream over WebSocket.

pub mod admission;
pub mod admission_gate;
pub mod audit;
pub mod cluster;
pub mod cohorts;
pub mod geoip_verify;
pub mod health;
pub mod invite_admission;
pub mod log_hooks;
pub mod rate_limit;
pub mod registry;
pub mod rotation;
pub mod server;

pub use geoip_verify::GeoipReader;
