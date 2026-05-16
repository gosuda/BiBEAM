#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

//! Library entry point for the `bibeam-coordinator` daemon.
//!
//! The coordinator is the rendezvous + matchmaker service. Peers POST
//! [`bibeam_protocol::control::Register`] / `MatchRequest` /
//! `Heartbeat` / `Disconnect` to the routes mounted by
//! [`server::build_router`], and subscribe to a coordinator-pushed
//! event stream over WebSocket. This crate also exposes the daemon as
//! a binary; `main.rs` is a thin shim that calls into this library so
//! the routes and storage primitives are reachable from integration
//! tests under `tests/`.

pub mod registry;
pub mod server;
