#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

//! Library entry point for the `bibeam-node` daemon.
//!
//! `bibeam-node` is the single dual-role server binary. It runs the
//! `WireGuard` data plane (relay / exit / forwarder) AND the control
//! plane (rendezvous / admission / rotation), with the control-plane
//! routes mounted behind an `is_coordinator` config flag. The
//! [`coordinator`] sub-module owns the control-plane surface that
//! previously lived in the standalone `bibeam-coordinator` crate
//! (dissolved per §11 R-1).

pub mod coordinator;
