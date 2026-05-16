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
//!
//! The [`forwarder`] sub-module implements the intermediate-node
//! stateful UDP forwarder mode (R-MULTIHOP-NODE): a per-pair
//! routing table + lease-enforced relay loop that never touches
//! `WireGuard` payload material.
//!
//! The [`telemetry`] sub-module defines the node data-plane
//! Prometheus metric names (counters / gauges) and a
//! [`telemetry::register_node_metrics`] entry point that attaches
//! `# HELP` and `# TYPE` metadata via the [`metrics`] facade (F-NODE.9).

pub mod coordinator;
pub mod forwarder;
pub mod telemetry;
