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
//!
//! The [`dns`] sub-module wraps `hickory-resolver` for the node's
//! own DNS needs (exit-mode DNS-over-TLS bootstrap, control-plane
//! peer hostname resolution); it falls back to public DNS when the
//! system configuration is unavailable (F-NODE.7).
//!
//! The [`rate_limit`] sub-module caps per-cohort and per-peer
//! data-plane packet rates (F-NODE.8). It is distinct from the
//! coord control-plane rate limit at
//! [`coordinator::rate_limit`], which keys on source IP +
//! `PeerId` for the four HTTP control-plane verbs.
//!
//! The [`exit_mode`] sub-module implements the exit-side packet
//! egress (F-NODE.4 per D-3 + D-1): an L3 path that writes decrypted
//! IP packets to a kernel TUN device for operator-configured NAT
//! egress, and an L4 SOCKS5 fallback for environments where a TUN
//! device cannot be opened.

pub mod coordinator;
pub mod dns;
pub mod exit_mode;
pub mod forwarder;
pub mod rate_limit;
pub mod telemetry;
