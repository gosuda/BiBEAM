#![forbid(unsafe_code)]
//! Bounded packet channels with a documented drop-newest policy.
//!
//! This module exposes [`bounded_packet_channel`] — a thin
//! constructor that returns a [`tokio::sync::mpsc`] sender/receiver
//! pair at a uniform bound — and the [`DEFAULT_CHANNEL_BOUND`]
//! constant that documents the chosen depth.
//!
//! ## Drop-newest, not drop-oldest, not block
//!
//! When the channel is full, the **send site** in
//! [`crate::outbound`]'s pipeline uses
//! [`tokio::sync::mpsc::Sender::try_send`] and discards the packet
//! it just produced. Two alternative policies were considered:
//!
//! - **Block on `send().await`** — head-of-line blocks the producer
//!   on a slow consumer. The TUN device's kernel-side queue then
//!   fills, the kernel drops *every* packet (not just newest), and
//!   the user experiences worse latency than under drop-newest.
//!
//! - **Drop-oldest** — equivalent latency under sustained overload
//!   but requires a `swap()`-style operation that `mpsc` does not
//!   provide cleanly. Drop-newest is one call.
//!
//! ## No `QoS` classifier
//!
//! This module deliberately has no concept of packet class. Per-class
//! scheduling (DSCP-aware, flow-keyed) is a deferred enhancement that
//! lands as its own task only after a classifier exists upstream.

use bytes::Bytes;
use tokio::sync::mpsc;

/// Default bound for packet channels.
///
/// `1024` slots of 1500-byte MTU is ~1.5 MiB of buffered packet
/// memory — enough to absorb short producer bursts while keeping
/// queueing latency below ~1 ms at typical home-link speeds.
pub const DEFAULT_CHANNEL_BOUND: usize = 1024;

/// Construct a bounded packet channel at [`DEFAULT_CHANNEL_BOUND`].
///
/// The returned pair has the right shape to plug into
/// [`crate::OutboundPipeline::new`] / [`crate::InboundPipeline::new`].
#[must_use]
pub fn bounded_packet_channel() -> (mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>) {
    mpsc::channel(DEFAULT_CHANNEL_BOUND)
}
