#![forbid(unsafe_code)]
//! Outbound packet pipeline: read TUN → channel.
//!
//! [`OutboundPipeline`] owns a [`crate::TunDevice`] plus the sender side
//! of a bounded mpsc channel. Its [`OutboundPipeline::run`] loop reads
//! one IP packet at a time from the TUN device, copies it into a
//! [`bytes::Bytes`], and tries to send it downstream.
//!
//! ## Backpressure
//!
//! When the channel is full, [`OutboundPipeline::run`] applies
//! drop-newest-on-overflow — the just-read packet is silently
//! discarded (with a `tracing::warn` so the drop is observable in
//! metrics later) and the loop continues. This matches the policy
//! [`crate::backpressure`] documents at the channel-construction
//! site. The alternative would be `Sender::send().await`, which
//! head-of-line blocks on a slow consumer and lets the TUN device's
//! kernel-side queue back up — which is worse for end-to-end latency
//! under congestion.
//!
//! ## Encryption boundary
//!
//! This pipeline emits **raw IP bytes**. Sealing the bytes into a
//! transport frame is the responsibility of a downstream stage
//! (`bibeam-crypto` for the AEAD, `bibeam-transport` for the
//! datagram envelope). The split keeps `bibeam-tun` cleanly L3 and
//! lets the crypto policy be decided independently — see D-4 in
//! `docs/plan/tasks.md`.

use bytes::Bytes;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::device::{TunDevice, TunError};

/// Default read buffer size, sized to the conventional Ethernet MTU
/// (`1500`). Larger MTUs are uncommon on tunnels because every overlay
/// header eats into the inner payload; if a future caller needs a
/// larger MTU they can subclass this loop or grow the buffer when
/// constructing it.
const READ_BUFFER_LEN: usize = 1500;

/// Reads packets from a TUN device and emits them on a bounded channel.
#[derive(Debug)]
pub struct OutboundPipeline {
    device: TunDevice,
    tx: mpsc::Sender<Bytes>,
}

impl OutboundPipeline {
    /// Wire a TUN device to a downstream packet channel.
    #[must_use]
    pub const fn new(device: TunDevice, tx: mpsc::Sender<Bytes>) -> Self {
        Self { device, tx }
    }

    /// Run the read loop until `cancel` is fired or the channel closes.
    ///
    /// Each iteration reads one packet from the TUN device and tries to
    /// `try_send` it on the channel. A full channel triggers
    /// drop-newest-on-overflow (the just-read packet is discarded);
    /// a closed channel terminates the loop cleanly with `Ok(())`.
    ///
    /// # Errors
    ///
    /// Returns [`TunError::Read`] when the underlying TUN device fails
    /// a read.
    pub async fn run(mut self, cancel: CancellationToken) -> Result<(), TunError> {
        let mut buf = vec![0u8; READ_BUFFER_LEN];
        loop {
            tokio::select! {
                () = cancel.cancelled() => return Ok(()),
                read = self.device.read_packet(&mut buf) => {
                    let read_len = read?;
                    let pkt = Bytes::copy_from_slice(&buf[..read_len]);
                    match self.tx.try_send(pkt) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            // Drop-newest-on-overflow per F-TUN.8.
                            // A metrics counter wires up once the
                            // observability stack lands.
                            tracing::warn!(
                                read_bytes = read_len,
                                "outbound packet channel full; dropping packet"
                            );
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            // Downstream has gone away. Treat as a
                            // clean shutdown signal — there is no
                            // useful work for us to do.
                            return Ok(());
                        }
                    }
                }
            }
        }
    }
}
