#![forbid(unsafe_code)]
//! Inbound packet pipeline: channel → write TUN.
//!
//! [`InboundPipeline`] owns a [`crate::TunDevice`] plus the receiver
//! side of a bounded mpsc channel. Its [`InboundPipeline::run`] loop
//! awaits one packet at a time and writes it to the TUN device.
//!
//! ## Decryption boundary
//!
//! The channel carries **already-decrypted IP bytes**. Whatever
//! upstream stage handed bytes to us has already stripped the
//! transport envelope (e.g. WireGuard-encapsulated UDP packet) and the AEAD seal
//! (see `bibeam-crypto`). This crate stays cleanly L3; the inverse
//! split is documented on the outbound side too.
//!
//! ## Shutdown
//!
//! Two paths terminate the loop, both cleanly:
//!
//! - `cancel.cancelled()` fires (cooperative shutdown from a
//!   supervisor).
//! - The channel sender drops, [`mpsc::Receiver::recv`] returns
//!   `None`. This is the normal teardown when the upstream pipeline
//!   exits.

use bytes::Bytes;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::device::{TunDevice, TunError};

/// Receives packets from an upstream channel and writes them to the TUN
/// device.
#[derive(Debug)]
pub struct InboundPipeline {
    device: TunDevice,
    rx: mpsc::Receiver<Bytes>,
}

impl InboundPipeline {
    /// Wire an upstream packet channel to a TUN device.
    #[must_use]
    pub const fn new(device: TunDevice, rx: mpsc::Receiver<Bytes>) -> Self {
        Self { device, rx }
    }

    /// Run the write loop until `cancel` is fired or the upstream
    /// channel closes.
    ///
    /// # Errors
    ///
    /// Returns [`TunError::Write`] when the underlying TUN device fails
    /// a write. The loop bails on the first write error; an upstream
    /// supervisor decides whether to restart it.
    pub async fn run(mut self, cancel: CancellationToken) -> Result<(), TunError> {
        loop {
            tokio::select! {
                () = cancel.cancelled() => return Ok(()),
                pkt = self.rx.recv() => match pkt {
                    Some(packet) => {
                        self.device.write_packet(&packet).await?;
                    }
                    None => return Ok(()),
                }
            }
        }
    }
}
