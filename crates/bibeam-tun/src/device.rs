#![forbid(unsafe_code)]
//! Cross-platform TUN device wrapper.
//!
//! [`TunDevice`] is a thin façade over [`tun_rs::AsyncDevice`] that gives the
//! rest of `bibeam-tun` a single shape — `async fn read_packet` and
//! `async fn write_packet` — independent of the platform-specific
//! [`tun_rs`] backing (Linux netlink, macOS utun, Windows wintun).
//!
//! ## Blocking I/O caveats
//!
//! Device *construction* delegates to [`tun_rs::DeviceBuilder::build_async`],
//! which on every supported platform performs synchronous syscalls
//! (`/dev/net/tun` open on Linux, `wintun.dll` device registration on
//! Windows, kernel control socket on macOS) before returning. Those calls
//! happen inside [`TunDevice::new`]'s `async fn` body but do not yield to
//! the runtime — keep that in mind if the function is awaited on a
//! latency-sensitive task. Read and write *are* fully asynchronous and
//! integrate with the Tokio reactor.
//!
//! ## Privileges
//!
//! Opening a TUN interface needs root on Linux, an administrator on
//! Windows, and either root or an entitlement on macOS. Failures surface
//! as [`TunError::Open`].

use core::fmt;

use thiserror::Error;
use tun_rs::{AsyncDevice, DeviceBuilder};

/// Errors emitted by the TUN device wrapper and the surrounding L3
/// pipeline.
///
/// Each variant captures the I/O class the failure belongs to so callers
/// can distinguish device-creation problems (which usually mean the
/// process lacks privilege) from steady-state read/write errors (which
/// usually mean the kernel side has gone away).
#[derive(Debug, Error)]
pub enum TunError {
    /// Failed to open or configure the underlying TUN interface.
    #[error("tun open error: {0}")]
    Open(#[source] std::io::Error),
    /// Failed to read a packet from the TUN device.
    #[error("tun read error: {0}")]
    Read(#[source] std::io::Error),
    /// Failed to write a packet to the TUN device.
    #[error("tun write error: {0}")]
    Write(#[source] std::io::Error),
    /// A packet is malformed or violates a length invariant.
    #[error("tun packet error: {0}")]
    Packet(String),
}

/// Async TUN/TAP device handle.
///
/// Wraps [`tun_rs::AsyncDevice`] and exposes the two L3 packet operations
/// the rest of the crate needs. The wrapper takes ownership of the
/// underlying file descriptor / driver handle and closes it on drop, the
/// same semantics as [`AsyncDevice`].
pub struct TunDevice {
    inner: AsyncDevice,
}

impl TunDevice {
    /// Open a new TUN interface with the requested name and MTU.
    ///
    /// `name` is a *hint*: on Linux it is honoured verbatim if available,
    /// on macOS it must be a `utunN` shape (and the kernel may pick the
    /// final `N`), on Windows it becomes the wintun adapter name. If the
    /// platform rewrites the name, that is reflected on the underlying
    /// [`AsyncDevice`] but not surfaced through this wrapper (the L3
    /// pipeline does not care about the link-layer name).
    ///
    /// `mtu` is applied to the interface. The conventional default for
    /// an Ethernet-edged tunnel is `1500`; callers wanting a smaller MTU
    /// for overlay-traversal headroom can pass it here.
    ///
    /// # Errors
    ///
    /// Returns [`TunError::Open`] when the underlying [`DeviceBuilder`]
    /// rejects the configuration. Common causes: the process lacks the
    /// `CAP_NET_ADMIN` capability (Linux) or is not running as an
    /// administrator (Windows), the wintun driver is missing, or the
    /// requested name conflicts with an existing interface.
    #[allow(
        clippy::unused_async,
        reason = "Constructor is async by spec so future refactors (e.g. \
                  awaiting a runtime-side configuration probe before binding \
                  the interface) can land without an API break. tun-rs 2.x's \
                  `build_async` is sync today; the async signature is \
                  forward-compatible."
    )]
    pub async fn new(name: &str, mtu: u16) -> Result<Self, TunError> {
        let inner =
            DeviceBuilder::new().name(name).mtu(mtu).build_async().map_err(TunError::Open)?;
        Ok(Self { inner })
    }

    /// Read one IP packet from the TUN device into `buf`.
    ///
    /// Returns the number of bytes written to `buf`. The buffer must be
    /// at least as large as the interface MTU (typically `1500` bytes);
    /// excess bytes of an oversized packet may be discarded by the
    /// underlying driver.
    ///
    /// # Errors
    ///
    /// Returns [`TunError::Read`] when the underlying I/O fails.
    pub async fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize, TunError> {
        self.inner.recv(buf).await.map_err(TunError::Read)
    }

    /// Write one IP packet from `buf` to the TUN device.
    ///
    /// Returns the number of bytes accepted by the driver, which equals
    /// `buf.len()` on every well-behaved platform.
    ///
    /// # Errors
    ///
    /// Returns [`TunError::Write`] when the underlying I/O fails.
    pub async fn write_packet(&mut self, buf: &[u8]) -> Result<usize, TunError> {
        self.inner.send(buf).await.map_err(TunError::Write)
    }
}

impl fmt::Debug for TunDevice {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `tun_rs::AsyncDevice` does not implement `Debug`, and printing the
        // raw fd would not add information a human reading a log line can
        // act on. Render the wrapper as an opaque token.
        formatter.write_str("TunDevice(<opaque>)")
    }
}
