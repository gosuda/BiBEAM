#![forbid(unsafe_code)]
//! ICE-lite simultaneous-open `WireGuard` hole-punch.
//!
//! Per D-4 the data plane is `boringtun`-driven `WireGuard`. F-TRANS.5
//! is the NAT-traversal step that gets two peers' UDP packets through
//! whichever NATs sit between them.
//!
//! ## The protocol
//!
//! 1. Both peers have already learned their public `(ip, port)` via
//!    F-TRANS.4's STUN client.
//! 2. The coordinator orchestrates a wall-clock target [`Timestamp`]
//!    (`sync_at`). At that moment, both peers send the **same byte
//!    sequence** — the first `WireGuard` handshake-init message — at
//!    each other's STUN-discovered address.
//! 3. The NATs on both sides each see an outbound UDP packet first,
//!    install a 5-tuple binding, then accept the matching inbound
//!    packet from the other side.
//! 4. From there, normal `WgTunnel` traffic flows.
//!
//! The hole-punch packet IS the WG handshake first message —
//! `boringtun` emits 148 bytes that look exactly like a real WG
//! initiation, and the receiver's `boringtun` instance processes it
//! normally. We do NOT send a separate "ping" payload.
//!
//! ## Past `sync_at`
//!
//! If `sync_at` is already in the past, we send immediately rather
//! than erroring. A negative-duration sleep is a no-op; the
//! coordinator is responsible for spacing target times sensibly, but
//! a missed window should not abort the punch — the other peer may
//! still be on time and a single late send is the cheapest recovery.

use std::net::SocketAddr;
use std::time::Duration;

use thiserror::Error;
use tokio::net::UdpSocket;

use bibeam_core::Timestamp;

/// Errors emitted by [`simultaneous_open`].
#[derive(Debug, Error)]
pub enum HolepunchError {
    /// Underlying UDP socket I/O failed.
    #[error("holepunch: udp i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// `handshake_init` was empty — there is nothing to send, which
    /// means the caller didn't drive `WgTunnel::encapsulate` first.
    #[error("holepunch: handshake_init bytes were empty")]
    EmptyHandshake,
}

/// Issue one ICE-lite simultaneous-open hole-punch.
///
/// Sleeps until `sync_at` (or fires immediately if `sync_at` is in
/// the past), then sends `handshake_init` to `peer_addr` exactly once.
/// Returns once the local send has completed.
///
/// `handshake_init` MUST be the bytes produced by
/// [`crate::WgTunnel::encapsulate`]'s first call (148 bytes of WG
/// handshake-initiation). Passing arbitrary bytes here works as a NAT
/// punch but does NOT advance the WG session, which makes the punch
/// pointless: the boringtun state on both sides will reject anything
/// that isn't a valid handshake message.
///
/// # Errors
///
/// Returns [`HolepunchError::EmptyHandshake`] if `handshake_init` is
/// empty (caller-side programming error) and [`HolepunchError::Io`] if
/// the UDP send fails.
pub async fn simultaneous_open(
    socket: &UdpSocket,
    peer_addr: SocketAddr,
    sync_at: Timestamp,
    handshake_init: &[u8],
) -> Result<(), HolepunchError> {
    if handshake_init.is_empty() {
        return Err(HolepunchError::EmptyHandshake);
    }
    let delay = time_until(sync_at);
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
    socket.send_to(handshake_init, peer_addr).await?;
    Ok(())
}

/// Compute the `Duration` from now to `sync_at`, clamped to zero for
/// past targets.
///
/// `Timestamp` wraps `time::OffsetDateTime`; the subtraction produces
/// a `time::Duration`, which we convert to `std::time::Duration` via
/// `try_into`. A negative result (target in the past) clamps to zero.
fn time_until(sync_at: Timestamp) -> Duration {
    let now = Timestamp::now();
    let delta = sync_at.into_inner() - now.into_inner();
    delta.try_into().unwrap_or(Duration::ZERO)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use time::OffsetDateTime;
    use tokio::net::UdpSocket;

    use super::*;

    fn loopback_v4_zero() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    fn timestamp_at(now: OffsetDateTime, offset: time::Duration) -> Timestamp {
        Timestamp::from_offset_date_time(now + offset)
    }

    #[tokio::test]
    async fn empty_handshake_is_rejected() {
        let socket = UdpSocket::bind(loopback_v4_zero()).await.expect("bind");
        let outcome = simultaneous_open(&socket, loopback_v4_zero(), Timestamp::now(), &[]).await;
        assert!(matches!(outcome, Err(HolepunchError::EmptyHandshake)));
    }

    #[tokio::test]
    async fn fires_immediately_when_sync_at_is_in_the_past() {
        // Sender + receiver on loopback. Sync target is one full hour
        // in the past so the function never sleeps; we then assert
        // the bytes land on the receiver promptly.
        let sender = UdpSocket::bind(loopback_v4_zero()).await.expect("bind sender");
        let receiver = UdpSocket::bind(loopback_v4_zero()).await.expect("bind receiver");
        let receiver_addr = receiver.local_addr().expect("receiver addr");
        let past_sync = timestamp_at(OffsetDateTime::now_utc(), -time::Duration::hours(1));
        let payload: [u8; 16] = [42; 16];
        let send_outcome = simultaneous_open(&sender, receiver_addr, past_sync, &payload).await;
        assert!(send_outcome.is_ok(), "past sync_at must not error: {send_outcome:?}");
        let mut recv_buf = [0_u8; 32];
        let recv_outcome =
            tokio::time::timeout(Duration::from_millis(200), receiver.recv_from(&mut recv_buf))
                .await
                .expect("receiver got bytes within 200ms");
        let (recv_len, _src) = recv_outcome.expect("recv ok");
        assert_eq!(&recv_buf[..recv_len], &payload);
    }

    #[tokio::test]
    async fn delays_until_sync_at_when_in_the_future() {
        let sender = UdpSocket::bind(loopback_v4_zero()).await.expect("bind sender");
        let receiver = UdpSocket::bind(loopback_v4_zero()).await.expect("bind receiver");
        let receiver_addr = receiver.local_addr().expect("receiver addr");

        // Target is ~150ms in the future. We measure the actual elapsed
        // wall-clock from call → send completion and assert it is at
        // least 100ms (lower bound — tests are flaky if we go tighter).
        let future_sync =
            timestamp_at(OffsetDateTime::now_utc(), time::Duration::milliseconds(150));
        let payload: [u8; 16] = [7; 16];
        let started = std::time::Instant::now();
        simultaneous_open(&sender, receiver_addr, future_sync, &payload)
            .await
            .expect("send must succeed");
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(100),
            "expected ~150ms wait, observed {elapsed:?}",
        );
        let mut recv_buf = [0_u8; 32];
        let (recv_len, _src) =
            receiver.recv_from(&mut recv_buf).await.expect("receiver gets the punch");
        assert_eq!(&recv_buf[..recv_len], &payload);
    }
}
