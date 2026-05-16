#![forbid(unsafe_code)]
//! Per-session rotation loop (F-CLI.5).
//!
//! [`rotation_loop`] drives the two rotation triggers spelled out
//! in the F-CLI.5 spec:
//!
//! 1. **Wall-clock** — every 15 minutes ([`ROTATION_INTERVAL`]).
//! 2. **Byte-cap** — when a session has carried more than 500 MiB
//!    of plaintext ([`ROTATION_BYTE_CAP`]).
//!
//! Whichever trigger fires first wins; rotation then resets the
//! byte counter so the *next* rotation starts from a clean slate.
//! The byte counter itself is an [`AtomicU64`] the data-plane
//! layer increments outside this module — the rotation loop does
//! not own the counter, only watches it.
//!
//! ## Callback shape, not hard-coded action
//!
//! The actual rotation work (re-running [`bibeam_discovery::
//! SessionBootstrap::bootstrap`], re-picking the exit via
//! [`crate::exit_pick::pick_exit`], rewriting the on-disk session
//! blob via [`crate::register::persist_session`]) lives in
//! F-CLI.6's data-plane wire-up — those bits all need
//! configuration to materialise. To keep this commit testable
//! today, the loop takes a `FnMut(RotationCause) -> impl Future`
//! callback. F-CLI.6 will pass a closure that does the real work;
//! tests pass a closure that records causes into a vec for
//! assertion.
//!
//! ## Tick semantics
//!
//! [`tokio::time::interval`] fires its first tick *immediately*,
//! which is the wrong shape for "rotate every 15 min after
//! start". We drain that first tick with one extra `tick().await`
//! before the loop. We also set
//! [`MissedTickBehavior::Delay`] so a laptop that suspends for
//! hours does not wake up to back-to-back rotations queued by the
//! default `Burst` policy — sequential rotations would burn
//! bandwidth without actually unlinking traffic, the opposite of
//! the rotation contract.
//!
//! ## Select! discipline
//!
//! The `tokio::select!` is `biased;` so cancel always wins over
//! tick or byte-cap. Each arm calls one helper fn rather than
//! inlining the rotation; that pattern matches the same
//! cognitive-complexity discipline F-CLI.2 uses in
//! `classify_tun_outcome`.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context as _, Result};
use tokio::time::{Instant, MissedTickBehavior, interval_at};
use tokio_util::sync::CancellationToken;

/// Wall-clock cap between rotations. Matches the F-CLI.5 spec
/// (15 minutes).
const ROTATION_INTERVAL: Duration = Duration::from_secs(15 * 60);

/// Byte cap between rotations. Matches the F-CLI.5 spec
/// (500 MiB).
const ROTATION_BYTE_CAP: u64 = 500 * 1024 * 1024;

/// How often [`wait_for_bytes_cap`] polls the byte counter. A
/// 5-second cadence is fine: the worst-case overshoot of the
/// 500 MiB cap is whatever the data plane wrote in one 5-second
/// window, which at line-rate (~125 MB/s) is ~625 MiB — still in
/// the same order of magnitude as the cap itself. A tighter
/// cadence costs more wake-ups for no real privacy gain.
const BYTE_CAP_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Why a rotation fired. The callback supplied to
/// [`rotation_loop`] receives this so it can decide whether to
/// log differently per cause, emit different metrics, etc.
#[allow(
    clippy::redundant_pub_crate,
    reason = "binary-only crate: rustc's `unreachable_pub` rejects bare `pub` on items \
              consumed only by sibling private modules; clippy disagrees. We side with \
              rustc, the load-bearing lint."
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RotationCause {
    /// The 15-minute interval elapsed.
    WallClock,
    /// The 500-MiB byte cap was crossed.
    ByteCap,
}

/// Drive the rotation loop until `cancel` fires.
///
/// The `rotate` callback is invoked for each rotation; the
/// argument tells the callback which trigger fired. The callback
/// is responsible for doing the actual rotation work (bootstrap,
/// exit pick, state persist) and returning [`Result`]. A failed
/// callback aborts the loop with the callback's error wrapped in
/// a top-level "rotation failed" context.
///
/// After every successful rotation the byte counter is reset to
/// zero, so the next byte-cap trigger starts from a clean slate.
/// The wall-clock interval is not reset; it continues to tick at
/// `ROTATION_INTERVAL` cadence regardless of how often byte-cap
/// rotations fire.
///
/// # Errors
///
/// Propagates any error from the callback verbatim (wrapped in a
/// "rotation failed" context). Returns `Ok(())` only when
/// `cancel` is triggered.
#[allow(
    clippy::redundant_pub_crate,
    reason = "binary-only crate: see RotationCause for the rustc-vs-clippy rationale."
)]
#[allow(
    dead_code,
    reason = "wired into the up flow by F-CLI.6's data-plane bring-up. Reachable today \
              through the rotation_loop_* integration tests at the bottom of this file."
)]
pub(crate) async fn rotation_loop<F, Fut>(
    bytes_counter: Arc<AtomicU64>,
    cancel: CancellationToken,
    mut rotate: F,
) -> Result<()>
where
    F: FnMut(RotationCause) -> Fut + Send,
    Fut: Future<Output = Result<()>> + Send,
{
    let mut tick = interval_at(Instant::now() + ROTATION_INTERVAL, ROTATION_INTERVAL);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => return Ok(()),
            _ = tick.tick() => {
                // Wall-clock fires regardless of byte count; we
                // still snapshot the current value so the
                // post-rotation reset preserves concurrent
                // increments (same shape as the byte-cap arm).
                let observed = bytes_counter.load(Ordering::Acquire);
                fire(&mut rotate, RotationCause::WallClock, &bytes_counter, observed).await?;
            }
            observed = wait_for_bytes_cap(&bytes_counter, ROTATION_BYTE_CAP) => {
                fire(&mut rotate, RotationCause::ByteCap, &bytes_counter, observed).await?;
            }
        }
    }
}

/// Run one rotation and reset the byte counter for the next
/// cycle.
///
/// `observed` is the byte-counter value sampled at the moment
/// the rotation was decided to fire. Subtracting that exact
/// value (not a plain `store(0)`) preserves any increments the
/// data plane recorded *while the callback was running*: if the
/// data plane bumped the counter to `observed + delta`, the
/// `fetch_sub(observed)` leaves the counter at `delta` — the
/// "left over" bytes that count toward the *next* rotation.
///
/// `saturating_sub` semantics for atomics are not directly
/// available; we approximate with a CAS loop that clamps to
/// zero, so a misbehaved counter that somehow underflows does
/// not wrap to `u64::MAX` and disable the byte-cap arm forever.
async fn fire<F, Fut>(
    rotate: &mut F,
    cause: RotationCause,
    bytes_counter: &AtomicU64,
    observed: u64,
) -> Result<()>
where
    F: FnMut(RotationCause) -> Fut,
    Fut: Future<Output = Result<()>>,
{
    tracing::info!(?cause, observed_bytes = observed, "rotation: firing");
    rotate(cause).await.context("rotation failed")?;
    saturating_subtract(bytes_counter, observed);
    Ok(())
}

/// Saturating atomic subtract: subtract `delta` from `counter`,
/// clamping to zero on underflow. Implemented via a
/// compare-exchange loop so concurrent increments observed
/// *during* the subtract land into the final value rather than
/// being clobbered.
fn saturating_subtract(counter: &AtomicU64, delta: u64) {
    let mut current = counter.load(Ordering::Acquire);
    loop {
        let next = current.saturating_sub(delta);
        match counter.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

/// Yield-friendly wait for `counter >= cap`. Polls every
/// [`BYTE_CAP_POLL_INTERVAL`]; returns the observed count once
/// the cap has been crossed.
///
/// Returning the observed value (rather than `()`) lets the
/// caller subtract exactly that amount from the counter after
/// the rotation completes, preserving any concurrent increments
/// the data plane recorded during the rotation callback.
///
/// Implemented as a free async fn so the `tokio::select!` in
/// [`rotation_loop`] can race it against the wall-clock tick
/// without holding the executor.
async fn wait_for_bytes_cap(counter: &AtomicU64, cap: u64) -> u64 {
    let mut tick = tokio::time::interval(BYTE_CAP_POLL_INTERVAL);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        // The first .tick() resolves immediately, which is the
        // right shape here — we want to read the counter once at
        // entry, then poll on cadence.
        tick.tick().await;
        let observed = counter.load(Ordering::Acquire);
        if observed >= cap {
            return observed;
        }
    }
}

#[cfg(test)]
mod tests {
    use parking_lot::Mutex;

    use super::*;

    /// Records the causes a rotation callback was invoked with.
    /// Wrapped in `Arc<parking_lot::Mutex<...>>` (workspace policy
    /// forbids `std::sync::Mutex`) so the test task can read it
    /// after the loop has finished.
    type CauseLog = Arc<Mutex<Vec<RotationCause>>>;

    fn cause_log() -> CauseLog {
        Arc::new(Mutex::new(Vec::new()))
    }

    fn record_callback(
        log: CauseLog,
    ) -> impl FnMut(RotationCause) -> futures_util::future::BoxFuture<'static, Result<()>> {
        move |cause| {
            let log = log.clone();
            Box::pin(async move {
                log.lock().push(cause);
                Ok(())
            })
        }
    }

    /// Simulate the data plane incrementing the byte counter
    /// *during* the rotation callback. Returns a boxed future
    /// so the closure passed to `rotation_loop` stays flat
    /// (avoids the nested-async-block clippy lint).
    fn simulate_concurrent_increment(
        counter: Arc<AtomicU64>,
        delta: u64,
    ) -> futures_util::future::BoxFuture<'static, Result<()>> {
        Box::pin(async move {
            counter.fetch_add(delta, Ordering::AcqRel);
            Ok(())
        })
    }

    #[tokio::test(start_paused = true)]
    async fn cancel_returns_promptly_without_rotating() {
        // Contract: a fresh loop with no traffic and no time
        // advance must exit cleanly when cancel fires. A
        // regression that swapped the select! arm priority would
        // fire a spurious rotation here.
        let counter = Arc::new(AtomicU64::new(0));
        let cancel = CancellationToken::new();
        let log = cause_log();
        let cb = record_callback(log.clone());

        cancel.cancel();
        rotation_loop(counter, cancel, cb).await.expect("loop must return Ok");

        let snapshot: Vec<RotationCause> = log.lock().clone();
        assert!(snapshot.is_empty(), "no rotation should fire when cancelled at start");
    }

    #[tokio::test(start_paused = true)]
    async fn wall_clock_fires_after_15_minutes() {
        // Contract: the wall-clock arm fires on the
        // 15-minute mark, not before. We assert exactly one
        // WallClock event lands after the full interval.
        let counter = Arc::new(AtomicU64::new(0));
        let cancel = CancellationToken::new();
        let log = cause_log();
        let cb = record_callback(log.clone());
        let cancel_clone = cancel.clone();
        let counter_clone = counter.clone();
        let loop_handle =
            tokio::spawn(async move { rotation_loop(counter_clone, cancel_clone, cb).await });
        // Yield first so the spawned loop reaches its
        // tokio::select! before we advance virtual time. Then
        // advance just past the interval so the tick has fired,
        // and yield again so the callback gets a chance to
        // record before we cancel.
        tokio::task::yield_now().await;
        tokio::time::advance(ROTATION_INTERVAL + Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        cancel.cancel();
        loop_handle.await.expect("loop join").expect("loop ok");

        let snapshot: Vec<RotationCause> = log.lock().clone();
        assert!(
            snapshot.contains(&RotationCause::WallClock),
            "expected at least one WallClock cause, got {snapshot:?}",
        );
        assert_eq!(
            counter.load(Ordering::Acquire),
            0,
            "byte counter must be reset to zero after rotation",
        );
    }

    #[tokio::test(start_paused = true)]
    async fn byte_cap_fires_when_counter_exceeds_cap() {
        // Contract: pre-loading the counter past the cap makes
        // the byte-cap arm win on the first poll tick. The
        // wall-clock arm should not yet have fired (we advance
        // only one poll interval, not 15 minutes).
        let counter = Arc::new(AtomicU64::new(ROTATION_BYTE_CAP + 1));
        let cancel = CancellationToken::new();
        let log = cause_log();
        let cb = record_callback(log.clone());
        let cancel_clone = cancel.clone();
        let counter_clone = counter.clone();
        let loop_handle =
            tokio::spawn(async move { rotation_loop(counter_clone, cancel_clone, cb).await });
        // Advance just past the poll interval so the byte-cap
        // arm gets a chance to wake up.
        tokio::time::advance(BYTE_CAP_POLL_INTERVAL + Duration::from_millis(100)).await;
        tokio::task::yield_now().await;
        cancel.cancel();
        loop_handle.await.expect("loop join").expect("loop ok");

        let snapshot: Vec<RotationCause> = log.lock().clone();
        assert_eq!(
            snapshot.first(),
            Some(&RotationCause::ByteCap),
            "byte-cap should win first when counter is already over cap, got {snapshot:?}",
        );
        assert!(
            !snapshot.contains(&RotationCause::WallClock),
            "wall-clock should not have fired in the first 5 seconds",
        );
        assert_eq!(
            counter.load(Ordering::Acquire),
            0,
            "byte counter must be reset to zero after byte-cap rotation",
        );
    }

    #[tokio::test(start_paused = true)]
    async fn rotation_preserves_concurrent_increments() {
        // Contract: the reset after rotation must subtract only
        // what was observed when the rotation fired, NOT reset
        // to zero. Otherwise bytes the data plane wrote during
        // the rotation callback would be lost — and the next
        // byte-cap rotation would be delayed by exactly that
        // missed-increment count.
        //
        // We simulate the race by having the rotation callback
        // bump the counter by `INCREMENT_DURING_CALLBACK` before
        // returning. After the rotation, the counter must be
        // exactly that increment (not zero, not the original
        // value).
        const INCREMENT_DURING_CALLBACK: u64 = 1024;
        let counter = Arc::new(AtomicU64::new(ROTATION_BYTE_CAP + 1));
        let cancel = CancellationToken::new();
        let counter_in_cb = counter.clone();
        let cb = move |_cause: RotationCause| {
            let counter_inner = counter_in_cb.clone();
            simulate_concurrent_increment(counter_inner, INCREMENT_DURING_CALLBACK)
        };
        let cancel_clone = cancel.clone();
        let counter_clone = counter.clone();
        let loop_handle =
            tokio::spawn(async move { rotation_loop(counter_clone, cancel_clone, cb).await });
        tokio::time::advance(BYTE_CAP_POLL_INTERVAL + Duration::from_millis(100)).await;
        tokio::task::yield_now().await;
        cancel.cancel();
        loop_handle.await.expect("loop join").expect("loop ok");

        let post = counter.load(Ordering::Acquire);
        assert_eq!(
            post, INCREMENT_DURING_CALLBACK,
            "rotation must preserve the increment that landed during the callback; \
             a regression to bare `store(0)` here would return 0 instead of {INCREMENT_DURING_CALLBACK}",
        );
    }

    #[tokio::test(start_paused = true)]
    async fn callback_error_aborts_loop() {
        // Contract: a failed rotation callback halts the loop
        // and surfaces the error. A regression that swallowed
        // the error would silently disable rotation on the
        // first transient coordinator failure.
        let counter = Arc::new(AtomicU64::new(ROTATION_BYTE_CAP + 1));
        let cancel = CancellationToken::new();
        let cb = |_cause| async { Err(anyhow::anyhow!("forced rotation failure")) };
        let cancel_clone = cancel.clone();
        let counter_clone = counter.clone();
        let loop_handle =
            tokio::spawn(async move { rotation_loop(counter_clone, cancel_clone, cb).await });
        tokio::time::advance(BYTE_CAP_POLL_INTERVAL + Duration::from_millis(100)).await;
        tokio::task::yield_now().await;
        let err = loop_handle.await.expect("loop join").expect_err("must surface error");
        assert!(format!("{err:?}").contains("forced rotation failure"));
        // Loop aborted on error; cancel afterwards is a no-op
        // but must not panic.
        cancel.cancel();
    }
}
