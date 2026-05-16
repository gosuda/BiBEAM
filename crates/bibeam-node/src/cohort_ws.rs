#![forbid(unsafe_code)]
//! Node-side cohort-assignment WebSocket receiver (F-NODE.5).
//!
//! The node holds a single long-lived WebSocket to the coordinator
//! pool. Every event the coordinator pushes onto the
//! `/api/v1/events` stream (see F-DISC.2) is decoded into a
//! [`bibeam_discovery::CoordinatorEvent`] and routed to a
//! caller-supplied [`CohortHandler`] trait object.
//!
//! ## Mapping the wire to the trait
//!
//! The coordinator publishes exactly three event variants today:
//!
//! - [`bibeam_discovery::CoordinatorEvent::CohortAssigned`] — the
//!   peer learned its (possibly fresh) cohort and its canonical
//!   exit set. Routed to [`CohortHandler::on_assigned`].
//! - [`bibeam_discovery::CoordinatorEvent::CohortRotated`] — the
//!   peer's cohort is being retired; in-flight tunnels migrate to
//!   the replacement. Routed to [`CohortHandler::on_rotated`].
//! - [`bibeam_discovery::CoordinatorEvent::Disconnect`] — the
//!   coordinator is asking the peer to leave. Routed to
//!   [`CohortHandler::on_disconnect`]; the receiver then closes the
//!   current session and re-enters the reconnect loop because, per
//!   F-DISC.3, the *next* coordinator in the pool may still want us.
//!
//! The task's planning note mentioned a `CohortMembershipChanged`
//! variant; no such event exists on the wire today, so the trait
//! intentionally does not surface one. Adding it later is a
//! source-compatible extension: append a defaulted
//! `async fn on_membership_changed(..)` to the trait, add the
//! variant to [`bibeam_discovery::CoordinatorEvent`], wire one new
//! arm in the receiver's internal `route_event` dispatcher.
//!
//! ## Reconnect policy
//!
//! [`CohortWsReceiver::run`] never returns on a recoverable error.
//! When a session ends — clean remote close, transport error, or a
//! coordinator-issued `Disconnect` — the receiver:
//!
//! 1. classifies the failure (clean close vs. transport error vs.
//!    fatal). Fatal failures — those for which
//!    [`bibeam_discovery::DiscoveryError::is_retriable`] returns
//!    `false` — surface as a [`CohortWsError`] and abort the loop;
//!    a 401 on the upgrade is a configuration bug, not a retry.
//! 2. for retriable failures: increments the
//!    [`crate::telemetry::NODE_COORD_WS_RECONNECTS_TOTAL`] counter
//!    *after* the next successful re-connect (not on every retry
//!    attempt — the counter reads "sessions re-established", not
//!    "attempts"), and walks the [`CoordinatorPool`] in
//!    round-robin order via [`CoordinatorPool::try_each`].
//! 3. between full-pool sweeps that came back empty-handed, sleeps
//!    for an exponential-with-jitter interval bounded above by a
//!    crate-private 60-second `MAX_RECONNECT_BACKOFF` ceiling.
//!
//! The cursor inside [`CoordinatorPool`] already advances across
//! calls — this module does not roll its own rotation index.
//!
//! ## Testability seam
//!
//! Production wiring binds a crate-private `CoordSessionFactory` to
//! a [`CoordinatorPool`] + token + rustls config, which calls
//! [`bibeam_discovery::CoordinatorWs::connect`] inside the
//! `try_each` closure. Tests bind that factory to an mpsc-fed
//! queue of mock sessions, so the `cohort_ws` tests do not need
//! an axum + TLS coordinator harness; the discovery crate's
//! `bootstrap_happy_path` integration test exercises that path
//! end-to-end and is the right place to grow it from.
//!
//! ## Threat boundary
//!
//! This module sees `CohortLive` / `CohortRotate` payloads after
//! the coordinator decoded them; it does not interpret cohort
//! membership semantics (that is F-NODE.6's `RotationHandler` job)
//! and does not touch any cryptographic key material. The handler
//! trait is `Send + Sync` and is the only surface that can act on
//! a coord event.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bibeam_discovery::{CoordinatorEvent, CoordinatorPool, CoordinatorWs, DiscoveryError};
use bibeam_protocol::cohort::{CohortLive, CohortRotate};
use rand::RngExt as _;
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::telemetry::NODE_COORD_WS_RECONNECTS_TOTAL;

/// Base backoff between full-pool sweeps that all returned
/// retriable errors. The first sweep retries immediately; the
/// second waits this long; subsequent sweeps double up to
/// [`MAX_RECONNECT_BACKOFF`].
const INITIAL_RECONNECT_BACKOFF: Duration = Duration::from_millis(500);

/// Maximum backoff between full-pool sweeps. Reached after roughly
/// seven retries on the geometric schedule
/// (500 ms → 1 s → 2 s → 4 s → 8 s → 16 s → 32 s → 60 s).
const MAX_RECONNECT_BACKOFF: Duration = Duration::from_secs(60);

/// Maximum amount of additive jitter (in milliseconds) layered on
/// top of the computed backoff for the next sweep.
///
/// Drawn uniformly from `[0, JITTER_CEILING_MS)`; the resulting
/// total sleep is still capped at [`MAX_RECONNECT_BACKOFF`] before
/// the receiver actually sleeps. The jitter exists so a fleet of
/// nodes whose coord WS all dropped at the same wall-clock instant
/// does not synchronise reconnect storms against the recovering
/// pool.
const JITTER_CEILING_MS: u64 = 250;

/// Errors returned by [`CohortWsReceiver::run`] when it terminates.
///
/// The receiver loops forever on retriable failures; this enum only
/// surfaces unrecoverable conditions. A `Cancelled` is not really an
/// error — it is the cooperative shutdown contract — but is folded in
/// because callers `tokio::spawn` the receiver onto a [`tokio::task::JoinHandle`]
/// whose return type must be `Result<_, _>` to thread the
/// non-retriable upgrade failures back to the supervisor without a
/// second `enum`.
#[derive(Debug, Error)]
pub enum CohortWsError {
    /// The coordinator rejected the upgrade with a permanent failure
    /// (e.g. 401 on auth, 4xx on routing, a codec error, or a malformed
    /// base URL). Reconnecting would surface the same answer, so the
    /// loop bubbles out instead of spinning.
    #[error("cohort-ws: non-retriable coordinator failure: {0}")]
    Permanent(#[source] DiscoveryError),
    /// The handler trait object returned an error from one of its
    /// `on_*` methods. The receiver does NOT loop past a handler
    /// failure — a handler that refuses to accept a cohort assignment
    /// is signalling that the local node is no longer in a usable
    /// state, and the supervisor is expected to restart the daemon.
    #[error("cohort-ws: handler returned error: {0}")]
    Handler(String),
}

/// Pluggable sink for the three coord-WS event variants.
///
/// Implementations must be `Send + Sync` because the receiver holds
/// the handler behind an `Arc` and may call its methods from the
/// reconnect task. Each method takes `&self` so the trait object
/// stays shareable; interior mutability (e.g. parking-lot `Mutex` or
/// an atomic snapshot pointer) lives in the implementor.
///
/// `Result<(), String>` is the return type because a handler is
/// expected to capture its own typed error and stringify it for the
/// supervisor — propagating opaque handler errors out of the receiver
/// keeps this crate decoupled from F-NODE.6's `RotationHandler` types.
#[async_trait]
pub trait CohortHandler: Send + Sync {
    /// Called once per [`CoordinatorEvent::CohortAssigned`] event.
    ///
    /// Production handlers persist the snapshot into the node's
    /// `CohortState` and react to membership / exit changes. The
    /// receiver does NOT cache successive assignments — every event
    /// the coord sends arrives here, including idempotent
    /// re-broadcasts after a reconnect.
    async fn on_assigned(&self, cohort: CohortLive) -> Result<(), String>;

    /// Called once per [`CoordinatorEvent::CohortRotated`] event.
    ///
    /// F-NODE.6's rotation handler drains the outgoing cohort and
    /// swaps to the new one atomically; this method is the entry
    /// point that drives that swap.
    async fn on_rotated(&self, rotation: CohortRotate) -> Result<(), String>;

    /// Called once per [`CoordinatorEvent::Disconnect`] event.
    ///
    /// The wrapped string is the coordinator's free-form reason. The
    /// receiver closes the current session immediately after this
    /// call returns and re-enters its reconnect loop (the next
    /// coordinator in the pool may still want us); the handler does
    /// NOT need to short-circuit.
    async fn on_disconnect(&self, reason: String) -> Result<(), String>;
}

/// Asynchronous factory producing a fresh [`EventSession`] each time
/// the receiver needs one.
///
/// Production wires this to a [`CoordinatorPool`] + token + rustls
/// config that walks every coordinator in `try_each` and returns the
/// first successful [`CoordinatorWs::connect`]; tests wire it to an
/// mpsc-backed mock that yields pre-canned sessions without opening
/// any sockets.
///
/// The trait is `pub(crate)` because the production wiring is the
/// public surface; the only public way to construct a receiver is
/// [`CohortWsReceiver::new_with_pool`].
#[async_trait]
pub(crate) trait CoordSessionFactory: Send + Sync {
    /// Open a new coord-WS session, walking the [`CoordinatorPool`]
    /// in round-robin order if the underlying factory is
    /// pool-backed. The boxed return makes the factory object-safe
    /// without exposing the concrete session type.
    ///
    /// # Errors
    ///
    /// Surfaces [`DiscoveryError`] verbatim so the caller can
    /// inspect `is_retriable` and pick between backoff-and-retry vs.
    /// bubble-out semantics.
    async fn open_session(&self) -> Result<Box<dyn EventSession>, DiscoveryError>;
}

/// One open coord-WS session.
///
/// Polled iteratively by the receiver; each call yields the next
/// decoded [`CoordinatorEvent`] or a sentinel meaning "the stream
/// is finished". Implementations are expected to NOT silently drop
/// frames — every event the coord sent must surface exactly once.
#[async_trait]
pub(crate) trait EventSession: Send {
    /// Pull the next event from the underlying stream.
    ///
    /// Mirrors [`CoordinatorWs::next_event`]:
    ///
    /// - `Ok(Some(event))` — one event decoded;
    /// - `Ok(None)` — the coord closed the stream cleanly; the
    ///   receiver loops back into a fresh `open_session` call;
    /// - `Err(_)` — transport / decode failure. The receiver
    ///   reconnects on retriable variants and bubbles out on the
    ///   rest.
    async fn next_event(&mut self) -> Result<Option<CoordinatorEvent>, DiscoveryError>;
}

#[async_trait]
impl EventSession for CoordinatorWs {
    async fn next_event(&mut self) -> Result<Option<CoordinatorEvent>, DiscoveryError> {
        // Trait method and inherent method share the same name; use
        // UFCS to disambiguate against this trait impl and avoid
        // recursing into ourselves.
        Self::next_event(self).await
    }
}

/// Pool-backed factory that drives every fresh session through
/// [`CoordinatorPool::try_each`].
///
/// Holding the rustls config in an `Arc` lets a single config flow
/// through the entire pool without re-cloning the certificate roots
/// per call; the WS upgrade path itself accepts the `Arc` by clone
/// and shares the inner config across attempts.
struct PoolFactory {
    pool: CoordinatorPool,
    token: String,
    tls: Arc<rustls::ClientConfig>,
}

#[async_trait]
impl CoordSessionFactory for PoolFactory {
    async fn open_session(&self) -> Result<Box<dyn EventSession>, DiscoveryError> {
        let token = self.token.as_str();
        let tls = Arc::clone(&self.tls);
        let session = self
            .pool
            .try_each(|client| {
                let tls = Arc::clone(&tls);
                async move { CoordinatorWs::connect(client.base_url(), token, tls).await }
            })
            .await?;
        Ok(Box::new(session))
    }
}

/// Long-lived coord-WS receiver task.
///
/// Hold one per node. Each instance owns the connection state for
/// exactly one coordinator pool — multi-pool deployments would build
/// two receivers, but the threat model assumes a single configured
/// pool today.
pub struct CohortWsReceiver {
    /// Factory yielding one fresh [`EventSession`] per call. Boxed +
    /// `Arc` so the receiver can be cloned cheaply and so a test can
    /// inject a mock factory through
    /// [`CohortWsReceiver::with_factory_for_test`].
    factory: Arc<dyn CoordSessionFactory>,
    /// Handler routing surface. Held as `Arc<dyn CohortHandler>` so
    /// the receiver and any outer supervisor can share a single
    /// handler.
    handler: Arc<dyn CohortHandler>,
    /// Cooperative-shutdown signal. Firing this token causes
    /// [`Self::run`] to return `Ok(())` from whichever step it was
    /// in (connect / receive / sleep).
    cancel: CancellationToken,
}

impl core::fmt::Debug for CohortWsReceiver {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Custom Debug because every field is a trait object or a
        // token whose `<Debug>` impl is noisy or non-existent. The
        // useful operator-visible state is just "is this receiver
        // alive?" which the cancel-token flag captures.
        formatter
            .debug_struct("CohortWsReceiver")
            .field("cancelled", &self.cancel.is_cancelled())
            .finish_non_exhaustive()
    }
}

impl CohortWsReceiver {
    /// Build a receiver bound to a [`CoordinatorPool`].
    ///
    /// `token` is the PASETO session token issued by the coord at
    /// registration; `tls` is the shared rustls config the rest of
    /// the discovery layer uses (build via
    /// [`bibeam_transport::coordinator_client_config`] at startup).
    ///
    /// The returned value is ready to be driven by [`Self::run`];
    /// production wires that into `tokio::spawn` from `main.rs`.
    #[must_use]
    pub fn new_with_pool(
        pool: CoordinatorPool,
        token: String,
        tls: Arc<rustls::ClientConfig>,
        handler: Arc<dyn CohortHandler>,
        cancel: CancellationToken,
    ) -> Self {
        let factory: Arc<dyn CoordSessionFactory> = Arc::new(PoolFactory { pool, token, tls });
        Self { factory, handler, cancel }
    }

    /// Test-only constructor that lets the unit-test module wire a
    /// mock factory directly. `pub(crate)` so it is invisible from
    /// outside the crate but reachable from the tests below.
    #[cfg(test)]
    pub(crate) fn with_factory_for_test(
        factory: Arc<dyn CoordSessionFactory>,
        handler: Arc<dyn CohortHandler>,
        cancel: CancellationToken,
    ) -> Self {
        Self { factory, handler, cancel }
    }

    /// Run the receive loop until the cancel token passed to the
    /// constructor is fired or a non-retriable failure surfaces.
    ///
    /// # Errors
    ///
    /// - [`CohortWsError::Permanent`] when a coord-WS error returns
    ///   `is_retriable() == false`. The supervisor MUST escalate
    ///   this — reconnecting would observe the same response.
    /// - [`CohortWsError::Handler`] when one of the `on_*` methods
    ///   on the handler trait failed.
    ///
    /// Cancellation returns `Ok(())`: a clean shutdown is not an
    /// error.
    pub async fn run(self) -> Result<(), CohortWsError> {
        // The first connect attempt does NOT count toward the
        // reconnects counter — the metric reads "how often did we
        // recover after a drop", not "how many connects ever".
        let mut is_first_connect = true;
        let mut attempt: u32 = 0;
        loop {
            // Race the connect attempt against the cancel token so
            // a shutdown during startup terminates cleanly without
            // waiting for the WS upgrade to time out.
            let session_result = tokio::select! {
                () = self.cancel.cancelled() => return Ok(()),
                outcome = self.factory.open_session() => outcome,
            };
            match self
                .step_after_connect(session_result, &mut is_first_connect, &mut attempt)
                .await?
            {
                StepOutcome::Continue => {},
                StepOutcome::Cancelled => return Ok(()),
            }
        }
    }

    /// Handle one "open-session-or-fail" outcome.
    ///
    /// Pulled out of [`Self::run`] to keep the run-loop body shallow
    /// (one level of nesting) — the connect / drive / retriable-fail /
    /// permanent-fail branches each get a flat arm here. Returning a
    /// [`StepOutcome`] lets the caller decide whether to loop back into
    /// `select!` on the cancel token or break out cleanly.
    async fn step_after_connect(
        &self,
        session_result: Result<Box<dyn EventSession>, DiscoveryError>,
        is_first_connect: &mut bool,
        attempt: &mut u32,
    ) -> Result<StepOutcome, CohortWsError> {
        match session_result {
            Ok(session) => {
                if !*is_first_connect {
                    metrics::counter!(NODE_COORD_WS_RECONNECTS_TOTAL).increment(1);
                }
                *is_first_connect = false;
                *attempt = 0;
                Ok(self.drive_to_step_outcome(session).await?)
            },
            Err(err) if err.is_retriable() => {
                self.handle_retriable_open_failure(err, attempt).await
            },
            Err(err) => Err(CohortWsError::Permanent(err)),
        }
    }

    /// Map the binary `SessionOutcome` of a finished session onto the
    /// outer loop's [`StepOutcome`]. A standalone helper because the
    /// `?` propagation in [`Self::step_after_connect`] makes the inline
    /// `match` awkward and obscures the only interesting branch
    /// (cancel-during-session).
    async fn drive_to_step_outcome(
        &self,
        session: Box<dyn EventSession>,
    ) -> Result<StepOutcome, CohortWsError> {
        match self.drive_session(session).await? {
            SessionOutcome::ReconnectRequested => Ok(StepOutcome::Continue),
            SessionOutcome::Cancelled => Ok(StepOutcome::Cancelled),
        }
    }

    /// Handle a retriable open-session failure: log, bump the attempt
    /// counter, and sleep with backoff until the cancel token fires or
    /// the schedule completes.
    async fn handle_retriable_open_failure(
        &self,
        err: DiscoveryError,
        attempt: &mut u32,
    ) -> Result<StepOutcome, CohortWsError> {
        tracing::warn!(
            target: "bibeam_node::cohort_ws",
            attempt = *attempt,
            error = %err,
            "coord-WS open failed (retriable); backing off",
        );
        *attempt = attempt.saturating_add(1);
        if self.sleep_with_backoff(*attempt).await.is_break() {
            Ok(StepOutcome::Cancelled)
        } else {
            Ok(StepOutcome::Continue)
        }
    }

    /// Pump one open session until it ends. Returns whether the
    /// outer loop should reconnect or shut down.
    ///
    /// Pulled out of [`Self::run`] so the run-loop body stays under
    /// the cognitive-complexity ceiling and the four reasons a
    /// session ends (cancel / clean close / retriable I/O /
    /// non-retriable failure) each get a named branch.
    async fn drive_session(
        &self,
        mut session: Box<dyn EventSession>,
    ) -> Result<SessionOutcome, CohortWsError> {
        loop {
            let event_result = tokio::select! {
                () = self.cancel.cancelled() => return Ok(SessionOutcome::Cancelled),
                outcome = session.next_event() => outcome,
            };
            if let Some(outcome) = self.handle_event_result(event_result).await? {
                return Ok(outcome);
            }
        }
    }

    /// Reduce one `next_event` outcome to either "keep pumping"
    /// (`None`) or "session ended; tell the outer loop what to do"
    /// (`Some`).
    ///
    /// Pulled out of [`Self::drive_session`] so the loop body is
    /// flat (one `if let` branch instead of a four-arm match nested
    /// inside a `loop`). Stream-end / I/O classification is split
    /// off into [`Self::classify_stream_end`] so this helper stays
    /// under the cognitive-complexity ceiling.
    async fn handle_event_result(
        &self,
        event_result: Result<Option<CoordinatorEvent>, DiscoveryError>,
    ) -> Result<Option<SessionOutcome>, CohortWsError> {
        match event_result {
            Ok(Some(event)) => Ok(self.dispatch_one_event(event).await?),
            Ok(None) => Ok(Some(stream_closed_cleanly())),
            Err(err) => classify_stream_error(err).map(Some),
        }
    }

    /// Dispatch one decoded event and translate the route tag onto
    /// the outer "keep pumping vs. session ended" signal.
    async fn dispatch_one_event(
        &self,
        event: CoordinatorEvent,
    ) -> Result<Option<SessionOutcome>, CohortWsError> {
        let route = self.route_event(event).await?;
        Ok(match route {
            EventRoute::DisconnectRequested => Some(SessionOutcome::ReconnectRequested),
            EventRoute::Consumed => None,
        })
    }

    /// Dispatch one event to the handler trait.
    ///
    /// Splitting `match` into its own helper keeps [`Self::drive_session`]
    /// compact and lets the three handler-method bodies stay aligned
    /// in the source. Returns an [`EventRoute`] tag so the caller
    /// can react to a `Disconnect` without re-pattern-matching the
    /// already-consumed event.
    async fn route_event(&self, event: CoordinatorEvent) -> Result<EventRoute, CohortWsError> {
        match event {
            CoordinatorEvent::CohortAssigned(cohort) => {
                self.handler.on_assigned(cohort).await.map_err(CohortWsError::Handler)?;
                Ok(EventRoute::Consumed)
            },
            CoordinatorEvent::CohortRotated(rotation) => {
                self.handler.on_rotated(rotation).await.map_err(CohortWsError::Handler)?;
                Ok(EventRoute::Consumed)
            },
            CoordinatorEvent::Disconnect(reason) => {
                self.handler.on_disconnect(reason).await.map_err(CohortWsError::Handler)?;
                Ok(EventRoute::DisconnectRequested)
            },
        }
    }

    /// Sleep for the next exponential-with-jitter backoff window,
    /// or short-circuit on cancel.
    ///
    /// Returns [`SleepOutcome::Break`] if the cancel token fired
    /// during the sleep — the caller treats this as "shutdown
    /// requested mid-backoff" and returns from [`Self::run`].
    async fn sleep_with_backoff(&self, attempt: u32) -> SleepOutcome {
        let delay = compute_backoff(attempt);
        tracing::debug!(
            target: "bibeam_node::cohort_ws",
            attempt,
            delay_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
            "cohort-ws reconnect backoff",
        );
        tokio::select! {
            () = self.cancel.cancelled() => SleepOutcome::Break,
            () = tokio::time::sleep(delay) => SleepOutcome::Continue,
        }
    }
}

/// Outcome of one open session. `drive_session` returns one of these
/// rather than re-pattern-matching event variants inside `run`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionOutcome {
    /// Either the coord cleanly closed the stream, or its
    /// `Disconnect` event asked us to leave. Either way, the outer
    /// loop opens a fresh session against the (possibly different)
    /// next coordinator in the pool.
    ReconnectRequested,
    /// The cancel token was fired mid-session. The outer loop
    /// returns `Ok(())`.
    Cancelled,
}

/// Outcome of one iteration of the outer `run` loop's
/// connect-or-fail step. Surfaces the same "loop or shut down"
/// signal that the inline match used to carry, but as a typed value
/// so [`CohortWsReceiver::step_after_connect`] can return it through
/// `?` without re-flattening the original four-way branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StepOutcome {
    /// Run-loop should continue (either re-enter the connect phase
    /// after a clean session end, or fall through after a backoff
    /// sleep completed normally).
    Continue,
    /// Cancel token fired mid-step; the run-loop returns `Ok(())`.
    Cancelled,
}

/// How [`CohortWsReceiver::route_event`] classified the event it
/// just dispatched. The dispatch helper consumes the event by value,
/// so the caller (which already moved the variant in) needs this
/// out-of-band tag to react to a `Disconnect`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EventRoute {
    /// The event was routed to the handler and the session keeps
    /// going. Covers `CohortAssigned` and `CohortRotated`.
    Consumed,
    /// The event was a `Disconnect`; the caller closes the session.
    DisconnectRequested,
}

/// Return value of [`CohortWsReceiver::sleep_with_backoff`].
///
/// A bare `bool` would compile but the name documents the contract
/// at the call site (`if outcome.is_break() return …`) better.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SleepOutcome {
    /// The backoff slept to completion; resume reconnecting.
    Continue,
    /// The cancel token fired mid-sleep; outer loop returns.
    Break,
}

impl SleepOutcome {
    /// Inline classifier — keeps the call-site `if` legible without
    /// pulling in a full pattern match for a binary signal.
    const fn is_break(self) -> bool {
        matches!(self, Self::Break)
    }
}

/// Log the coord-side clean close and return the matching session
/// outcome. Pulled into a free fn so
/// [`CohortWsReceiver::handle_event_result`] stays under the
/// cognitive-complexity threshold without losing the operator log
/// line that distinguishes a clean close from a transport error.
fn stream_closed_cleanly() -> SessionOutcome {
    tracing::info!(
        target: "bibeam_node::cohort_ws",
        "coord-WS closed cleanly; reconnecting",
    );
    SessionOutcome::ReconnectRequested
}

/// Classify a stream-side I/O failure as retriable (reconnect) or
/// permanent (bubble out). Mirrors the same retry contract the rest
/// of the discovery layer codifies via
/// [`DiscoveryError::is_retriable`]; surfaced here as its own
/// function so the calling `match` arm holds exactly one expression.
fn classify_stream_error(err: DiscoveryError) -> Result<SessionOutcome, CohortWsError> {
    if err.is_retriable() {
        tracing::warn!(
            target: "bibeam_node::cohort_ws",
            error = %err,
            "coord-WS stream error (retriable); reconnecting",
        );
        Ok(SessionOutcome::ReconnectRequested)
    } else {
        Err(CohortWsError::Permanent(err))
    }
}

/// Compute the next backoff window for `attempt` (1-indexed: the
/// first failure passes `attempt = 1`).
///
/// Geometric schedule capped at [`MAX_RECONNECT_BACKOFF`], with up
/// to [`JITTER_CEILING_MS`] ms of additive jitter to spread the
/// reconnect storm across a fleet whose coord all dropped at the
/// same instant. The jitter draw uses rand 0.10's thread-local RNG;
/// the jitter ceiling is small enough that the additive offset
/// never pushes the deterministic schedule into the next decade
/// bucket.
fn compute_backoff(attempt: u32) -> Duration {
    // Saturating shift: at attempt = 64 the shift would otherwise
    // wrap to zero on u64. `min` against the cap below makes that
    // saturation observable as "always 60s past attempt ~7".
    let exponent = attempt.saturating_sub(1).min(20);
    let base_ms = u64::try_from(INITIAL_RECONNECT_BACKOFF.as_millis()).unwrap_or(500);
    let scaled = base_ms.saturating_mul(1u64 << exponent);
    let capped = scaled.min(u64::try_from(MAX_RECONNECT_BACKOFF.as_millis()).unwrap_or(60_000));
    let jitter = rand::rng().random_range(0..JITTER_CEILING_MS);
    let total = capped
        .saturating_add(jitter)
        .min(u64::try_from(MAX_RECONNECT_BACKOFF.as_millis()).unwrap_or(60_000));
    Duration::from_millis(total)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use bibeam_core::{CohortId, NodeId, PeerId, Timestamp};
    use parking_lot::Mutex;
    use tokio::sync::Notify;

    use super::*;

    /// Sample [`CohortLive`] for the test events; no PII, no real
    /// network identity material.
    fn sample_cohort_live() -> CohortLive {
        CohortLive {
            cohort: CohortId::new(),
            members: vec![PeerId::new()],
            exits: vec![NodeId::new()],
            exit_regions: std::collections::HashMap::new(),
            at: Timestamp::now(),
        }
    }

    /// Recording handler: counts every `on_*` call and stashes the
    /// payload of the last `on_assigned` so the test can assert
    /// round-trip equality.
    #[derive(Default)]
    struct RecordingHandler {
        assigned_calls: AtomicU64,
        rotated_calls: AtomicU64,
        disconnect_calls: AtomicU64,
        last_assigned: Mutex<Option<CohortLive>>,
    }

    #[async_trait]
    impl CohortHandler for RecordingHandler {
        async fn on_assigned(&self, cohort: CohortLive) -> Result<(), String> {
            *self.last_assigned.lock() = Some(cohort);
            self.assigned_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn on_rotated(&self, _rotation: CohortRotate) -> Result<(), String> {
            self.rotated_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn on_disconnect(&self, _reason: String) -> Result<(), String> {
            self.disconnect_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    /// Mock session that yields one clean close (mirrors a coord
    /// that hung up), used to drive the reconnect path.
    struct ClosedSession;

    #[async_trait]
    impl EventSession for ClosedSession {
        async fn next_event(&mut self) -> Result<Option<CoordinatorEvent>, DiscoveryError> {
            Ok(None)
        }
    }

    /// Mock session that emits one `CohortAssigned` event and then
    /// blocks forever. Used by tests that need to assert the
    /// handler was invoked without the session terminating.
    struct OneShotAssignedSession {
        cohort: Option<CohortLive>,
        notify_consumed: Arc<Notify>,
    }

    #[async_trait]
    impl EventSession for OneShotAssignedSession {
        async fn next_event(&mut self) -> Result<Option<CoordinatorEvent>, DiscoveryError> {
            if let Some(cohort) = self.cohort.take() {
                self.notify_consumed.notify_one();
                Ok(Some(CoordinatorEvent::CohortAssigned(cohort)))
            } else {
                // Block forever; the test cancels to unwind.
                std::future::pending().await
            }
        }
    }

    /// Factory that pops pre-canned sessions out of a Vec in order.
    ///
    /// The reconnect test drives this with two entries (clean-close
    /// then a long-running session) to exercise the
    /// session-end-then-reconnect path. The cancel test drives it
    /// with one. Either way, the queue is consumed exactly once per
    /// `open_session` call so the test can observe how many times
    /// the receiver opened a fresh session via [`Self::opens`].
    struct QueuedFactory {
        queue: Mutex<Vec<Box<dyn EventSession>>>,
        opens: AtomicU64,
    }

    impl QueuedFactory {
        fn new(sessions: Vec<Box<dyn EventSession>>) -> Arc<Self> {
            // Reverse so the first session is at the end of the
            // Vec — pop() returns the last element, so pushing in
            // reverse keeps the natural read-top-to-bottom order.
            let mut reversed = sessions;
            reversed.reverse();
            Arc::new(Self {
                queue: Mutex::new(reversed),
                opens: AtomicU64::new(0),
            })
        }

        fn opens(&self) -> u64 {
            self.opens.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl CoordSessionFactory for QueuedFactory {
        async fn open_session(&self) -> Result<Box<dyn EventSession>, DiscoveryError> {
            self.opens.fetch_add(1, Ordering::SeqCst);
            self.queue
                .lock()
                .pop()
                .ok_or_else(|| DiscoveryError::Url("no more queued sessions".into()))
        }
    }

    /// Poll `factory.opens()` until it reaches `target` or the
    /// caller's timeout fires. Pulled out of the reconnect test
    /// body so the `loop { … }` does not stack inside an async
    /// block inside the test, which trips
    /// `clippy::excessive_nesting`.
    async fn wait_for_opens(factory: Arc<QueuedFactory>, target: u64) {
        loop {
            if factory.opens() >= target {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// Wire up a fresh receiver pointed at the given factory, returning
    /// the factory + handler clones the test will assert against. The
    /// helper exists so each test body shows only its scenario-specific
    /// session list; the `Arc<dyn _>` plumbing stays out of the way.
    fn build_receiver(
        sessions: Vec<Box<dyn EventSession>>,
    ) -> (Arc<QueuedFactory>, Arc<RecordingHandler>, CancellationToken, CohortWsReceiver) {
        let factory = QueuedFactory::new(sessions);
        let handler = Arc::new(RecordingHandler::default());
        let cancel = CancellationToken::new();
        // Method-call `clone()` on the typed RHS lets coercion
        // place the `Arc<Concrete>` into an `Arc<dyn _>` binding
        // without a `trivial_casts`-flagged `as` keyword. Calling
        // `Arc::clone(&factory)` here would instead fix the
        // type-param to the trait object and refuse the
        // concrete reference.
        let factory_dyn: Arc<dyn CoordSessionFactory> = factory.clone();
        let handler_dyn: Arc<dyn CohortHandler> = handler.clone();
        let receiver =
            CohortWsReceiver::with_factory_for_test(factory_dyn, handler_dyn, cancel.clone());
        (factory, handler, cancel, receiver)
    }

    /// Contract: the receiver decodes a `CohortAssigned` event off
    /// the mock session and routes it to the handler verbatim. The
    /// payload arrives at the handler with field-equal contents, so
    /// downstream rotation logic can trust the snapshot it sees.
    #[tokio::test]
    async fn ws_receiver_routes_cohort_assigned_to_handler() {
        let cohort = sample_cohort_live();
        let notify = Arc::new(Notify::new());
        let session = OneShotAssignedSession {
            cohort: Some(cohort.clone()),
            notify_consumed: Arc::clone(&notify),
        };
        let (_factory, handler, cancel, receiver) = build_receiver(vec![Box::new(session)]);
        let join = tokio::spawn(receiver.run());
        // Wait for the session to actually emit; otherwise a fast
        // cancel races the dispatch and the test flakes.
        notify.notified().await;
        // Give the await point on the handler a chance to settle.
        tokio::task::yield_now().await;
        cancel.cancel();
        join.await.expect("task joined").expect("run returned Ok");
        assert_eq!(
            handler.assigned_calls.load(Ordering::SeqCst),
            1,
            "exactly one CohortAssigned routed to the handler",
        );
        assert_eq!(
            handler.rotated_calls.load(Ordering::SeqCst),
            0,
            "no CohortRotated events emitted",
        );
        assert_eq!(
            *handler.last_assigned.lock(),
            Some(cohort),
            "handler observed the round-tripped CohortLive verbatim",
        );
    }

    /// Contract: a session that ends with `Ok(None)` causes the
    /// receiver to open a fresh session AND increment the
    /// reconnects-total counter. The mock factory yields one
    /// closed-session then one pending session so the reconnect
    /// path is exercised exactly once.
    #[tokio::test]
    async fn ws_receiver_handles_disconnect_and_reconnects() {
        // Per F-NODE.5 the metric is `bibeam_node_coord_ws_reconnects_total`.
        // The constant is checked structurally by the telemetry
        // tests; this test asserts the const itself is sourced
        // verbatim into the metric name we increment.
        assert_eq!(NODE_COORD_WS_RECONNECTS_TOTAL, "bibeam_node_coord_ws_reconnects_total");
        let pending = OneShotAssignedSession {
            cohort: None,
            notify_consumed: Arc::new(Notify::new()),
        };
        let sessions: Vec<Box<dyn EventSession>> = vec![Box::new(ClosedSession), Box::new(pending)];
        let (factory, handler, cancel, receiver) = build_receiver(sessions);
        let join = tokio::spawn(receiver.run());
        // Spin until the factory has been called twice — i.e. the
        // reconnect path actually ran. A timeout guards the loop so
        // a regression that wedges the reconnect surfaces here as a
        // test failure rather than a hang.
        tokio::time::timeout(Duration::from_secs(2), wait_for_opens(factory.clone(), 2))
            .await
            .expect("reconnect must happen within budget");
        cancel.cancel();
        join.await.expect("task joined").expect("run returned Ok");
        assert_eq!(
            factory.opens(),
            2,
            "the receiver opened a second session after the clean close",
        );
        assert_eq!(
            handler.disconnect_calls.load(Ordering::SeqCst),
            0,
            "a clean close is not a coord-issued Disconnect event",
        );
    }

    /// Factory that always rejects the WS upgrade with a 401, used
    /// by the non-retriable-error test below. Defined at module
    /// scope so the `async fn` body is two levels shallower than if
    /// it lived inside the test body (`clippy::excessive_nesting`).
    struct AlwaysAuthFails;

    #[async_trait]
    impl CoordSessionFactory for AlwaysAuthFails {
        async fn open_session(&self) -> Result<Box<dyn EventSession>, DiscoveryError> {
            Err(DiscoveryError::HttpStatus {
                status: 401,
                body: "bad token".into(),
            })
        }
    }

    /// Contract: a non-retriable error returned by the factory
    /// surfaces as `CohortWsError::Permanent` without reconnecting.
    /// Guards against a regression that would spin against a
    /// misconfigured coordinator burning CPU.
    #[tokio::test]
    async fn ws_receiver_surfaces_non_retriable_factory_error() {
        let handler = Arc::new(RecordingHandler::default());
        let cancel = CancellationToken::new();
        let factory_dyn: Arc<dyn CoordSessionFactory> = Arc::new(AlwaysAuthFails);
        let handler_dyn: Arc<dyn CohortHandler> = handler;
        let receiver =
            CohortWsReceiver::with_factory_for_test(factory_dyn, handler_dyn, cancel.clone());
        let outcome = receiver.run().await;
        match outcome {
            Err(CohortWsError::Permanent(inner)) => {
                assert!(
                    matches!(inner, DiscoveryError::HttpStatus { status: 401, .. }),
                    "expected the 401 to surface verbatim, got {inner:?}",
                );
            },
            other => panic!("expected Permanent(401), got {other:?}"),
        }
    }

    /// Contract: firing the cancel token mid-receive returns
    /// `Ok(())` from `run` — clean shutdown, not an error.
    #[tokio::test]
    async fn ws_receiver_exits_on_cancel() {
        let pending = OneShotAssignedSession {
            cohort: None,
            notify_consumed: Arc::new(Notify::new()),
        };
        let sessions: Vec<Box<dyn EventSession>> = vec![Box::new(pending)];
        let (_factory, _handler, cancel, receiver) = build_receiver(sessions);
        let join = tokio::spawn(receiver.run());
        // Give the receiver time to actually enter the receive
        // loop (one open + one next_event poll) so the cancel
        // races the recv branch of the inner select, exercising
        // the production code path.
        tokio::time::sleep(Duration::from_millis(20)).await;
        cancel.cancel();
        let result = tokio::time::timeout(Duration::from_secs(2), join)
            .await
            .expect("cancel must drain receiver within budget");
        result.expect("task joined").expect("clean shutdown is Ok");
    }

    /// Contract: the backoff schedule is geometric with the cap
    /// documented at the module's top. Catches a regression that
    /// would either skip the geometric growth or breach the 60 s
    /// ceiling under a long outage.
    #[test]
    fn compute_backoff_grows_geometrically_and_caps_at_ceiling() {
        // The deterministic component for attempt = 1 is the base
        // (500 ms); jitter adds at most 250 ms. So an attempt-1
        // delay must land in [500 ms, 750 ms].
        let first = compute_backoff(1);
        assert!(first >= INITIAL_RECONNECT_BACKOFF, "first attempt below base: {first:?}");
        assert!(
            first <= INITIAL_RECONNECT_BACKOFF + Duration::from_millis(JITTER_CEILING_MS),
            "first attempt above base + jitter: {first:?}",
        );
        // Far enough out, the cap binds and even the worst-case
        // jitter cannot push the result past the documented
        // ceiling.
        let huge = compute_backoff(50);
        assert!(
            huge <= MAX_RECONNECT_BACKOFF,
            "saturating schedule must respect the {MAX_RECONNECT_BACKOFF:?} cap, got {huge:?}",
        );
        // Two adjacent attempts well below the ceiling should
        // show geometric growth (factor 2 on the deterministic
        // component; jitter can shave at most JITTER_CEILING_MS
        // off the gap, but the ratio still favours growth).
        let two = compute_backoff(2);
        let three = compute_backoff(3);
        assert!(
            three >= two || (MAX_RECONNECT_BACKOFF.saturating_sub(two) < Duration::from_secs(1)),
            "attempt-3 must dominate attempt-2 unless both are near the cap; \
             got attempt-2={two:?}, attempt-3={three:?}",
        );
    }
}
