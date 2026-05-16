#![forbid(unsafe_code)]
//! Random exit selection (F-CLI.4).
//!
//! [`pick_exit`] picks one [`NodeId`] uniformly at random from a
//! [`CohortLive`]'s `exits` set. The CLI calls this once per
//! session and again on every rotation (F-CLI.5).
//!
//! ## Why uniform
//!
//! Per the project's threat model, a peer should not be able to
//! steer its own exit to a colluding node: a weighted-by-trust
//! scheme would let an attacker who controls a fraction of the
//! exit set predict the next pick. Uniform random over the
//! coordinator-vetted exit set is the right MVP shape — the
//! coordinator decides who is eligible; the peer's job is only to
//! pick anonymously from the supplied list.
//!
//! ## RNG injection
//!
//! The fn takes `&mut impl rand::Rng` rather than reaching for a
//! thread-local RNG, so tests can supply a deterministic seed
//! (or a coverage-driven fuzzer can drive every index). Callers
//! in production wire in `rand::rng()` (the new thread-local
//! cryptographic RNG handle in rand 0.10).

use bibeam_core::NodeId;
use bibeam_protocol::cohort::CohortLive;
use rand::RngExt as _;

/// Pick one exit uniformly at random from `cohort.exits`.
///
/// Returns [`None`] when the cohort has no exits — the caller
/// must surface this as "cohort still bootstrapping; retry after
/// the next `CohortAssigned` event" rather than as a hard error.
///
/// The RNG is `&mut impl rand::Rng` so callers can wire in a
/// seeded RNG for tests; production callers use `rand::rng()`.
#[allow(
    clippy::redundant_pub_crate,
    reason = "binary-only crate: rustc's `unreachable_pub` rejects bare `pub` on items \
              consumed only by sibling private modules; clippy disagrees. We side with \
              rustc, the load-bearing lint."
)]
#[allow(
    dead_code,
    reason = "wired into the up flow by F-CLI.5's rotation loop, which calls pick_exit \
              both at session start and on every rotation. Reachable today through the \
              module's own integration tests below."
)]
pub(crate) fn pick_exit<R: rand::Rng + ?Sized>(cohort: &CohortLive, rng: &mut R) -> Option<NodeId> {
    if cohort.exits.is_empty() {
        return None;
    }
    let idx = rng.random_range(0..cohort.exits.len());
    cohort.exits.get(idx).copied()
}

#[cfg(test)]
mod tests {
    use bibeam_core::{CohortId, Timestamp};
    use rand::SeedableRng as _;
    use rand::rngs::StdRng;

    use super::*;

    fn cohort_with_exits(count: usize) -> CohortLive {
        let exits = (0..count).map(|_| NodeId::new()).collect();
        CohortLive {
            cohort: CohortId::new(),
            members: Vec::new(),
            exits,
            at: Timestamp::now(),
        }
    }

    #[test]
    fn pick_exit_returns_none_for_empty_cohort() {
        // Contract: a cohort that has not yet learned any exits
        // surfaces as None so the caller (F-CLI.5's rotation
        // loop) can defer rather than crash. A regression that
        // panicked on `gen_range(0..0)` would surface as a
        // crash-on-startup the moment the cohort is empty.
        let cohort = cohort_with_exits(0);
        let mut rng = StdRng::seed_from_u64(42);
        assert!(pick_exit(&cohort, &mut rng).is_none());
    }

    #[test]
    fn pick_exit_returns_some_for_singleton() {
        // Contract: a singleton cohort always returns the only
        // exit. Determinism guarantees the seed doesn't matter.
        let cohort = cohort_with_exits(1);
        let mut rng = StdRng::seed_from_u64(1);
        let picked = pick_exit(&cohort, &mut rng).expect("singleton must pick");
        assert_eq!(picked, cohort.exits[0]);
    }

    #[test]
    fn pick_exit_returns_member_of_exit_set() {
        // Contract: pick_exit must never invent an exit. Run it
        // 100 times against a 4-exit cohort and confirm every
        // outcome is one of the originals.
        let cohort = cohort_with_exits(4);
        let mut rng = StdRng::seed_from_u64(0xDEAD_BEEF);
        for _ in 0..100 {
            let picked = pick_exit(&cohort, &mut rng).expect("non-empty must pick");
            assert!(
                cohort.exits.contains(&picked),
                "picked exit {picked:?} not in cohort.exits {:?}",
                cohort.exits,
            );
        }
    }

    #[test]
    fn pick_exit_is_distribution_balanced_on_seeded_rng() {
        // Contract: uniform random over the exit set. A 10-exit
        // cohort sampled 10_000 times under a seeded RNG should
        // hit every index — a regression that always picked
        // index 0 (or fell back to the first/last) is caught by
        // the "no zero-count slot" assertion. We do not test the
        // exact distribution shape because that would couple the
        // test to rand's internal implementation; we only test
        // that every index is reachable.
        let cohort = cohort_with_exits(10);
        let mut rng = StdRng::seed_from_u64(0xCAFE_F00D);
        let mut counts = vec![0_usize; cohort.exits.len()];
        for _ in 0..10_000 {
            let picked = pick_exit(&cohort, &mut rng).expect("non-empty must pick");
            let idx = cohort
                .exits
                .iter()
                .position(|node| node == &picked)
                .expect("picked exit must be in the cohort");
            counts[idx] = counts[idx].saturating_add(1);
        }
        for (idx, count) in counts.iter().enumerate() {
            assert!(
                *count > 0,
                "exit at index {idx} was never picked across 10_000 draws — distribution \
                 collapsed to a strict subset",
            );
        }
    }
}
