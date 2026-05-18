#![forbid(unsafe_code)]
//! Random exit selection (F-CLI.4, F-CLI.4b).
//!
//! [`pick_exit`] picks one [`NodeId`] uniformly at random from a
//! [`CohortLive`]'s `exits` set, filtered by an explicit
//! [`ExitFilter`]. The CLI calls this once per session and again
//! on every rotation (F-CLI.5).
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
//! ## Filter contract ([`ExitFilter`], F-CLI.4 / F-CLI.4b)
//!
//! Every call site MUST choose one of two filter variants, making
//! the region intent explicit at the type level:
//!
//! - [`ExitFilter::Region`] — restrict candidates to exits whose
//!   tag in [`CohortLive::exit_regions`] matches the borrowed
//!   string (case-sensitive, exact). Exits with no region entry
//!   are non-matches, never wildcards (§11 R-2). An empty filtered
//!   set returns [`None`] for the caller to surface as a §11 R-3
//!   refusal ("no exit in `<region>`; defer / fallback to
//!   multi-hop").
//! - [`ExitFilter::Any`] — full `cohort.exits` set with no region
//!   restriction. This is the explicit "any region is fine"
//!   choice; previously this case was modelled as
//!   `requested_region: Option<&str>::None`, which silently
//!   conflated "no preference" with "missing argument."
//!
//! The previous `Option<&str>`-shaped argument is gone: there is
//! no implicit fallback. Every caller writes either
//! `ExitFilter::Any` or `ExitFilter::Region(r)`, so the intent
//! reads at the call site.
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
use rand::seq::IteratorRandom as _;

/// Explicit caller-supplied filter for [`pick_exit`].
///
/// Replaces the previous `Option<&str>` argument so the "any
/// region" case reads as a distinct variant at every call site
/// (Cleanup A — wire-format forward-compat strip).
#[allow(
    dead_code,
    reason = "variants are constructed today only by the module's own integration tests; \
              F-CLI.5's rotation loop will wire `ExitFilter::Any` (default) and \
              `ExitFilter::Region(r)` (when the user pins a region) on the same commit \
              that lifts `#[allow(dead_code)]` off `pick_exit`."
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExitFilter<'a> {
    /// Restrict candidates to exits whose region tag matches the
    /// supplied string (case-sensitive, exact). The borrow lets
    /// callers pass through a `&str` from CLI args or session
    /// state without an allocation.
    Region(&'a str),
    /// Pick from the full `cohort.exits` set with no region
    /// restriction. Distinct from "no caller supplied a region"
    /// — this is the affirmative "any region is acceptable"
    /// choice.
    Any,
}

/// Pick one exit uniformly at random from `cohort.exits`,
/// constrained by the supplied [`ExitFilter`].
///
/// Returns [`None`] when:
/// - the cohort has no exits at all — caller surfaces as "cohort
///   still bootstrapping; retry after the next `CohortAssigned`
///   event" rather than a hard error; or
/// - the filter is [`ExitFilter::Region`] and no exit in the set
///   carries a matching region tag — caller surfaces as the
///   §11 R-3 refusal ("no exit in `<region>`; defer / fallback to
///   multi-hop").
///
/// The RNG is `&mut impl rand::Rng` so callers can wire in a
/// seeded RNG for tests; production callers use `rand::rng()`.
#[allow(
    dead_code,
    reason = "wired into the up flow by F-CLI.5's rotation loop, which calls pick_exit \
              both at session start and on every rotation. Reachable today through the \
              module's own integration tests below."
)]
pub(crate) fn pick_exit<R: rand::Rng + ?Sized>(
    cohort: &CohortLive,
    filter: ExitFilter<'_>,
    rng: &mut R,
) -> Option<NodeId> {
    match filter {
        // F-CLI.4: explicit "any region" path. Full exit set,
        // uniform pick. Indexed pick over the Vec preserves the
        // original single-`random_range` shape — no reservoir
        // loop, no intermediate allocations.
        ExitFilter::Any => {
            if cohort.exits.is_empty() {
                return None;
            }
            let idx = rng.random_range(0..cohort.exits.len());
            cohort.exits.get(idx).copied()
        },
        // F-CLI.4b: region-filtered path. Missing tags are
        // non-matches (region-unknown, not wildcard) — see module
        // docs and §11 R-2. Reservoir sampling via
        // `IteratorRandom::choose` keeps this allocation-free: we
        // walk the exit list once, no intermediate `Vec`, and a
        // single weighted-by-index reservoir pick falls out at the
        // end. Returns `None` for the empty filtered set, which
        // the caller surfaces as a §11 R-3 refusal.
        ExitFilter::Region(region) => cohort
            .exits
            .iter()
            .copied()
            .filter(|node| cohort.exit_regions.get(node).map(String::as_str) == Some(region))
            .choose(rng),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

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
            exit_regions: HashMap::new(),
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
        assert!(pick_exit(&cohort, ExitFilter::Any, &mut rng).is_none());
    }

    #[test]
    fn pick_exit_returns_some_for_singleton() {
        // Contract: a singleton cohort always returns the only
        // exit. Determinism guarantees the seed doesn't matter.
        let cohort = cohort_with_exits(1);
        let mut rng = StdRng::seed_from_u64(1);
        let picked = pick_exit(&cohort, ExitFilter::Any, &mut rng).expect("singleton must pick");
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
            let picked =
                pick_exit(&cohort, ExitFilter::Any, &mut rng).expect("non-empty must pick");
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
            let picked =
                pick_exit(&cohort, ExitFilter::Any, &mut rng).expect("non-empty must pick");
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

    #[test]
    fn pick_exit_filters_by_requested_region() {
        // Contract (F-CLI.4b, §11 R-2): pick_exit must filter
        // cohort.exits down to exits whose region tag matches the
        // requested region BEFORE the uniform-random pick.
        //
        // - `ExitFilter::Region("us-east")` over `[us-east, eu-de, us-east, kr-seoul]`
        //   must always return one of the two us-east exits.
        // - `ExitFilter::Region("kr-seoul")` must always return the single
        //   kr-seoul exit (determinism is incidental: the
        //   filtered set has only one element).
        // - `ExitFilter::Region("us-west")` (no member matches) must
        //   return None — the caller surfaces this as a §11 R-3
        //   refusal ("no exit in <region>; defer / fallback to
        //   multi-hop"), not a panic.
        //
        // A regression that ignored the filter would still pick
        // SOME exit for `us-west` (failing the None assertion)
        // and would occasionally pick eu-de or kr-seoul for
        // `us-east` (failing the membership assertion).
        let exits: Vec<NodeId> = (0..4).map(|_| NodeId::new()).collect();
        let regions = ["us-east", "eu-de", "us-east", "kr-seoul"];
        let mut exit_regions: HashMap<NodeId, String> = HashMap::new();
        for (node, region) in exits.iter().zip(regions.iter()) {
            exit_regions.insert(*node, (*region).to_owned());
        }
        let cohort = CohortLive {
            cohort: CohortId::new(),
            members: Vec::new(),
            exits: exits.clone(),
            exit_regions,
            at: Timestamp::now(),
        };

        let us_east: Vec<NodeId> = [exits[0], exits[2]].into_iter().collect();
        let kr_seoul = exits[3];

        let mut rng = StdRng::seed_from_u64(0x00F1_17E2);

        // Hammer the filter 100 times to surface any one-shot
        // bias (e.g. always returning the first match).
        for _ in 0..100 {
            let picked = pick_exit(&cohort, ExitFilter::Region("us-east"), &mut rng)
                .expect("us-east must yield a pick");
            assert!(
                us_east.contains(&picked),
                "picked exit {picked:?} not in us-east set {us_east:?}",
            );
        }

        let picked_kr = pick_exit(&cohort, ExitFilter::Region("kr-seoul"), &mut rng)
            .expect("kr-seoul must yield a pick");
        assert_eq!(picked_kr, kr_seoul);

        // §11 R-3: empty filtered set is None, not a panic.
        let picked_none = pick_exit(&cohort, ExitFilter::Region("us-west"), &mut rng);
        assert!(
            picked_none.is_none(),
            "us-west has no member in the exit set; must refuse with None, got {picked_none:?}",
        );
    }
}
