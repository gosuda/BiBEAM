# Changelog

All notable changes to BiBeam are documented in this file.

The format follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and the project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

From Phase 2 onward this file will be populated automatically by [release-plz](https://release-plz.dev/) and [git-cliff](https://git-cliff.org/) from conventional-commit messages. Until then, entries are hand-curated.

## [Unreleased]

### Breaking

- **Wire-format fields now required (no `#[serde(default)]` fallback).** The following control-plane fields no longer accept absent values; producers MUST emit the field (possibly empty `{}` / `null`), and consumers refuse to decode a frame that omits the field entirely:
  - `bibeam_protocol::control::SingleHopMatch.exit_regions` (per-exit region map; emit `{}` when GeoIP is unconfigured).
  - `bibeam_protocol::cohort::CohortLive.exit_regions` (cohort-plane mirror of the SingleHopMatch field; same emission rules).
  - `bibeam_discovery::records::PeerRecord.wg_public_key` (X25519 WireGuard public key; emit `null` until the peer registers a key, the base64 string thereafter).

  The previous `#[serde(default)]` fallback silently filled empty maps / `None` on field absence — that fallback was speculative forward-compat for coordinators / peers that no longer exist (pre-1.0 MVP, no consumers) and is now removed. Loud deserialize failure is the new shape; protocol drift surfaces immediately instead of degrading silently. Wire-version pinning (`MAGIC = "BIBM"`, `VERSION = 1`) is unchanged and remains the right primitive for future schema evolution.

- **CLI exit-pick now requires an explicit `ExitFilter`.** `bibeam_cli::exit_pick::pick_exit` no longer takes `requested_region: Option<&str>`; it takes `filter: ExitFilter<'_>` with two variants — `ExitFilter::Region(&str)` (filter the candidate set to exits whose region tag matches, case-sensitive) and `ExitFilter::Any` (full `cohort.exits` set, no region restriction). The previous `None` case (implicit "any region") is now spelled explicitly as `ExitFilter::Any`; every call site reads its region intent at the type level instead of inferring it from a sentinel.
