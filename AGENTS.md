# AGENTS.md — AI Coding Assistant Brief

This file gives an AI coding assistant the minimum it needs to make a useful first change. Keep it tight; if a section grows, link out instead of expanding here.

## Quick facts

- **Project.** BiBeam (brand case) / 비빔 (Hangul) / Bidirectional-Beam (Bi-Beam). Etymology: Korean *bibimbap*; design metaphor: a bidirectional beam linking peers. ASCII identifier `bibeam` (lowercase). Never substitute hanja; never romanize 비빔 to `bibim`.
- **Edition.** Rust 2024 (`resolver = "3"`).
- **Toolchain.** Latest stable. **No MSRV pin.** `rust-toolchain.toml` declares `channel = "stable"`. CI runs `dtolnay/rust-toolchain@stable`. There is no nightly, no per-version matrix, no `cargo +nightly` anywhere.

## Commands

```bash
# format / lint / test / doc / supply-chain — match what hooks and CI run
just fmt       # cargo fmt --all
just lint      # cargo clippy --workspace --all-targets --all-features -- -D warnings
just test      # cargo nextest run --workspace --all-features
just doc       # RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features

# format / lint / test / doc / supply-chain — match what hooks and CI run
just ci       # fmt-check + lint + test + doc + deny + machete (see Justfile:41)

# per-crate README regeneration (do this after editing any Cargo.toml description)
cargo run -p xtask -- gen-readmes          # write
cargo run -p xtask -- gen-readmes --check  # drift gate
```

`just bootstrap` (run once per dev machine) installs `prek`, `cargo-nextest`, `typos-cli`, `cocogitto`, and `taplo-cli`, then arms the git hooks via `prek install`.

`just bootstrap-phase2` (only after the first real feature PR) installs the release stack: `git-cliff`, `release-plz`, `cargo-dist` (see Justfile:52).

## Workspace layout

See [`docs/architecture.md`](./docs/architecture.md) for the crate boundary map, the two-plane control/data split, and the request flow. The ten crates live under `crates/`:

## Strict regime — non-negotiable

- Clippy runs `pedantic` + `nursery` + `cargo` groups at `warn` plus a surgical restriction-deny list (see full list + rust/rustdoc lints in [`Cargo.toml`](./Cargo.toml):174-201; tests exempt via [`clippy.toml`](./clippy.toml):16-20). CI invokes `-D warnings`.
- **Cognitive complexity ≤ 15** per function. State machines that legitimately exceed it may carry `#[allow(clippy::cognitive_complexity)]` with a justification in the commit body.
- **Conventional Commits required.** `cog verify` runs at commit-msg time. See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for accepted types, branch policy, review axes (Correctness > Hygiene > Footprint), and the 5-point dep rubric.
- **Per-crate READMEs are generated.** Never hand-edit `crates/*/README.md`. Edit the `[package].description` and run `cargo run -p xtask -- gen-readmes`.

## Security context

[`docs/threat-model.md`](./docs/threat-model.md) is the canonical list of adversaries and what each can see. BiBeam is **not** Tor: there is no global passive adversary in scope, no cover traffic, no Sphinx packets. If a proposed change implies otherwise, push back.

## Common pitfalls

- Reaching for `cargo +nightly` to use a nightly-only feature — refuse. Find a stable workaround or open an issue.
- Editing `crates/<name>/README.md` directly — the drift check will fail in pre-commit and CI. Edit `Cargo.toml` instead.
- Bypassing `cog verify` with `git commit --no-verify` to land a non-conventional message — never. The CHANGELOG depends on conventional messages from day one.
- Using `std::sync::Mutex` / `std::sync::RwLock` — `clippy.toml` disallows them in favor of `parking_lot` equivalents.
- Using `chrono::DateTime` — `clippy.toml` disallows it in favor of `time::OffsetDateTime`.
- Using `println!` / `eprintln!` / `dbg!` in non-test code — disallowed by the restriction lints. Use `tracing` macros.
- Re-implementing what already exists. The anonymity-set ≥30 floor (R-3) IS enforced today (`crates/bibeam-node/src/coordinator/admission_gate.rs` — R-FLOOR per-region partition + `NoAnonymousPathAvailable` refusal). Phase-2 release tooling (release-plz, cargo-dist, dependabot, git-cliff) now has committed configs + `just bootstrap-phase2`; publish/installers still gated. Full enablement is future work.
- Bypassing the heavy pre-commit surface (prek-managed, see [`.pre-commit-config.yaml`](./.pre-commit-config.yaml):35-71). The policy is deliberate: fail on fmt/taplo/typos/xtask/clippy/nextest/deny/machete/doc *before* you write a commit message that `cog verify` will then reject (rationale in [`CONTRIBUTING.md`](./CONTRIBUTING.md):29-35).
- Hyphenated negative prefixes in comments (the three-letter form starting with `m`, hyphen, then a verb such as `paired` / `keyed` / `bind` / `classified` / `delivered`) trip the `typos` pre-commit hook because that three-letter token is read as a misspelling of `miss` / `mist`. Use `wrongly <verb>` or rewrite the phrase. The hook also enforces `unparsable` over the alternate spelling with an `e`.
- Adding a third-party dependency without checking the rubric in [`CONTRIBUTING.md`](./CONTRIBUTING.md) — active in the last 12 months, no RustSec advisory, latest release not yanked.
- Treating `docs/protocol.md`, root `PLAN.md`, or `docs/plan/tasks.md` as current. They contain pre-D-4 (QUIC/Noise) and pre-resolution (pending docs-only PR) text. Canonical sources: [`docs/architecture.md`](./docs/architecture.md):54 (data plane) + [`docs/threat-model.md`](./docs/threat-model.md):122 (multi-hop + R-3) + [`docs/plan/init.md`](./docs/plan/init.md):13 (MSRV/prek corrections).

## Picked design decisions (D-* + R-*)

Quick reference. Full grounding lives in [`docs/architecture.md`](./docs/architecture.md) (Operational decisions + two-plane crate map) + [`docs/threat-model.md`](./docs/threat-model.md):112 (R-1/R-3/D-6 sections) + [`docs/plan/init.md`](./docs/plan/init.md):13 (MSRV/prek/lefthook pivots + 0.2c corrections) + [`docs/plan/init.md`](./docs/plan/init.md):66 (original 17 decisions). The old "§11" pointers are stale post-correction; decisions were moved into architecture + threat-model.

- **D-1** ECH (Encrypted ClientHello): **best-effort** when rustls supports it for BiBeam's own coordinator TLS (CLI/node → coord); user-app ECH is transparent end-to-end. Policy knob `ech = "best-effort" | "deferred"` (CLI default `Deferred`). (arch:67, threat:11, cli/config.rs:51)
- **D-3** Exit-mode forwarding: **L3 via `tun-rs` + kernel NAT44/66** (primary), **L4 via `fast-socks5`** (fallback when TUN unavailable). (arch:127, plan/tasks:114)
- **D-4** VPN protocol family: **WireGuard wire-compat via `boringtun`** end-to-end (clients see a stock WG peer). (arch:56,69, threat:122)
- **D-5** GeoIP region cross-check: **warn-only** at MVP (`AuditKind::RegionMismatch`); admission proceeds. Region = free-form operator `String` (R-2). (region_verify.rs:1, admission_gate.rs:131)
- **D-6** Multi-hop construction: **option (c)** — stateful UDP forwarder + *end-to-end* client↔exit WG (TURN-style). Intermediates see only addr pair + ciphertext. (arch:56, threat:122-166)
- **R-1** (coord-crate dissolution): single `bibeam-node` binary; `is_coordinator` flag mounts the axum+redb admission module. Coord + data keys in same process (operators should physically separate). (arch:52, threat:114)
- **R-2** Region is operator-tagged free-form `String` on records; coord cross-checks vs GeoIP (ISO-3166) + allowlist CIDRs; per-region partitioning prevents anon-set pollution.
- **R-3** Per-position anonymity floor is **topology-only** (≥30 at *every* hop independently; **no cross-hop union**). Under-floor → refuse (`NoAnonymousPathAvailable`, one fresh audit row per drain poll). Region-isolated. (admission_gate.rs:186-240,300, threat:160)
- **R-MULTIHOP-PROTO** packet-to-lease binding: **option (B)** — explicit `RelayFrame { chain_id, wg_payload }`. Coord **never** holds WG X25519 private keys (client + exit mint locally at registration, publish only pubkeys). (threat:164, multihop.rs:206)

**Cross-cutting invariants (expensive to rediscover):**
- **Data / control plane split** (arch:7): control crates (`discovery`, crypto PASETO, `node/coordinator/`) never see WG private keys or inner traffic; data crates (`tun`, `transport/wg_*`, exit) never perform admission or issue tokens. Any change must respect the boundary.
- **Key custody + forwarder visibility** (D-6/R-4): intermediates see only outer address + WG ciphertext shape; never plaintext, transport keys, or identities. Coord is a pairing service only.
- **Anonymity floor mechanics** (R-3 + R-2): per-position + per-region + per-poll audit (no dedup, no continuous re-gate between rotations). Refuse rather than route. One audit row per poll for operator visibility.
- **Historical pivot record** (plan/init.md:13): MSRV pin removed (0.2c), lefthook → prek, "latest stable only, no dedicated MSRV CI job". The "why no pin" rationale lives only in the correction notes.

## Where to look first

- A new lint failure: [`clippy.toml`](./clippy.toml) and `[workspace.lints.*]` in [`Cargo.toml`](./Cargo.toml).
- A new hook failure: [`.pre-commit-config.yaml`](./.pre-commit-config.yaml).
- A CI failure that does not reproduce locally: the [GitHub workflow](./.github/workflows/ci.yml) runs three operating systems; macOS and Windows runners catch path and line-ending issues.
- A "where does this fit?" question: [`docs/architecture.md`](./docs/architecture.md).
- A "why does the scaffold look like this?" question: [`docs/plan/init.md`](./docs/plan/init.md) — the spec that drove Phase 1 (plus corrections at :13).
- Supply-chain policy or new third-party dep: [`deny.toml`](./deny.toml) (yanked=deny, "Revisit by YYYY-MM-DD" ignore convention, license allowlist, bans, graph.all-features) + [`CONTRIBUTING.md`](./CONTRIBUTING.md):58-68 (5-point rubric) + :70 (review axes).
- Release / changelog / dist automation: [`release-plz.toml`](./release-plz.toml), [`dist-workspace.toml`](./dist-workspace.toml), [`cliff.toml`](./cliff.toml) (parser order critical for `chore(release)`), [`cog.toml`](./cog.toml), [`.github/dependabot.yml`](./.github/dependabot.yml) (weekly groups).
- Formatting + cross-OS churn prevention: [`.taplo.toml`](./.taplo.toml) (reorder_keys/arrays=false to protect Cargo.lock), [`.editorconfig`](./.editorconfig) (2-space for toml/yml + md no-trim), [`rustfmt.toml`](./rustfmt.toml), [`.cargo/config.toml`](./.cargo/config.toml) (retry=3, git-fetch-with-cli).
- Hook surface + prek policy: [`.pre-commit-config.yaml`](./.pre-commit-config.yaml) (heavy pre-commit vs light pre-push, fail_fast=false, nextest --no-tests=warn in hook, xtask --release gen-readmes --check).
