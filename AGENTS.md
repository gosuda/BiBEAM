# AGENTS.md — AI Coding Assistant Brief

This file gives an AI coding assistant the minimum it needs to make a useful first change. Keep it tight; if a section grows, link out instead of expanding here.

## Quick facts

- **Project.** BiBEAM (브랜드 케이스), 비빔 in Hangul; also expanded as Bidirectional-Beam (Bi-Beam). The name doubles as etymology (Korean *bibimbap*) and design metaphor (a bidirectional beam linking peers). Identifier `bibeam` (lowercase). Never substitute hanja, never romanize the Hangul to `bibim`.
- **Edition.** Rust 2024 (`resolver = "3"`).
- **Toolchain.** Latest stable. **No MSRV pin.** `rust-toolchain.toml` declares `channel = "stable"`. CI runs `dtolnay/rust-toolchain@stable`. There is no nightly, no per-version matrix, no `cargo +nightly` anywhere.
- **Phase.** Phase 1 init complete + plan §11 revisions landed. The 10 crates carry real implementations (frames, codec, crypto, transport, TUN, discovery, runtime, coord, node forwarder, exit-mode, CLI). What's NOT yet wired: the `bibeam-node` supervisor that composes the F-NODE.* modules into a single running daemon (each module's unit + integration tests pass; the binary's `src/main.rs` is the §0.2a placeholder per the original plan).

## Commands

```bash
# format / lint / test / doc — match what hooks and CI run
just fmt       # cargo fmt --all
just lint      # cargo clippy --workspace --all-targets --all-features -- -D warnings
just test      # cargo nextest run --workspace --all-features
just doc       # RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features

# full local CI pipeline
just ci

# per-crate README regeneration (do this after editing any Cargo.toml description)
cargo run -p xtask -- gen-readmes          # write
cargo run -p xtask -- gen-readmes --check  # drift gate
```

`just bootstrap` (run once per dev machine) installs `prek`, `cargo-nextest`, `typos-cli`, `cocogitto`, and `taplo-cli`, then arms the git hooks via `prek install`.

## Workspace layout

See [`docs/architecture.md`](./docs/architecture.md) for the crate boundary map, the two-plane control/data split, and the request flow. The ten crates live under `crates/`:

`bibeam-core`, `bibeam-protocol`, `bibeam-crypto`, `bibeam-transport`, `bibeam-tun`, `bibeam-discovery`, `bibeam-runtime` (libraries) · `bibeam-node`, `bibeam-cli` (daemons) · `xtask` (ops runner). The `bibeam-node` daemon carries both data-plane and control-plane roles in a single binary, gated by the `is_coordinator` config flag (per §11 R-1; the previously-separate `bibeam-coordinator` crate was dissolved into `bibeam-node`'s `src/coordinator/` module).

## Strict regime — non-negotiable

- `#![forbid(unsafe_code)]` at every first-party crate. Any FFI goes through a third-party wrapper. Do not introduce `unsafe { … }` in workspace code, ever.
- Clippy runs `pedantic` + `nursery` + `cargo` groups at `warn` plus a surgical restriction-deny list (no `panic`, `unwrap_used`, `expect_used`, `todo`, `unimplemented`, `unreachable`, `dbg_macro`, `print_stdout`, `print_stderr`, `mem_forget`, `unwrap_in_result`, `let_underscore_must_use` in non-test code). CI invokes `-D warnings`.
- **Cognitive complexity ≤ 15** per function. State machines that legitimately exceed it may carry `#[allow(clippy::cognitive_complexity)]` with a justification in the commit body.
- **Conventional Commits required.** `cog verify` runs at commit-msg time. See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for accepted types.
- **Pre-commit is heavy.** `prek` runs fmt + taplo + typos + xtask drift + clippy + nextest + deny + machete + doc on every commit (see [`.pre-commit-config.yaml`](./.pre-commit-config.yaml)). Failing a hook does not produce a commit. Pre-push is intentionally lighter (a `cargo check`).
- **Per-crate READMEs are generated.** Never hand-edit `crates/*/README.md`. Edit the `[package].description` and run `cargo run -p xtask -- gen-readmes`.

## Security context

[`docs/threat-model.md`](./docs/threat-model.md) is the canonical list of adversaries and what each can see. BiBEAM is **not** Tor: there is no global passive adversary in scope, no cover traffic, no Sphinx packets. If a proposed change implies otherwise, push back.

## Common pitfalls

- Reaching for `cargo +nightly` to use a nightly-only feature — refuse. Find a stable workaround or open an issue.
- Editing `crates/<name>/README.md` directly — the drift check will fail in pre-commit and CI. Edit `Cargo.toml` instead.
- Bypassing `cog verify` with `git commit --no-verify` to land a non-conventional message — never. The CHANGELOG depends on conventional messages from day one.
- Using `std::sync::Mutex` / `std::sync::RwLock` — `clippy.toml` disallows them in favor of `parking_lot` equivalents.
- Using `chrono::DateTime` — `clippy.toml` disallows it in favor of `time::OffsetDateTime`.
- Using `println!` / `eprintln!` / `dbg!` in non-test code — disallowed by the restriction lints. Use `tracing` macros.
- Treating actually-implemented features as Phase-2-deferred. The anonymity-set ≥30 floor IS enforced (see `crates/bibeam-node/src/coordinator/admission_gate.rs` — per-region partition + `NoAnonymousPathAvailable` refusal per §11 R-FLOOR + R-3 formalism). Still genuinely Phase 2 / not-yet-implemented: release-plz, cargo-dist, dependabot, coordinator replication protocol (P2A-1 only recorded the decision). Re-implementing what already exists wastes a sweep.
- Hyphenated negative prefixes in comments (the three-letter form starting with `m`, hyphen, then a verb such as `paired` / `keyed` / `bind` / `classified` / `delivered`) trip the `typos` pre-commit hook because that three-letter token is read as a misspelling of `miss` / `mist`. Use `wrongly <verb>` or rewrite the phrase. The hook also enforces `unparsable` over the alternate spelling with an `e`.
- Adding a third-party dependency without checking the rubric in [`CONTRIBUTING.md`](./CONTRIBUTING.md) — active in the last 12 months, no RustSec advisory, latest release not yanked.

## Picked design decisions (D-* + R-*)

Quick reference so you don't grep the plan-doc on every change. Full rationale lives in `docs/plan/init.md` §11; the docs themselves are the source of record for downstream readers.

- **D-1** ECH (Encrypted ClientHello): **deferred** at MVP — wired through F-TRANS.2's rustls config + F-CLI.7 `--ech-policy` flag; default `Deferred`.
- **D-3** Exit-mode forwarding: **L3 via `tun-rs` + kernel NAT44/66** (primary), **L4 via `fast-socks5`** (fallback when TUN unavailable).
- **D-4** VPN protocol family: **WireGuard wire-compat via `boringtun`** end-to-end (clients see a stock WG peer).
- **D-5** GeoIP region cross-check: **warn-only** at MVP. Mismatch emits `AuditKind::RegionMismatch`; admission proceeds.
- **D-6** Multi-hop construction: **option (c) — stateful UDP forwarder + end-to-end client↔exit WG** (TURN-style). Intermediates see address pair + ciphertext, never plaintext. Verified by the `forwarder_relays_opaque_payload_byte_preserving` integration test in `crates/bibeam-node/tests/multihop_e2e.rs`.
- **R-1** Coord crate dissolved into `bibeam-node/src/coordinator/`; the single binary carries both roles behind `is_coordinator`.
- **R-2** Region is operator-tagged free-form `String` on `PeerRecord`/`RelayRecord`/`ExitRecord`; coord cross-checks against GeoIP per D-5.
- **R-3** Per-position anonymity floor is **topology-only**: every position p in a multi-hop path must independently satisfy `|position_cohort(C, p)| + 1 ≥ 30`. **No union across hops** (an earlier draft's union claim was rejected by review). Under-floor → refuse, don't auto-route.
- **R-MULTIHOP-PROTO** packet-to-lease binding: **option (B)** — explicit `RelayFrame { chain_id, wg_payload }` encapsulation. Coord NEVER holds WG private keys; client + exit each generate their own keypairs at registration and publish only public keys.

## Where to look first

- A new lint failure: [`clippy.toml`](./clippy.toml) and `[workspace.lints.*]` in [`Cargo.toml`](./Cargo.toml).
- A new hook failure: [`.pre-commit-config.yaml`](./.pre-commit-config.yaml).
- A CI failure that does not reproduce locally: the [GitHub workflow](./.github/workflows/ci.yml) runs three operating systems; macOS and Windows runners catch path and line-ending issues.
- A "where does this fit?" question: [`docs/architecture.md`](./docs/architecture.md).
- A "why does the scaffold look like this?" question: [`docs/plan/init.md`](./docs/plan/init.md) — the spec that drove Phase 1.
