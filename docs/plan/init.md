# BiBeam (비빔) — Init Plan: Strict Rust 2024 Workspace + Distributed P2P VPN

> **Name fidelity.** The project name is rendered as **`비빔`** in Hangul (verbatim). Never substitute hanja (e.g. Chinese-character forms), never romanize the standalone name to `bibim`, never drop the Hangul where it currently appears. The ASCII binary/crate name is `bibeam` (lowercase); the brand is `BiBeam` (camel-cap); the Korean script is `비빔`. These three forms are interchangeable in human-readable prose; identifiers (binaries, crates, env vars) stay ASCII.

## 0. Scaffold Order (Do This First)

The init commit is **not** a single atomic dump. It is a sequenced bring-up: every step installs a gate, every later step is verified through that gate. If step N's gate fails, **fix N or roll N back** — do not proceed to N+1. Phase 2 templates (§10) are out of this sequence; they land in a later PR.

| # | Artifact group | Files added in this step | Gate that must pass before next step |
|---|---|---|---|
| 0.1 | **Project structure** | `crates/{bibeam-core,bibeam-protocol,bibeam-crypto,bibeam-transport,bibeam-tun,bibeam-discovery,bibeam-runtime,bibeam-coordinator,bibeam-node,bibeam-cli,xtask}/src/` directories, `docs/`, `.github/workflows/`, `.cargo/` | `eza --tree --level=3` matches the tree in §3 exactly (no extra dirs, no missing crates) |
| 0.2a | **Cargo.toml + toolchain + crate stubs + hand-written placeholder READMEs** | `rust-toolchain.toml` (§4.1, `channel = "stable"`), workspace `Cargo.toml` (§4.2 layout **with `crates/xtask` temporarily removed from `[workspace] members` — xtask is added in 0.2b along with its manifest**; `default-members` is unaffected), **10** crate `Cargo.toml` files (all of §5 except xtask), `src/lib.rs` and `src/main.rs` stubs with `#![forbid(unsafe_code)]` and `#![doc = include_str!("../README.md")]` (§5), **10 hand-written per-crate `README.md` files** (one paragraph each: `# <crate-name>\n\n<description>\n`) so the doc-include macro resolves cleanly. xtask is **not** added in this step — its concern lives in 0.2b. | `cargo check --workspace --all-targets --all-features` on latest stable → zero errors, zero warnings (passes because `members` lists only the 10 crates that actually exist). `rustup show` confirms the active toolchain is `stable-*` (whatever the current stable channel resolves to). **No Rust version is pinned** — the project rides latest stable always; no `rust-version` field in `[workspace.package]`, no per-version CI matrix, no nightly anywhere. |
| 0.2c | **Drop MSRV pin** | Correction commit: remove `rust-version = "1.89"` from workspace `Cargo.toml` `[workspace.package]` and `rust-version = { workspace = true }` from all 11 per-crate `Cargo.toml` files. Lands after the original 0.2a/0.2b commits because the project owner pivoted to "latest stable always, no MSRV pin" partway through bring-up. Future fresh runs of 0.2a will produce the post-correction state directly (no separate 0.2c needed) because §4.2 / §5 now reflect the no-pin policy. | `cargo check --workspace --all-targets --all-features` on latest stable → still exits 0 (removing the MSRV declaration is a no-op for resolution). |
| 0.2d | **Bump workspace deps to latest** | Correction commit: bump `[workspace.dependencies]` to the latest published versions per project-owner direction "use latest and de-facto and well-maintained crates only" — `governor 0.10`, `redb 4`, `hkdf 0.13`, `rand 0.10`, `rand_core 0.10`, `snow 0.10`, `reqwest 0.13` (with `rustls-tls` → `rustls` feature rename), `tokio-tungstenite 0.29` (with `rustls-tls-webpki-roots` → `rustls-tls-webpki-roots-aws-lc-rs` or equivalent updated feature), `fast-socks5 1.0`, `hickory-resolver 0.26`, `metrics 0.24`, `metrics-exporter-prometheus 0.18`, `etherparse 0.20`, `toml 1.1`. Lands after 0.2c because the original 0.2a's pre-bump versions are what HEAD has at that point. Future fresh runs of 0.2a transcribe the post-bump §4.2 directly. | `cargo update --workspace` regenerates `Cargo.lock` cleanly; `cargo check --workspace --all-targets --all-features` exits 0 with zero errors and zero warnings on latest stable. |
| 0.2b | **xtask binary + gen-readmes subcommand + xtask added to workspace members** | xtask `Cargo.toml` + `src/main.rs` (§5) implementing `cargo run -p xtask -- gen-readmes` (writes) and `cargo run -p xtask -- gen-readmes --check` (drift-detect); **and an edit to the workspace `Cargo.toml` appending `"crates/xtask"` to the `[workspace] members` array** (the only modification to a 0.2a file — logically a workspace-member extension, atomic with the manifest it adds). xtask reads each workspace member's `[package].description` and produces the same one-paragraph `README.md` that 0.2a hand-wrote. From this commit onward, the 11 per-crate READMEs become **xtask-maintained**: hand-edits drift and are caught by the drift-check (armed in 0.6 / pre-commit / CI). | **Two checks, both required:** (a) `cargo build -p xtask --release` → zero errors; (b) `cargo run -p xtask --release -- gen-readmes --check` → exits 0 (the 0.2a hand-written READMEs for the 10 non-xtask crates match what xtask would generate; xtask itself also gets its README written by this command since the workspace now includes it — the check is run after one no-op `gen-readmes` invocation to produce xtask's own README, which is then staged into this same commit). |
| 0.3 | **Lint / format / supply-chain configs** | `rustfmt.toml` (§4.3), `clippy.toml` (§4.4), `deny.toml` (§4.5), `.cargo/config.toml` (§4.6), `.editorconfig` (§4.12), `typos.toml` (§4.11), `cog.toml` (§4.8) | `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo deny check`, `cargo machete --skip-target-dir`, `typos .` — **all exit 0** |
| 0.4 | **Pre-commit + dev tasks** | `.pre-commit-config.yaml` (§4.7, managed by `prek` — Rust-native drop-in for the pre-commit framework), `.taplo.toml` (§4.7a, preserves hand-aligned TOML styling against `taplo fmt --check`), `Justfile` with `bootstrap` recipe (§4.13); run `just bootstrap` to `cargo install --locked` prek (if not already present via system package manager) + cocogitto + taplo-cli + typos-cli + cargo-nextest; then `prek install` arms `.git/hooks/{pre-commit,commit-msg,pre-push}` | `prek run --all-files` exits 0; `prek run --stage pre-push --all-files` exits 0; `git commit -m "test:bad msg"` is **rejected** by `cog verify` (proves commit-msg hook is live) |
| 0.5 | **CI pipeline** | `.github/workflows/ci.yml` (§4.14) — fmt (stable), clippy strict, nextest matrix (stable × Linux/macOS/Windows), rustdoc strict, deny, machete, llvm-cov (report-only) | Push to a draft PR or `gh workflow run` — every job green. CI is the gate that catches cross-OS regressions before they ship |
| 0.6 | **Docs skeleton (workspace-level)** | `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md` (`## [Unreleased]` block only), **`AGENTS.md`** (AI-coding-assistant brief — see §6 for content spec), `docs/{architecture,protocol,threat-model,operator-runbook}.md` (§6). Per-crate READMEs were hand-written in 0.2a and locked to xtask generation in 0.2b; this step does **not** re-write them. | `cargo run -p xtask --release -- gen-readmes --check` (no drift since 0.2b) **and** `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features` — zero broken intra-doc links, zero missing-crate-level-docs warnings. |
| 0.7 | **`.gitignore` extension** | Append the editor / OS / coverage / dist block from §4.17 to the existing Rust-flavored `.gitignore` (do not replace) | `cargo build && cargo nextest run && cargo doc` produces no untracked files in `git status` other than `target/`, `lcov.info`, `*.profraw` (all already ignored) |

**Sequencing invariant.** Step 0.2a must compile **before** 0.2b (xtask needs the workspace to exist so `cargo build -p xtask` resolves). Both 0.2a and 0.2b must compile **before** 0.3 layers strict lints on top (or `cargo check` fails for an unrelated reason and you waste cycles). Step 0.3 must lint-clean **before** 0.4 hooks fire `cargo clippy -- -D warnings` on every push. Step 0.4 must arm hooks **before** 0.5 CI mirrors the same checks (so local and CI diverge by zero rules). Steps 0.6 / 0.7 are independent of each other and can run after 0.5.

**Commit cadence (atomic-commit per phase).** Each step is a single atomic commit. The gate must pass **before** the commit lands. Use the cocogitto types so `cog verify` (commit-msg hook, armed at step 0.4) accepts the message. Once 0.4 is live, commits 0.4 onward auto-run pre-commit and pre-push hooks — passing those hooks **is part of the gate**, not separate from it.

| Step | Commit message | Verify gate runs before commit |
|------|---------------|-------------------------------|
| 0.1 | `chore: scaffold workspace directory layout` | `eza --tree --level=3` review |
| 0.2a | `feat: workspace cargo manifests + 10 crate stubs + 10 hand-written per-crate READMEs (#![forbid(unsafe_code)]; xtask deferred to 0.2b)` | `cargo check` (stable, on 10-member workspace) |
| 0.2b | `feat(xtask): gen-readmes subcommand (locks per-crate READMEs to Cargo.toml descriptions)` | `cargo build -p xtask` + `cargo run -p xtask -- gen-readmes --check` |
| 0.2c | `chore: drop MSRV pin (workspace.package + 11 per-crate manifests) — latest-stable-only policy` | `cargo check` (stable, post-removal) |
| 0.2d | `chore: bump workspace deps to latest stable (redb 4, governor 0.10, snow 0.10, reqwest 0.13 [rustls feature rename], hkdf 0.13, rand 0.10, tokio-tungstenite 0.29, fast-socks5 1.0, hickory-resolver 0.26, metrics 0.24, metrics-exporter-prometheus 0.18, etherparse 0.20, toml 1.1)` | `cargo update` regenerates lock; `cargo check` (stable) exits 0 zero warnings |
| 0.3 | `chore: strict lint / format / supply-chain config (rustfmt, clippy, deny, .cargo, editorconfig, typos, cog)` | `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo deny check`, `cargo machete`, `typos .` |
| 0.4 | `chore: prek hooks (.pre-commit-config.yaml + .taplo.toml) + Justfile + bootstrap recipe` | `just bootstrap` → `prek run --all-files` → `prek run --stage pre-push --all-files` → reject-bad-commit-msg drill |
| 0.5 | `ci: github actions workflow (fmt + clippy + nextest matrix + doc + deny + machete + llvm-cov)` | local repro: `act -W .github/workflows/ci.yml` **or** push to draft PR and watch `gh run watch` until green |
| 0.6 | `docs: skeleton (README, CONTRIBUTING, SECURITY, CHANGELOG, docs/architecture, docs/protocol, docs/threat-model, docs/operator-runbook)` | `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features` |
| 0.7 | `chore: extend .gitignore (editor / OS / coverage / dist)` | `cargo build && cargo nextest run && cargo doc` then `git status` shows only the committed paths plus already-ignored `target/`, `lcov.info`, `*.profraw` |

**Rollback policy.** If a gate fails, do **not** commit. Either fix in-place and re-run the gate, or `git restore`-revert the working tree to the previous commit's state. Never amend a previously-landed commit to slip past a gate — that hides the failure from `git log` and from `cog changelog`.

**Out of Section 0 (Phase 2 templates — §10):** `cliff.toml`, `release-plz.toml`, `.github/workflows/release-plz.yml`, `.github/dependabot.yml`. These do **not** ship in the init commit, full stop.

## 1. Context

**Problem.** Korean users hit Cloudflare-451 / SNI-based geo-blocks. A single user behind a single foreign exit IP is trivially fingerprinted, blocked, or de-anonymized. The fix the user articulated is **collective IP washing** — many users sharing many overseas exits so that any single egress IP carries traffic from dozens of users, none of which is individually linkable.

**Project.** BiBeam (비빔, "mixing"): a multi-user **distributed P2P VPN/proxy** built in Rust. Two planes:

- **Control plane** — hybrid super-peer rendezvous (Iroh-style): 2–3 federated coordinator nodes host invite-gated peer registration + exit/relay matchmaking; clients may degrade to pkarr-on-Mainline-DHT fallback when super-peers are reachable but blocked.
- **Data plane** — **Model D+ shared exit pool** (one-bucket mixing): K clients egress through M exits via random-per-session + per-rotation assignment; SNI obfuscation (TLS 1.3 ECH) is the *primary* 451 defense, shared-pool mixing the *secondary* unlinkability layer. Not Tor: anonymity set ~50 users/exit, latency budget < 25 ms direct, falls back to relay only when hole-punch fails.

**Constraints (user-stated, hard).**
- Latest, well-maintained, de-facto crates. Edition 2024.
- `#![forbid(unsafe_code)]` at every first-party crate.
- Strict clippy with **aggressive cognitive complexity caps**.
- Pre-commit hooks + CI hooks both enforce the strict regime.
- Run on Oracle Cloud ARM Free Tier (low-spec) for server-side; cross-platform clients.
- "Best-effort" minimum-viable scaffold — no over-engineering.

**Current repo state (`/home/alpha/toys/BiBeam`).** Fresh clone of `github.com/gosuda/BiBeam` (single commit `53517cc`). Tracked files: `LICENSE` (MIT, GoSuda 2026) + `.gitignore` (Rust-flavored, kept). No Rust sources yet. Toolchain on host: `rustc 1.95.0` stable + nightlies; `cargo-nextest`, `cargo-deny`, `cargo-audit`, `cargo-machete`, `cargo-llvm-cov`, `just`, `bacon`, `eza`, `fd`, `bat`, `rg` all present. `prek` (already available on PATH via Homebrew in the dev image), `typos`, `cocogitto`, `taplo-cli`, `cargo-nextest` either already-present or installed via `cargo install --locked`.

**Intended outcome.** A workspace skeleton — every config, lint, hook, and CI gate present and enforcing — plus a layered crate boundary (11 crates) ready for incremental implementation. Zero compile errors, zero clippy warnings, all hooks green on a `git push` of the scaffold.

---

## 2. Architecture Decisions

Each row: decision (rationale, 1–2 lines).

1. **Edition 2024; latest stable Rust always; no MSRV pin.** Edition is pinned at `2024` in `[workspace.package].edition`. **No `rust-version` field** is declared — the project rides whatever stable Rust release contributors and CI happen to have when they build. Per project-owner direction: "use latest and de-facto and well-maintained crates only" — the cost of supporting older Rust versions is not worth the constraint it places on dep choices (`redb = "3"`, `tokio = "1.40"`, etc. all assume current stable). `rust-toolchain.toml` pins `channel = "stable"`; CI runs `cargo` commands against whatever `dtolnay/rust-toolchain@stable` resolves to at job time. No nightly. No MSRV CI job, no per-version matrix.
2. **Workspace resolver `"3"`.** Edition 2024 default; MSRV-aware dependency selection.
3. **`unsafe_code = "forbid"` workspace-wide.** Forbid (not deny) at `[workspace.lints.rust]`. All FFI (TUN device, sockets, crypto) goes through third-party crates that wrap unsafe themselves — we never write `unsafe { … }` in first-party code. Third-party unsafe is accepted; CI-enforcement on deps is limited to RustSec advisories via `cargo deny check advisories`. The contributor-facing dep-selection rubric (maintenance, freshness) lives in `CONTRIBUTING.md` (§6) and is review-time guidance, not a CI gate.
4. **Strict-clippy shape: warn-in-Cargo.toml + deny-in-CI.** `pedantic` / `nursery` / `cargo` groups at `warn` (priority -1) in `[workspace.lints.clippy]`; CI invokes `cargo clippy … -- -D warnings` to escalate. Local `cargo check` stays usable; CI is the gate.
5. **Restriction lints — surgical `deny` list.** Only safety-load-bearing lints denied: `panic`, `unwrap_used`, `expect_used`, `todo`, `unimplemented`, `unreachable`, `dbg_macro`, `print_stdout`, `print_stderr`, `mem_forget`, `unwrap_in_result`, `let_underscore_must_use`. Tests are exempt via `allow-unwrap-in-tests` / `allow-expect-in-tests` in `clippy.toml`. Hot lints like `arithmetic_side_effects`, `indexing_slicing`, `as_conversions`, `string_slice` are **NOT** denied — they trigger constant `#[allow]` noise in packet-math code.
6. **Cognitive-complexity threshold = 15.** Default 25 is loose; 10 is unworkable; 15 is the empirical sweet spot. Per-function `#[allow(clippy::cognitive_complexity)]` with commit-body justification permitted for hand-tuned state machines.
7. **Topology (control plane): Hybrid super-peer rendezvous.** 2–3 federated super-peers each running `iroh-relay`-derived rendezvous + invite admission. Operator liability stays bounded (control-plane metadata only, no payload). Phase 1 ships **independent coordinators with client round-robin failover** (no inter-coordinator replication; clients re-register on whichever peer answers). Phase-1 failure mode: when any single coordinator is unreachable the client retries the next; when **all configured coordinators are unreachable** the client falls back to pkarr-on-Mainline-DHT for discovery. The replication protocol (lightweight-but-robust per project owner direction) and any quorum semantics it implies are deferred to a Phase 2 architectural research task — see §2.5.
8. **Mixing model (data plane): Model D+ shared exit pool; coordinator-side anonymity-set admission gate.** Clients pick exit randomly per session, rotate every 15 min or 500 MB. **Anonymity-set invariant (MVP):** ≥ 30 users bound to an exit at the moment of cohort admission, re-applied on every rotation. Decay between rotations (as individual sessions end) is bounded by the rotation window and accepted as the MVP trade-off — no continuous re-gating. The gate is enforced coordinator-side at PASETO token issuance (single auditable point). The cohort lifecycle and rotation re-pool mechanism are coordinator-impl concerns specified in `docs/protocol.md` (§6). SNI obfuscation via TLS 1.3 ECH is the **primary** 451 defense; pool mixing is the **secondary** unlinkability layer.
9. **Crypto: Noise_IK_25519_ChaChaPoly_BLAKE3 over QUIC datagrams.** 1-RTT client→exit handshake using pre-shared invite-derived key. ChaCha20-Poly1305 AEAD per packet. Ed25519 for long-term identity + invite signing. PASETO v4 (`pasetors`) for coordinator-issued session tokens.
10. **Transport: Quinn 0.11.x QUIC + tun-rs 2.8.x TUN device + `fast-socks5` L4 fallback.** Quinn datagram extension (RFC 9221) carries Noise-sealed IP frames; SOCKS5 over QUIC for restricted networks where TUN is unavailable.
11. **Coordinator storage: redb 3.x.** Embedded ACID KV, single-writer/multi-reader, fits Oracle ARM Free Tier comfortably. No Postgres dependency at MVP.
12. **Hook runner: prek** (Rust-native drop-in for the pre-commit framework; reads `.pre-commit-config.yaml`). Per project-owner direction, the de-facto pre-commit ecosystem wins for hook discoverability; prek provides it without the Python runtime that vanilla pre-commit requires. Distributed via `cargo install --locked prek` and via system package managers (Homebrew, etc.). Local-only hooks (no external repo deps in `repos:`) keep hook execution offline-deterministic.
13. **Conventional commits: cocogitto.** Rust-native, drives both commit-msg validation and changelog seed.
14. **Release pipeline: release-plz + cargo-dist + git-cliff.** release-plz drives the version-bump-PR loop from conventional commits; cargo-dist builds multi-target binaries (Linux x86_64+aarch64, macOS aarch64, Windows x86_64) and creates GitHub Releases; git-cliff seeds CHANGELOG.md.
15. **Observability MVP: tracing-subscriber JSON + Prometheus `/metrics` + `/healthz` `/readyz`.** No OpenTelemetry-OTLP at MVP (deferred). PII redacted via BLAKE3-keyed hash of peer ID + IP before logging.
16. **Coverage tool: `cargo-llvm-cov`.** Rust-team-endorsed, cross-platform, LCOV export to Codecov.
17. **Workspace = 11 crates.** 7 libraries + 3 binaries + 1 xtask. Clear boundary between protocol/crypto/transport/discovery primitives (libs) and role-specific daemons (bins).

**Explicitly deferred (out-of-scope for init):** OpenTelemetry-OTLP, cosign / sigstore binary signing, cargo-vet, cargo-audit (covered by cargo-deny advisories), human-panic, sentry-rs, hot-reload SIGHUP, mobile (iOS/Android), full Loopix mixnet, on-chain proof-of-stake exit incentives.

---

## 2.5 Init Phase Split (MVP vs Phase 2)

To keep the init scaffold minimum-viable while still landing the strict regime the user demanded, split deliverables by activation gate:

**Phase 1 — MVP init (active immediately on commit):**

- Workspace + 11 crate stubs (Cargo.toml + `#![forbid(unsafe_code)]` lib.rs/main.rs each). Stubs compile with zero warnings, run a single smoke test each. Crate boundaries are layout-only; no protocol/transport/crypto code yet — only types and bin skeletons.
- `xtask` binary with a working `gen-readmes` subcommand (and `--check` drift mode). **Project-owner direction (askme Q4): generate, do not hand-maintain.** Rationale: per-crate README content is a one-paragraph derivation of `[package].description` already present in `Cargo.toml`; hand-maintaining it in two places creates a silent-drift surface between `cargo metadata` and rendered rustdoc. The drift-check eliminates that bug class at init (not deferred to first incident). Cost is small: ~80 LOC of xtask + a sub-100ms `--check` run wired into pre-commit and CI.
- All lint / format / hook configs: `rust-toolchain.toml`, `Cargo.toml` `[workspace.lints.*]`, `rustfmt.toml`, `clippy.toml`, `deny.toml`, `.cargo/config.toml`, `.pre-commit-config.yaml`, `cog.toml`, `typos.toml`, `.editorconfig`, `Justfile`.
- CI gates that block PRs from day one: `fmt` (stable), `clippy -D warnings`, `nextest` matrix (stable × Linux/macOS/Windows), `rustdoc -D warnings`, `cargo deny check`, `cargo machete`, `cargo llvm-cov` (report-only at init — does **not** fail CI; threshold ratchet introduced in Phase 2 once real code exists), `xtask gen-readmes --check` (drift gate).
- Doc skeletons (`README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`, `AGENTS.md`, `docs/{architecture,protocol,threat-model,operator-runbook}.md`) so `cargo doc` resolves cleanly.

**Phase 2 — added in a separate later PR, NOT in the init commit:**

**Activation trigger:** Phase 2 PR opens the moment the **first non-stub merge** lands on `main` — i.e., as soon as any feature crate gains its first real (non-skeleton) module via a merged PR. Until then, the templates live in §10 of this plan only; no `release-plz.toml` / `dependabot.yml` / `cliff.toml` file exists in the repo. Including them at init would create dead config that breaks the "minimum viable scaffold" promise.

The following files are **documented as templates in §10 of this plan** but are **not created at init time** and **not added in the init commit**.

- `release-plz.toml` + `.github/workflows/release-plz.yml` — release-PR automation.
- `cargo-dist` multi-target binary releases (`dist init` run later).
- `.github/dependabot.yml` — weekly dep PR generation.
- `cliff.toml` — changelog template (CHANGELOG.md at init is a hand-written empty `## [Unreleased]` block).
- Coverage **threshold** gate (`--fail-under-lines N`) in CI; until then Phase 1's `cargo llvm-cov` is report-only.

**Activation rule (unambiguous):** init commit creates exactly the Phase 1 file list above. Phase 2 files appear only in PRs that follow the first non-stub code merge. No file is ever both "scaffolded at init" and "Phase 2."

### 2.5.1 Phase 2 Architectural-Research Checkpoints

Separate from the file-gating rule above, the following are **decision checkpoints** gated by the same activation trigger. The deliverable for each checkpoint is a `docs/architecture.md` update (a docs file edit, not a new template-file creation); no executable code lands until a follow-up PR after the decision is recorded.

- **Coordinator replication protocol.** Pick one of {gossip + Δ-CRDT, lightweight leader-election with lease+heartbeat, openraft-Raft} per the "lightweight but robust" project-owner direction (askme Q1). The pick + rationale lands as a `docs/architecture.md` edit before the coordinator MVP reaches feature-complete. Implementation follows in a separate PR.

---

## 3. Workspace Layout

```
bibeam/
├── Cargo.toml                       # workspace manifest + lints + deps
├── rust-toolchain.toml              # channel = "stable" (latest stable)
├── rustfmt.toml
├── clippy.toml
├── deny.toml                        # cargo-deny
├── .pre-commit-config.yaml          # prek hooks (Rust drop-in for pre-commit)
├── cog.toml                         # cocogitto (commit-msg hook from day 1)
├── typos.toml
├── .cargo/config.toml
├── .editorconfig
├── .gitignore                       # extend existing
├── Justfile
├── README.md                        # write skeleton
├── LICENSE                          # exists (MIT)
├── CONTRIBUTING.md                  # write skeleton
├── SECURITY.md                      # write skeleton
├── CHANGELOG.md                     # write skeleton (keep-a-changelog, empty Unreleased)
├── .github/
│   └── workflows/
│       └── ci.yml
# NOTE: .github/dependabot.yml, .github/workflows/release-plz.yml,
#       cliff.toml, release-plz.toml are Phase 2 only (see §10).
├── docs/
│   ├── architecture.md
│   ├── protocol.md
│   ├── threat-model.md
│   └── operator-runbook.md
└── crates/
    ├── bibeam-core/                 # lib: IDs (ULID), errors, identity types
    ├── bibeam-protocol/             # lib: wire frames + postcard codec
    ├── bibeam-crypto/               # lib: Noise IK, AEAD, PASETO, key mgmt
    ├── bibeam-transport/            # lib: quinn + STUN + hole-punch + datagram tunnel
    ├── bibeam-tun/                  # lib: tun-rs wrapper + packet pipeline
    ├── bibeam-discovery/            # lib: coordinator client + rendezvous types
    ├── bibeam-runtime/              # lib: tracing, metrics, config, signals, health
    ├── bibeam-coordinator/          # bin: rendezvous server (axum + redb)
    ├── bibeam-node/                 # bin: dual-role relay/exit daemon
    ├── bibeam-cli/                  # bin: end-user client daemon + CLI
    └── xtask/                       # bin: workspace ops (ci, docs, release)
```

---

## 4. Configuration Files (Full Content)

### 4.1 `rust-toolchain.toml`

```toml
# DELIBERATELY NON-REPRODUCIBLE TOOLCHAIN.
# Project policy (per project owner): always build on the latest Rust stable release.
# Trade-off accepted: `rustup update` may advance the active toolchain between
# `cargo build` invocations. We trade build-time reproducibility for free upstream
# bugfixes / perf wins on the daily-driven toolchain.
#
# What IS reproducible:
#   - Edition: declared in workspace.package.edition = "2024".
#   - Dependency graph: pinned by Cargo.lock (committed at repo root) — so the same
#     `cargo build` on the same Rust release always resolves identical crate versions.
#
# What is NOT reproducible by design:
#   - The exact Rust compiler version. There is no `rust-version` (MSRV) pin in
#     [workspace.package]; the project rides latest stable. If you need a deterministic
#     build (release artifact, security audit, reproducible binary), the CI release
#     job (Phase 2) overrides this with an explicit `dtolnay/rust-toolchain@<version>` pin.

[toolchain]
channel    = "stable"   # latest stable; rustup resolves on `rustup update`
components = ["rustfmt", "clippy", "rust-analyzer", "rust-src", "llvm-tools-preview"]
targets = [
  "x86_64-unknown-linux-gnu",
  "aarch64-unknown-linux-gnu",
  "aarch64-apple-darwin",
  "x86_64-apple-darwin",
  "x86_64-pc-windows-msvc",
]
profile = "minimal"
```

### 4.2 Workspace `Cargo.toml`

```toml
[workspace]
resolver = "3"
members  = [
  "crates/bibeam-core",
  "crates/bibeam-protocol",
  "crates/bibeam-crypto",
  "crates/bibeam-transport",
  "crates/bibeam-tun",
  "crates/bibeam-discovery",
  "crates/bibeam-runtime",
  "crates/bibeam-coordinator",
  "crates/bibeam-node",
  "crates/bibeam-cli",
  "crates/xtask",
]
default-members = ["crates/bibeam-cli"]

[workspace.package]
version       = "0.0.1"
edition       = "2024"
license       = "MIT"
repository    = "https://github.com/gosuda/BiBeam"
homepage      = "https://github.com/gosuda/BiBeam"
authors       = ["GoSuda BiBeam contributors"]
readme        = "README.md"
keywords      = ["vpn", "p2p", "quic", "noise", "privacy"]
categories    = ["network-programming", "cryptography"]

[workspace.dependencies]
# --- shared first-party crates (path deps) ---
bibeam-core       = { version = "0.0.1", path = "crates/bibeam-core" }
bibeam-protocol   = { version = "0.0.1", path = "crates/bibeam-protocol" }
bibeam-crypto     = { version = "0.0.1", path = "crates/bibeam-crypto" }
bibeam-transport  = { version = "0.0.1", path = "crates/bibeam-transport" }
bibeam-tun        = { version = "0.0.1", path = "crates/bibeam-tun" }
bibeam-discovery  = { version = "0.0.1", path = "crates/bibeam-discovery" }
bibeam-runtime    = { version = "0.0.1", path = "crates/bibeam-runtime" }

# --- async runtime ---
tokio        = { version = "1.40", features = ["rt-multi-thread", "macros", "net", "sync", "time", "io-util", "signal", "process", "fs"] }
tokio-util   = { version = "0.7",  features = ["codec", "io", "rt"] }
tokio-stream = { version = "0.1",  features = ["sync", "time"] }
futures      = "0.3"
futures-util = "0.3"

# --- transport / crypto / proto ---
quinn               = { version = "0.11", default-features = false, features = ["rustls-ring", "runtime-tokio"] }
quinn-proto         = "0.11"
rustls              = { version = "0.23", default-features = false, features = ["std", "ring"] }
tokio-rustls        = "0.26"
rustls-pemfile      = "2"
snow                = { version = "0.10", features = ["ring-accelerated"] }
x25519-dalek        = { version = "2",   features = ["serde", "static_secrets"] }
ed25519-dalek       = { version = "2",   features = ["serde", "rand_core"] }
chacha20poly1305    = "0.10"
blake3              = { version = "1",   features = ["traits-preview"] }
hkdf                = "0.13"
rand                = "0.10"
rand_core           = "0.10"
zeroize             = { version = "1",   features = ["derive"] }
subtle              = "2"
pasetors            = { version = "0.7", features = ["v4"] }

# --- TUN / packets / NAT ---
tun-rs       = { version = "2",  features = ["async_tokio"] }
etherparse   = "0.20"
hickory-resolver = { version = "0.26", default-features = false, features = ["tokio", "system-config"] }

# --- HTTP / WS ---
axum                 = { version = "0.8", features = ["macros", "ws", "json", "tokio"] }
tower                = "0.5"
tower-http           = { version = "0.6", features = ["trace", "cors", "compression-gzip", "limit", "timeout"] }
hyper                = "1"
reqwest              = { version = "0.13", default-features = false, features = ["json", "rustls", "stream"] }
tokio-tungstenite    = { version = "0.29", default-features = false, features = ["connect", "rustls-tls-webpki-roots"] }
fast-socks5          = "1.0"

# --- storage / config / ids ---
redb         = "4"
figment      = { version = "0.10", features = ["toml", "env"] }
clap         = { version = "4.5", features = ["derive", "env", "wrap_help"] }
ulid         = { version = "1",   features = ["serde"] }
uuid         = { version = "1",   features = ["v7", "serde"] }
time         = { version = "0.3", features = ["serde", "formatting", "parsing", "macros"] }

# --- serde / data ---
serde         = { version = "1", features = ["derive"] }
serde_json    = "1"
serde_with    = { version = "3", features = ["base64", "hex"] }
postcard      = { version = "1", features = ["alloc", "use-std"] }
bytes         = "1"
toml          = "1.1"
base64        = "0.22"
hex           = "0.4"

# --- error / logging / metrics ---
thiserror                      = "2"
anyhow                         = "1"
tracing                        = "0.1"
tracing-subscriber             = { version = "0.3", features = ["env-filter", "json", "fmt", "registry"] }
tracing-error                  = "0.2"
metrics                        = "0.24"
metrics-exporter-prometheus    = { version = "0.18", default-features = false, features = ["http-listener"] }

# --- rate limit / ops ---
governor   = "0.10"
parking_lot = "0.12"
dashmap    = "6"
async-trait = "0.1"

# --- test / bench / fuzz ---
proptest        = "1"
proptest-derive = "0.5"
criterion       = { version = "0.5", features = ["html_reports"] }
arbitrary       = { version = "1", features = ["derive"] }

# --- allocator (server-side) ---
mimalloc = { version = "0.1", default-features = false }

[workspace.lints.rust]
unsafe_code                = "forbid"
missing_docs               = "warn"
missing_debug_implementations = "warn"
unused_must_use            = "deny"
rust_2024_compatibility    = "warn"
rust_2018_idioms           = "warn"
unreachable_pub            = "warn"
let_underscore_drop        = "warn"
trivial_casts              = "warn"
trivial_numeric_casts      = "warn"
unused_import_braces       = "warn"
unused_lifetimes           = "warn"
unused_qualifications      = "warn"
single_use_lifetimes       = "warn"
non_ascii_idents           = "deny"

[workspace.lints.clippy]
# group-level warns (CI escalates with -D warnings)
pedantic = { level = "warn", priority = -1 }
nursery  = { level = "warn", priority = -1 }
cargo    = { level = "warn", priority = -1 }

# pedantic carve-outs (too noisy / not load-bearing for our domain)
module_name_repetitions = "allow"
missing_errors_doc      = "allow"
missing_panics_doc      = "allow"
must_use_candidate      = "allow"
similar_names           = "allow"
too_many_lines          = "allow"   # complexity caught by cognitive_complexity instead
multiple_crate_versions = "allow"   # transitive duplicates from rust-crypto + dalek ecosystems; not load-bearing for safety

# cognitive complexity gate (threshold lives in clippy.toml)
cognitive_complexity    = "warn"

# surgical restriction denies (safety-load-bearing only)
panic                    = "deny"
unwrap_used              = "deny"
expect_used              = "deny"
todo                     = "deny"
unimplemented            = "deny"
unreachable              = "deny"
dbg_macro                = "deny"
print_stdout             = "deny"
print_stderr             = "deny"
mem_forget               = "deny"
unwrap_in_result         = "deny"
let_underscore_must_use  = "deny"
exit                     = "deny"
get_unwrap               = "deny"
lossy_float_literal      = "deny"
rc_buffer                = "deny"
rc_mutex                 = "deny"
self_named_module_files  = "warn"
verbose_file_reads       = "warn"

[workspace.lints.rustdoc]
broken_intra_doc_links     = "deny"
private_intra_doc_links    = "warn"
missing_crate_level_docs   = "warn"
unescaped_backticks        = "warn"
invalid_html_tags          = "deny"
bare_urls                  = "warn"

[profile.release]
lto              = "fat"
codegen-units    = 1
panic            = "abort"
strip            = "symbols"
opt-level        = 3
debug            = false
overflow-checks  = false
incremental      = false

[profile.release-debug]
inherits = "release"
strip    = "none"
debug    = "full"

[profile.dev]
opt-level         = 0
debug             = "limited"
split-debuginfo   = "unpacked"
incremental       = true
overflow-checks   = true

[profile.bench]
inherits      = "release"
lto           = "thin"
codegen-units = 16
debug         = "line-tables-only"

[profile.test]
opt-level = 1
debug     = "limited"
```

### 4.3 `rustfmt.toml`

```toml
# Stable-only rustfmt. Anything that requires nightly rustfmt is omitted by design — the project
# pins `channel = "stable"` (§4.1) and never invokes `cargo +nightly fmt`.
edition           = "2024"
style_edition     = "2024"
max_width         = 100
tab_spaces        = 4
hard_tabs         = false
newline_style     = "Unix"
use_field_init_shorthand   = true
use_try_shorthand          = true
reorder_imports            = true
reorder_modules            = true
match_block_trailing_comma = true
chain_width                = 80
fn_call_width              = 80
single_line_if_else_max_width = 50
struct_lit_width           = 30
struct_variant_width       = 35
array_width                = 80
attr_fn_like_width         = 80
```

Note: nightly-only rustfmt options (`imports_granularity`, `group_imports`, `format_strings`, `wrap_comments`, `normalize_comments`, `normalize_doc_attributes`, `format_macro_matchers`) are **deliberately omitted**. The project uses latest stable Rust only; CI fmt job runs `cargo fmt --check` on stable, never `cargo +nightly fmt`.

### 4.4 `clippy.toml`

```toml
# complexity caps (aggressive but workable)
cognitive-complexity-threshold      = 15
type-complexity-threshold           = 200
too-many-arguments-threshold        = 5
too-many-lines-threshold            = 80
excessive-nesting-threshold         = 4
max-fn-params-bools                 = 2
single-char-binding-names-threshold = 0
large-error-threshold               = 64
trivial-copy-size-limit             = 16
enum-variant-size-threshold         = 128

# test ergonomics
allow-unwrap-in-tests = true
allow-expect-in-tests = true
allow-panic-in-tests  = true
allow-dbg-in-tests    = true
allow-print-in-tests  = true

# disallowed APIs (force the better alternative)
disallowed-methods = [
  { path = "std::sync::Mutex::lock",   reason = "prefer parking_lot::Mutex" },
  { path = "std::sync::RwLock::read",  reason = "prefer parking_lot::RwLock" },
  { path = "std::sync::RwLock::write", reason = "prefer parking_lot::RwLock" },
]
disallowed-types = [
  { path = "chrono::DateTime", reason = "prefer time::OffsetDateTime" },
]
disallowed-names = ["foo", "bar", "baz", "tmp", "tmp2", "TODO", "FIXME"]
```

### 4.5 `deny.toml`

```toml
[graph]
all-features  = true
no-default-features = false

[advisories]
db-urls        = ["https://github.com/RustSec/advisory-db"]
yanked         = "deny"
ignore = [
  # Time-boxed exceptions. Each entry MUST embed a "Revisit by <YYYY-MM-DD>"
  # at the START of `reason`. PR reviewers treat any past-date entry as a
  # hard fail until renewed or removed. (cargo-deny does not yet accept a
  # native `expiration` field; this is the manual-review fallback.)
  { id = "RUSTSEC-2024-0436", reason = "Revisit by 2026-08-15. paste 1.0.15 unmaintained — transitive via clap-derive macro expansion. Not directly invoked at MVP; replacement upstream depends on a clap-derive release." },
  { id = "RUSTSEC-2023-0089", reason = "Revisit by 2026-08-15. atomic-polyfill 1.0.3 unmaintained — transitive via embassy-sync / similar low-level chains. Not directly invoked at MVP; revisit when upstream chains drop the dep." },
]

[licenses]
allow = [
  "MIT", "Apache-2.0", "Apache-2.0 WITH LLVM-exception",
  "BSD-2-Clause", "BSD-3-Clause", "ISC", "Zlib",
  "Unicode-3.0", "Unicode-DFS-2016",
  "MPL-2.0",                # weak copyleft, acceptable for libs
  "CC0-1.0",
  "CDLA-Permissive-2.0",   # webpki-roots Mozilla CA bundle data
]
confidence-threshold = 0.93
exceptions = []

[bans]
multiple-versions = "warn"
wildcards         = "deny"
highlight         = "all"
deny = [
  { name = "openssl"     },                # use rustls
  { name = "openssl-sys" },
  { name = "native-tls"  },                # use rustls
  { name = "chrono"      },                # use time
  { name = "failure"     },                # use thiserror
  { name = "error-chain" },                # use thiserror
]
skip      = []
skip-tree = []

[sources]
unknown-registry = "deny"
unknown-git      = "deny"
allow-registry   = ["https://github.com/rust-lang/crates.io-index"]
allow-git        = []
```

### 4.6 `.cargo/config.toml`

Minimal. Justfile (§4.13) is the canonical task runner; aliases are NOT duplicated here. Linker config is opt-in (commented).

```toml
[net]
git-fetch-with-cli = true
retry = 3

# Optional faster linker for incremental Linux builds. Commented out by default
# because lld is not installed everywhere; uncommenting will break `cargo build`
# on hosts that lack lld. Opt in locally by either:
#   (a) uncommenting both stanzas below, OR
#   (b) placing them in a developer-local `.cargo/config.toml` in a parent dir
#       (or `$CARGO_HOME/config.toml`) instead of editing the repo.
# CI installs lld explicitly in `.github/workflows/ci.yml` if/when fast linking
# is wanted; see that workflow for the canonical opt-in path.
#
# [target.x86_64-unknown-linux-gnu]
# rustflags = ["-C", "link-arg=-fuse-ld=lld"]
#
# [target.aarch64-unknown-linux-gnu]
# rustflags = ["-C", "link-arg=-fuse-ld=lld"]
```

### 4.7 `.pre-commit-config.yaml`

```yaml
# .pre-commit-config.yaml — managed by `prek` (Rust-native drop-in for the
# pre-commit framework). `prek install` arms `.git/hooks/{pre-commit,commit-msg,pre-push}`.
#
# Hook-weight policy (per project owner): pre-commit is HEAVIER than pre-push.
# Rationale — fail the contributor BEFORE they invest in a commit message they
# will then have to rewrite. Pre-push runs a fast sanity check only. CI is the
# final authority for cross-OS regressions.
minimum_pre_commit_version: "3.5.0"
fail_fast: false

repos:
  - repo: local
    hooks:
      # ---- cheap pre-commit checks (sub-second) ----
      - id: cargo-fmt-check
        name: cargo fmt --check
        entry: cargo fmt --all -- --check
        language: system
        types: [rust]
        pass_filenames: false
        stages: [pre-commit]
      - id: taplo-fmt-check
        name: taplo fmt --check
        entry: taplo fmt --check
        language: system
        types: [toml]
        stages: [pre-commit]
      - id: typos
        name: typos
        entry: typos
        language: system
        pass_filenames: false
        stages: [pre-commit]

      # ---- heavy pre-commit checks (workspace-scope) ----
      - id: xtask-gen-readmes-check
        name: xtask gen-readmes --check
        entry: cargo run -p xtask --release -- gen-readmes --check
        language: system
        pass_filenames: false
        stages: [pre-commit]
      - id: cargo-clippy
        name: cargo clippy -- -D warnings
        entry: cargo clippy --workspace --all-targets --all-features -- -D warnings
        language: system
        pass_filenames: false
        stages: [pre-commit]
      - id: cargo-nextest
        name: cargo nextest run
        entry: cargo nextest run --workspace --all-features --no-tests=warn
        language: system
        pass_filenames: false
        stages: [pre-commit]
      - id: cargo-deny
        name: cargo deny check
        entry: cargo deny check
        language: system
        pass_filenames: false
        stages: [pre-commit]
      - id: cargo-machete
        name: cargo machete
        entry: cargo machete --skip-target-dir
        language: system
        pass_filenames: false
        stages: [pre-commit]
      - id: cargo-doc
        name: cargo doc (-D warnings)
        entry: bash -lc 'RUSTDOCFLAGS=-Dwarnings cargo doc --workspace --no-deps --all-features'
        language: system
        pass_filenames: false
        stages: [pre-commit]

      # ---- commit-msg gate (conventional commit format) ----
      - id: cog-verify
        name: cog verify
        entry: cog verify --file
        language: system
        stages: [commit-msg]

      # ---- pre-push sanity (intentionally light) ----
      - id: cargo-check-push
        name: cargo check (pre-push sanity)
        entry: cargo check --workspace --all-targets --all-features
        language: system
        pass_filenames: false
        stages: [pre-push]
```

### 4.7a `.taplo.toml`

Pins ordering invariants (no auto-sort of dep arrays or keys) while accepting taplo's default per-section `=` alignment. Step 0.4 lands this config alongside a one-time reformat of every workspace TOML so `taplo fmt --check` is satisfied from the moment the hook is armed.

```toml
# .taplo.toml — formatter config for https://taplo.tamasfe.dev
# Accepts taplo's default per-section `=` alignment; pins ordering to
# "as written" so PRs don't churn on auto-sorted deps or keys.
[formatting]
column_width        = 200
array_auto_collapse = true
array_auto_expand   = false
compact_arrays      = true
reorder_arrays      = false
reorder_keys        = false
```

### 4.8 `cog.toml`

```toml
from_latest_tag      = true
ignore_merge_commits = true
disable_changelog    = false
disable_bump_commit  = false
generate_mono_repository_global_tag = true
branch_whitelist     = ["main", "release/**"]
tag_prefix           = "v"

[changelog]
path        = "CHANGELOG.md"
template    = "remote"
remote      = "github.com"
repository  = "BiBeam"
owner       = "gosuda"
authors     = []

[commit_types]
hotfix = { changelog_title = "Hot Fixes" }
release = { changelog_title = "Releases" }
```

### 4.9 `cliff.toml` — **moved to §10 (Phase 2 templates)**

Not created at init. Template lives in §10.1. CHANGELOG.md at init is a hand-written `## [Unreleased]` keep-a-changelog stub.

### 4.10 `release-plz.toml` — **moved to §10 (Phase 2 templates)**

Not created at init. Template lives in §10.2.

### 4.11 `typos.toml`

```toml
[default]
extend-ignore-identifiers-re = [
  "[Bb]i[Bb][Ee][Aa][Mm]",
  "비빔",
]

[default.extend-words]
crate = "crate"

[files]
extend-exclude = [
  "CHANGELOG.md",
  "target/**",
  "*.lock",
]
```

### 4.12 `.editorconfig`

```ini
root = true

[*]
charset                  = utf-8
end_of_line              = lf
insert_final_newline     = true
trim_trailing_whitespace = true
indent_style             = space
indent_size              = 4

[*.{toml,yml,yaml,json}]
indent_size = 2

[*.md]
trim_trailing_whitespace = false
indent_size              = 2

[Makefile]
indent_style = tab
```

### 4.13 `Justfile`

```just
set shell        := ["bash", "-cu"]
set windows-shell := ["pwsh.exe", "-NoLogo", "-Command"]
set dotenv-load  := true

default:
    @just --list

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

lint:
    cargo clippy --workspace --all-targets --all-features -- -D warnings

test:
    cargo nextest run --workspace --all-features

doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features

cov:
    cargo llvm-cov --workspace --all-features --lcov --output-path lcov.info

deny:
    cargo deny check

machete:
    cargo machete --skip-target-dir

audit-supply-chain: deny machete

bench:
    cargo bench --workspace

watch:
    bacon

# full CI pipeline locally
ci: fmt-check lint test doc deny machete

# install Phase-1 tooling (everything the init hooks/CI rely on)
bootstrap:
    cargo install --locked prek
    cargo install --locked cargo-nextest
    cargo install --locked typos-cli
    cargo install --locked cocogitto
    cargo install --locked taplo-cli
    prek install

# install Phase-2 release tooling (run only after first impl PR; not needed at init)
bootstrap-phase2:
    cargo install --locked git-cliff
    cargo install --locked release-plz
    cargo install --locked cargo-dist
```

### 4.14 `.github/workflows/ci.yml`

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read

env:
  CARGO_TERM_COLOR: always
  RUST_BACKTRACE: 1
  CARGO_INCREMENTAL: 0

concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true

jobs:
  fmt:
    name: rustfmt (stable)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt
      - run: cargo fmt --all -- --check

  clippy:
    name: clippy (strict)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy
      - uses: Swatinem/rust-cache@v2
      - run: cargo clippy --workspace --all-targets --all-features -- -D warnings

  test:
    name: test (${{ matrix.os }} · ${{ matrix.rust }})
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        os:   [ubuntu-latest, macos-latest, windows-latest]
        rust: [stable]
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@master
        with:
          toolchain: ${{ matrix.rust }}
      - uses: Swatinem/rust-cache@v2
      - uses: taiki-e/install-action@nextest
      - run: cargo nextest run --workspace --all-features

  doc:
    name: rustdoc (strict)
    runs-on: ubuntu-latest
    env:
      RUSTDOCFLAGS: "-D warnings"
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - name: xtask gen-readmes drift check
        run: cargo run -p xtask --release -- gen-readmes --check
      - run: cargo doc --workspace --no-deps --all-features

  supply-chain:
    name: deny + machete
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: EmbarkStudios/cargo-deny-action@v2
      - uses: taiki-e/install-action@v2
        with: { tool: cargo-machete }
      - run: cargo machete --skip-target-dir

  coverage:
    name: coverage (llvm-cov)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with: { components: llvm-tools-preview }
      - uses: Swatinem/rust-cache@v2
      - uses: taiki-e/install-action@cargo-llvm-cov
      - uses: taiki-e/install-action@nextest
      - run: cargo llvm-cov nextest --workspace --all-features --lcov --output-path lcov.info
      - uses: codecov/codecov-action@v4
        with:
          files: lcov.info
          fail_ci_if_error: false

```

### 4.15 `.github/workflows/release-plz.yml` — **moved to §10 (Phase 2 templates)**

Not created at init. Template lives in §10.3.

### 4.16 `.github/dependabot.yml` — **moved to §10 (Phase 2 templates)**

Not created at init. Template lives in §10.4.

### 4.17 `.gitignore` (extend existing)

The existing `.gitignore` already covers Rust outputs. Append:

```
# editor / OS
.idea/
.vscode/
.DS_Store
Thumbs.db

# coverage / bench
lcov.info
*.profraw

# secrets / local
.env
.env.*
!.env.example

# release / dist
dist/
```

---

## 5. Initial Crate Stubs

Every first-party crate begins with this `lib.rs`/`main.rs` header (omitted in stubs below for brevity, but **MUST** be present at file scope):

```rust
#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]
```

Stubs are **minimal**: header + `pub fn` placeholder for libs, `tokio::main` placeholder for bins. Filled in incrementally post-init.

### `crates/bibeam-core/Cargo.toml`

```toml
[package]
name         = "bibeam-core"
version      = { workspace = true }
edition      = { workspace = true }
license      = { workspace = true }
repository   = { workspace = true }
description  = "Shared types, errors, and identity primitives."
keywords     = { workspace = true }
categories   = { workspace = true }

[dependencies]
serde      = { workspace = true }
thiserror  = { workspace = true }
ulid       = { workspace = true }
time       = { workspace = true }
bytes      = { workspace = true }

[lints]
workspace = true

[package.metadata.cargo-machete]
ignored = ["serde", "thiserror", "ulid", "time", "bytes"]
```

### `crates/bibeam-protocol/Cargo.toml`

```toml
[package]
name         = "bibeam-protocol"
version      = { workspace = true }
edition      = { workspace = true }
license      = { workspace = true }
repository   = { workspace = true }
description  = "Wire frames and postcard codec."
keywords     = { workspace = true }
categories   = { workspace = true }

[dependencies]
bibeam-core = { workspace = true }
serde       = { workspace = true }
postcard    = { workspace = true }
thiserror   = { workspace = true }
bytes       = { workspace = true }

[lints]
workspace = true

[package.metadata.cargo-machete]
ignored = ["bibeam-core", "serde", "postcard", "thiserror", "bytes"]
```

### `crates/bibeam-crypto/Cargo.toml`

```toml
[package]
name         = "bibeam-crypto"
version      = { workspace = true }
edition      = { workspace = true }
license      = { workspace = true }
repository   = { workspace = true }
description  = "Noise IK, AEAD, PASETO, and key management."
keywords     = { workspace = true }
categories   = { workspace = true }

[dependencies]
bibeam-core      = { workspace = true }
snow             = { workspace = true }
x25519-dalek     = { workspace = true }
ed25519-dalek    = { workspace = true }
chacha20poly1305 = { workspace = true }
blake3           = { workspace = true }
hkdf             = { workspace = true }
rand             = { workspace = true }
rand_core        = { workspace = true }
zeroize          = { workspace = true }
subtle           = { workspace = true }
pasetors         = { workspace = true }
thiserror        = { workspace = true }

[lints]
workspace = true

[package.metadata.cargo-machete]
ignored = ["bibeam-core", "snow", "x25519-dalek", "ed25519-dalek", "chacha20poly1305", "blake3", "hkdf", "rand", "rand_core", "zeroize", "subtle", "pasetors", "thiserror"]
```

### `crates/bibeam-transport/Cargo.toml`

```toml
[package]
name         = "bibeam-transport"
version      = { workspace = true }
edition      = { workspace = true }
license      = { workspace = true }
repository   = { workspace = true }
description  = "QUIC and Noise datagram tunnel with STUN hole-punching."
keywords     = { workspace = true }
categories   = { workspace = true }

[dependencies]
bibeam-core     = { workspace = true }
bibeam-protocol = { workspace = true }
bibeam-crypto   = { workspace = true }
tokio           = { workspace = true }
tokio-util      = { workspace = true }
quinn           = { workspace = true }
quinn-proto     = { workspace = true }
rustls          = { workspace = true }
bytes           = { workspace = true }
futures-util    = { workspace = true }
thiserror       = { workspace = true }
tracing         = { workspace = true }

[lints]
workspace = true

[package.metadata.cargo-machete]
ignored = ["bibeam-core", "bibeam-protocol", "bibeam-crypto", "tokio", "tokio-util", "quinn", "quinn-proto", "rustls", "bytes", "futures-util", "thiserror", "tracing"]
```

### `crates/bibeam-tun/Cargo.toml`

```toml
[package]
name         = "bibeam-tun"
version      = { workspace = true }
edition      = { workspace = true }
license      = { workspace = true }
repository   = { workspace = true }
description  = "Cross-platform TUN device wrapper and L3 packet pipeline."
keywords     = { workspace = true }
categories   = { workspace = true }

[dependencies]
bibeam-core = { workspace = true }
tokio       = { workspace = true }
tun-rs      = { workspace = true }
etherparse  = { workspace = true }
bytes       = { workspace = true }
thiserror   = { workspace = true }
tracing     = { workspace = true }

[lints]
workspace = true

[package.metadata.cargo-machete]
ignored = ["bibeam-core", "tokio", "tun-rs", "etherparse", "bytes", "thiserror", "tracing"]
```

### `crates/bibeam-discovery/Cargo.toml`

```toml
[package]
name         = "bibeam-discovery"
version      = { workspace = true }
edition      = { workspace = true }
license      = { workspace = true }
repository   = { workspace = true }
description  = "Coordinator client and rendezvous types."
keywords     = { workspace = true }
categories   = { workspace = true }

[dependencies]
bibeam-core     = { workspace = true }
bibeam-protocol = { workspace = true }
bibeam-crypto   = { workspace = true }
tokio           = { workspace = true }
reqwest         = { workspace = true }
tokio-tungstenite = { workspace = true }
serde           = { workspace = true }
serde_json      = { workspace = true }
thiserror       = { workspace = true }
tracing         = { workspace = true }

[lints]
workspace = true

[package.metadata.cargo-machete]
ignored = ["bibeam-core", "bibeam-protocol", "bibeam-crypto", "tokio", "reqwest", "tokio-tungstenite", "serde", "serde_json", "thiserror", "tracing"]
```

### `crates/bibeam-runtime/Cargo.toml`

```toml
[package]
name         = "bibeam-runtime"
version      = { workspace = true }
edition      = { workspace = true }
license      = { workspace = true }
repository   = { workspace = true }
description  = "Shared runtime primitives: tracing, metrics, config, signals, health."
keywords     = { workspace = true }
categories   = { workspace = true }

[dependencies]
bibeam-core                 = { workspace = true }
tokio                       = { workspace = true }
tokio-util                  = { workspace = true }
tracing                     = { workspace = true }
tracing-subscriber          = { workspace = true }
tracing-error               = { workspace = true }
metrics                     = { workspace = true }
metrics-exporter-prometheus = { workspace = true }
figment                     = { workspace = true }
clap                        = { workspace = true }
axum                        = { workspace = true }
tower-http                  = { workspace = true }
serde                       = { workspace = true }
thiserror                   = { workspace = true }
anyhow                      = { workspace = true }

[lints]
workspace = true

[package.metadata.cargo-machete]
ignored = ["bibeam-core", "tokio", "tokio-util", "tracing", "tracing-subscriber", "tracing-error", "metrics", "metrics-exporter-prometheus", "figment", "clap", "axum", "tower-http", "serde", "thiserror", "anyhow"]
```

### `crates/bibeam-coordinator/Cargo.toml`

```toml
[package]
name         = "bibeam-coordinator"
version      = { workspace = true }
edition      = { workspace = true }
license      = { workspace = true }
repository   = { workspace = true }
description  = "Rendezvous and matchmaker daemon (axum + redb)."
keywords     = { workspace = true }
categories   = { workspace = true }

[[bin]]
name = "bibeam-coordinator"
path = "src/main.rs"

[dependencies]
bibeam-core        = { workspace = true }
bibeam-protocol    = { workspace = true }
bibeam-crypto      = { workspace = true }
bibeam-discovery   = { workspace = true }
bibeam-runtime     = { workspace = true }
tokio              = { workspace = true }
axum               = { workspace = true }
tower              = { workspace = true }
tower-http         = { workspace = true }
redb               = { workspace = true }
serde              = { workspace = true }
serde_json         = { workspace = true }
governor           = { workspace = true }
parking_lot        = { workspace = true }
dashmap            = { workspace = true }
clap               = { workspace = true }
tracing            = { workspace = true }
tracing-subscriber = { workspace = true }   # required by the shared bin main.rs subscriber init (§5 main.rs skeleton)
thiserror          = { workspace = true }
anyhow             = { workspace = true }
mimalloc           = { workspace = true }

[lints]
workspace = true

[package.metadata.cargo-machete]
ignored = ["bibeam-core", "bibeam-protocol", "bibeam-crypto", "bibeam-discovery", "bibeam-runtime", "axum", "tower", "tower-http", "redb", "serde", "serde_json", "governor", "parking_lot", "dashmap", "thiserror", "mimalloc"]
```

### `crates/bibeam-node/Cargo.toml`

```toml
[package]
name         = "bibeam-node"
version      = { workspace = true }
edition      = { workspace = true }
license      = { workspace = true }
repository   = { workspace = true }
description  = "Dual-role relay and exit daemon."
keywords     = { workspace = true }
categories   = { workspace = true }

[[bin]]
name = "bibeam-node"
path = "src/main.rs"

[dependencies]
bibeam-core        = { workspace = true }
bibeam-protocol    = { workspace = true }
bibeam-crypto      = { workspace = true }
bibeam-transport   = { workspace = true }
bibeam-tun         = { workspace = true }
bibeam-discovery   = { workspace = true }
bibeam-runtime     = { workspace = true }
tokio              = { workspace = true }
tokio-util         = { workspace = true }
fast-socks5        = { workspace = true }
hickory-resolver   = { workspace = true }
clap               = { workspace = true }
tracing            = { workspace = true }
tracing-subscriber = { workspace = true }   # required by the shared bin main.rs subscriber init (§5 main.rs skeleton)
thiserror          = { workspace = true }
anyhow             = { workspace = true }
mimalloc           = { workspace = true }

[lints]
workspace = true

[package.metadata.cargo-machete]
ignored = ["bibeam-core", "bibeam-protocol", "bibeam-crypto", "bibeam-transport", "bibeam-tun", "bibeam-discovery", "bibeam-runtime", "tokio-util", "fast-socks5", "hickory-resolver", "thiserror", "mimalloc"]
```

### `crates/bibeam-cli/Cargo.toml`

```toml
[package]
name         = "bibeam-cli"
version      = { workspace = true }
edition      = { workspace = true }
license      = { workspace = true }
repository   = { workspace = true }
description  = "End-user client daemon and CLI."
keywords     = { workspace = true }
categories   = { workspace = true }

[[bin]]
name = "bibeam"
path = "src/main.rs"

[dependencies]
bibeam-core        = { workspace = true }
bibeam-protocol    = { workspace = true }
bibeam-crypto      = { workspace = true }
bibeam-transport   = { workspace = true }
bibeam-tun         = { workspace = true }
bibeam-discovery   = { workspace = true }
bibeam-runtime     = { workspace = true }
tokio              = { workspace = true }
clap               = { workspace = true }
figment            = { workspace = true }
tracing            = { workspace = true }
tracing-subscriber = { workspace = true }   # required by the shared bin main.rs subscriber init (§5 main.rs skeleton)
thiserror          = { workspace = true }
anyhow             = { workspace = true }

[lints]
workspace = true

[package.metadata.cargo-machete]
ignored = ["bibeam-core", "bibeam-protocol", "bibeam-crypto", "bibeam-transport", "bibeam-tun", "bibeam-discovery", "bibeam-runtime", "figment", "thiserror"]
```

### `crates/xtask/Cargo.toml`

```toml
[package]
name         = "xtask"
version      = "0.0.1"
edition      = { workspace = true }
license      = { workspace = true }
publish      = false
description  = "Workspace ops runner (CI, docs, release helpers)."
keywords     = { workspace = true }
categories   = { workspace = true }

[[bin]]
name = "xtask"
path = "src/main.rs"

[dependencies]
clap      = { workspace = true }
anyhow    = { workspace = true }
tracing   = { workspace = true }
tracing-subscriber = { workspace = true }
# xtask-only: workspace Cargo.toml parser for `gen-readmes`.
# Do NOT propagate to other crate manifests — only xtask needs it.
toml      = { workspace = true }

[lints]
workspace = true
```

### `crates/xtask/src/main.rs` (overrides the shared binary template for xtask only)

```rust
#![forbid(unsafe_code)]
//! `BiBeam` workspace ops runner. Hosts cross-cutting maintenance subcommands.
//! Current subcommands:
//!   - `gen-readmes`         — write per-crate `README.md` from each member's `[package].description`.
//!   - `gen-readmes --check` — drift gate; exit non-zero if any README does not match what would be generated.

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "xtask", version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Generate per-crate `README.md` files from each crate's `[package].description`.
    GenReadmes {
        /// Verify every per-crate `README.md` matches what would be generated; exit non-zero on drift.
        #[arg(long)]
        check: bool,
    },
}

fn main() -> Result<()> {
    // Simple default subscriber — xtask is a one-shot CLI; no env-filter parsing needed.
    // Relies only on the `fmt` feature, which is enabled on the workspace tracing-subscriber dep (§4.2).
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::GenReadmes { check } => gen_readmes(check),
    }
}

fn gen_readmes(check_only: bool) -> Result<()> {
    let workspace_root = workspace_root()?;
    let members = read_workspace_members(&workspace_root)?;
    let mut drift = Vec::new();
    for path in members {
        process_member(&workspace_root, &path, check_only, &mut drift)?;
    }
    if check_only && !drift.is_empty() {
        report_drift(&drift);
        bail!(
            "{} per-crate README(s) out of date; run `cargo run -p xtask --release -- gen-readmes`",
            drift.len()
        );
    }
    Ok(())
}

fn read_workspace_members(workspace_root: &Path) -> Result<Vec<String>> {
    let ws_manifest = fs::read_to_string(workspace_root.join("Cargo.toml"))
        .context("read workspace Cargo.toml")?;
    let ws: toml::Value =
        toml::from_str(&ws_manifest).context("parse workspace Cargo.toml")?;
    let members = ws
        .get("workspace")
        .and_then(|w| w.get("members"))
        .and_then(|m| m.as_array())
        .context("missing [workspace].members in workspace Cargo.toml")?;
    members
        .iter()
        .map(|m| {
            m.as_str()
                .map(str::to_owned)
                .context("non-string entry in [workspace].members")
        })
        .collect()
}

fn process_member(
    workspace_root: &Path,
    member_path: &str,
    check_only: bool,
    drift: &mut Vec<PathBuf>,
) -> Result<()> {
    let crate_dir = workspace_root.join(member_path);
    let manifest_path = crate_dir.join("Cargo.toml");
    let (name, description) = read_name_and_description(&manifest_path)?;
    let readme = format!("# {name}\n\n{description}\n");
    let readme_path = crate_dir.join("README.md");
    if check_only {
        let existing = fs::read_to_string(&readme_path).unwrap_or_default();
        if existing != readme {
            drift.push(readme_path);
        }
    } else {
        fs::write(&readme_path, &readme)
            .with_context(|| format!("write {}", readme_path.display()))?;
        tracing::info!(crate_name = name.as_str(), "wrote README.md");
    }
    Ok(())
}

fn read_name_and_description(manifest_path: &Path) -> Result<(String, String)> {
    let manifest = fs::read_to_string(manifest_path)
        .with_context(|| format!("read {}", manifest_path.display()))?;
    let parsed: toml::Value = toml::from_str(&manifest)
        .with_context(|| format!("parse {}", manifest_path.display()))?;
    let pkg = parsed
        .get("package")
        .context("missing [package] in crate Cargo.toml")?;
    let name = pkg
        .get("name")
        .and_then(|n| n.as_str())
        .context("missing [package].name")?
        .to_owned();
    let description = pkg
        .get("description")
        .and_then(|d| d.as_str())
        .context("missing [package].description (required by xtask gen-readmes)")?
        .to_owned();
    Ok((name, description))
}

fn report_drift(drift: &[PathBuf]) {
    for path in drift {
        tracing::error!(readme = %path.display(), "drift detected");
    }
}

fn workspace_root() -> Result<PathBuf> {
    let cwd = std::env::current_dir().context("get current dir")?;
    let mut cur: &Path = cwd.as_path();
    loop {
        let manifest = cur.join("Cargo.toml");
        if manifest.exists() {
            let body = fs::read_to_string(&manifest)
                .with_context(|| format!("read {}", manifest.display()))?;
            if body.contains("[workspace]") {
                return Ok(cur.to_path_buf());
            }
        }
        match cur.parent() {
            Some(parent) => cur = parent,
            None => bail!("workspace root not found (no [workspace] Cargo.toml in ancestor chain)"),
        }
    }
}
```

### `src/lib.rs` skeleton (libraries — explicit, no "omitted for brevity")

```rust
#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]
```

(No `mod tests` stub. An empty `fn smoke() {}` is structural-only — it asserts no behavior the Rust compiler does not already enforce. The `cargo-nextest` pre-commit hook uses `--no-tests=warn` so a testless workspace is not a hook failure.)

### `src/main.rs` skeleton (binaries — explicit, no "omitted for brevity")

```rust
#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

use anyhow::Result;
use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = env!("CARGO_PKG_NAME"), version, about)]
struct Cli {}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let _cli = Cli::parse();
    tracing_subscriber::fmt().with_env_filter(
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
    ).init();
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "bootstrap");
    Ok(())
}
```

(No `--config` / `BIBEAM_CONFIG` option in the skeleton: there is no `Config` struct to load yet, and silently accepting an inert flag misleads users about whether configuration was applied. Wire it back when a real `figment::Figment::new()` loader lands.)

Each binary crate also writes its own `README.md` (one paragraph) so the `#![doc = include_str!("../README.md")]` resolves cleanly.

---

## 6. Documentation Skeleton

Skeleton content for each doc (path + 1–3 line description of what goes inside). All written as part of init so `cargo doc` and rustdoc intra-doc-links resolve.

- `README.md` — project pitch (BiBeam = 비빔, "mixing"), the one-liner about Korean-overseas IP-washing for 451 bypass, build/run quickstart, badges, link to docs.
- `CONTRIBUTING.md` — conventional commits required (cocogitto), branch model (main + short-lived feature branches), strict lint policy, how to run `just ci` locally, **per-crate READMEs are xtask-generated (`cargo run -p xtask -- gen-readmes`; edit `[package].description` in `Cargo.toml`, not `README.md` directly)**, **dep-selection rubric** (when adding a third-party crate: active commits within ~12 months, no open RustSec advisory, no yanked latest release; the check is review-time guidance — CI only enforces RustSec advisories via `cargo deny`).
- `AGENTS.md` — AI-coding-assistant brief (≤200 lines): project quick facts (name `BiBeam` / 비빔, edition 2024, latest stable Rust, no MSRV pin); commands cheat-sheet (`just fmt|lint|test|doc`, `cargo run -p xtask -- gen-readmes`); workspace-layout pointer (link to `docs/architecture.md`); strict-regime reminders (`#![forbid(unsafe_code)]`, conventional commits enforced by `cog verify`, pre-commit runs clippy + nextest + deny + machete + doc heavy via prek — see §4.7); pointer to `docs/threat-model.md` for security context; common pitfalls (no `cargo +nightly`, do not bypass `cog verify`, do not hand-edit per-crate `README.md`).
- `SECURITY.md` — threat model summary, what's in/out of scope (NOT Tor-grade), responsible-disclosure email, no bug bounty yet.
- `CHANGELOG.md` — empty `## [Unreleased]` block, keep-a-changelog format; auto-populated by release-plz / git-cliff.
- `docs/architecture.md` — two-plane diagram (control = hybrid super-peer rendezvous; data = Model D+ shared exit pool), crate boundary map, request flow (register → match → handshake → tunnel).
- `docs/protocol.md` — wire format (postcard frames), Noise_IK pattern + key schedule, PASETO session token claims, REST + WS endpoints, error codes, **cohort admission lifecycle (pending → live → rotation re-pool) backing the anonymity-set ≥30 invariant declared in §2 decision #8**.
- `docs/threat-model.md` — adversaries enumerated (Cloudflare/ISP, curious exit operator, curious coordinator, honest-but-curious peers, ABSENT: global passive adversary), what each can see, mitigations.
- `docs/operator-runbook.md` — how to bring up a coordinator / node, systemd unit template, log + metrics endpoints, common failure modes + recovery.

---

## 7. Verification

After init is applied, the following must all pass clean (zero warnings, zero errors):

```bash
# toolchain pinning
rustup show                                       # confirms `stable-*` is the active toolchain (latest stable; non-reproducible by design — see §4.1 comment block)

# install dev tooling
just bootstrap                                    # Phase 1 only: cargo-installs prek, cargo-nextest, typos-cli, cocogitto, taplo-cli; runs `prek install`. Phase 2 release tooling (git-cliff, release-plz, cargo-dist) is gated behind a separate `just bootstrap-phase2` recipe per §4.13 and is NOT installed by `just bootstrap`.

# core gates (stable toolchain only — no nightly anywhere)
cargo check    --workspace --all-features
cargo fmt      --all -- --check
cargo clippy   --workspace --all-targets --all-features -- -D warnings
cargo nextest run --workspace --all-features
cargo run -p xtask --release -- gen-readmes --check     # per-crate README drift gate (§5 xtask)
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features

# supply-chain
cargo deny check
cargo machete --skip-target-dir

# hook drills (verify the hooks would catch regressions)
prek run --all-files
prek run --stage pre-push --all-files
```

**Expected:** every command exits 0, no warnings, no clippy diagnostics, no doc warnings, no banned licenses, no advisories, no unused deps, hooks complete in <60 s wall-clock.

**Smoke test (post-init):** each `bibeam-coordinator`, `bibeam-node`, `bibeam-cli` binary starts, prints `bootstrap version=0.0.1`, and exits cleanly on SIGINT.

---

## 8. Out-of-Scope / Deferred

Explicit deferred list so creep doesn't reintroduce them:

- OpenTelemetry-OTLP distributed tracing (logs + Prometheus suffice at MVP).
- cosign / sigstore binary signing (add when first external user joins).
- cargo-vet supply-chain attestations (premature for a fresh project).
- cargo-audit as a separate job (cargo-deny `advisories` already runs the same RustSec DB).
- human-panic / sentry-rs error reporting (defer to client polish work).
- SIGHUP hot-reload of config (manual restart fine).
- Mobile clients (iOS NetworkExtension, Android VpnService) — separate effort post-MVP.
- Full Loopix/Sphinx mixnet, cover traffic, on-chain incentives — explicitly out-of-scope per threat model.
- Container hardening beyond `distroless/cc-debian12` (no seccomp profile bundling at MVP).
- Kubernetes Helm chart (systemd is the deployment target).

---

## 9. Critical Files to Modify (Summary)

Files this plan creates (none modified — only `.gitignore` is extended with a few editor/OS lines):

**Phase 1 (init commit):**

| Path | Purpose |
|---|---|
| `Cargo.toml` | workspace manifest + lints + deps |
| `rust-toolchain.toml` | `channel = "stable"` — latest stable, deliberately non-reproducible (see §4.1) |
| `rustfmt.toml` | edition 2024 strict format |
| `clippy.toml` | thresholds (cognitive 15, args 5, lines 80) |
| `deny.toml` | license allowlist + bans |
| `.cargo/config.toml` | aliases + link-arg lld |
| `.pre-commit-config.yaml` | prek hooks: pre-commit (heavy) + commit-msg (cog verify) + pre-push (cargo check) |
| `.taplo.toml` | taplo formatter config — preserves hand-aligned `=` columns and single-line dep arrays |
| `cog.toml` | cocogitto conventional commits |
| `typos.toml` | spell-check ignore list (BiBeam, 비빔) |
| `.editorconfig` | editor consistency |
| `Justfile` | dev tasks + `bootstrap` / `bootstrap-phase2` |
| `.github/workflows/ci.yml` | fmt + clippy + test matrix + doc + deny + cov |
| `crates/<11 crates>/Cargo.toml` + `src/{lib,main}.rs` | scaffolding (11 crate stubs incl. xtask) |
| `crates/<11 crates>/README.md` | per-crate one-paragraph READMEs (hand-written in 0.2a; xtask-owned from 0.2b onward; consumed by `#![doc = include_str!("../README.md")]`) |
| `crates/xtask/src/main.rs` (override) | hosts the `gen-readmes` subcommand (§5 xtask block) |
| `docs/{architecture,protocol,threat-model,operator-runbook}.md` | doc skeletons |
| `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`, `AGENTS.md` | project meta (AGENTS.md = AI-coding-assistant brief, §6) |
| `.gitignore` (append) | editor/OS/coverage/dist additions |

Total Phase 1 new files: ~47 (≈35 config + docs + 11 per-crate READMEs + AGENTS.md). Lines committed: ~1,400 (config + 11 thin crate stubs + xtask gen-readmes impl ≈80 LOC + 11 short READMEs + AGENTS.md ≤200 LOC).

**Phase 2 (later PR, not in init commit):**

| Path | Purpose |
|---|---|
| `cliff.toml` | git-cliff changelog template (§10.1) |
| `release-plz.toml` | release-PR automation config (§10.2) |
| `.github/workflows/release-plz.yml` | release-plz workflow (§10.3) |
| `.github/dependabot.yml` | weekly cargo + actions PRs (§10.4) |

---

## 10. Phase 2 Templates (Not Committed at Init)

These four templates are documented here for the follow-up PR that activates them. They are **not** created during the init commit and are **not** part of Phase 1 verification.

### 10.1 `cliff.toml`

```toml
[changelog]
header = """
# Changelog\n
All notable changes to BiBeam follow Keep-a-Changelog (https://keepachangelog.com/en/1.1.0/) and SemVer (https://semver.org/spec/v2.0.0.html).\n
"""
body = """
{% if version %}\
### [{{ version | trim_start_matches(pat="v") }}] - {{ timestamp | date(format="%Y-%m-%d") }}
{% else %}\
### [Unreleased]
{% endif %}\
{% for group, commits in commits | group_by(attribute="group") %}
#### {{ group | upper_first }}
{% for commit in commits %}\
- {% if commit.breaking %}**BREAKING** {% endif %}{{ commit.message | upper_first }}{% if commit.id %} ({{ commit.id | truncate(length=7, end="") }}){% endif %}
{% endfor %}\
{% endfor %}\n
"""
trim   = true

[git]
conventional_commits  = true
filter_unconventional = true
split_commits         = false
tag_pattern           = "v[0-9]*"
sort_commits          = "newest"

[[git.commit_parsers]]
message = "^feat"
group   = "Features"
[[git.commit_parsers]]
message = "^fix"
group   = "Bug Fixes"
[[git.commit_parsers]]
message = "^perf"
group   = "Performance"
[[git.commit_parsers]]
message = "^refactor"
group   = "Refactor"
[[git.commit_parsers]]
message = "^docs?"
group   = "Documentation"
[[git.commit_parsers]]
message = "^test"
group   = "Tests"
[[git.commit_parsers]]
message = "^(chore|ci|build)"
group   = "Build & CI"
[[git.commit_parsers]]
message = "^chore\\(release\\)"
skip    = true
```

### 10.2 `release-plz.toml`

```toml
[workspace]
changelog_update    = true
changelog_path      = "CHANGELOG.md"
git_release_enable  = true
git_release_draft   = false
git_release_latest  = true
publish             = false   # flip to true when ready to publish to crates.io
release_commits     = "^(feat|fix|perf|refactor|docs|chore|ci|build|test)(\\(.+\\))?!?:"
semver_check        = true
```

### 10.3 `.github/workflows/release-plz.yml`

Copy the upstream **release-plz Quickstart** workflow verbatim from <https://release-plz.dev/docs/github/quickstart>. Do not customize. When this file is added in the Phase 2 PR, take whatever the upstream quickstart prescribes at that moment (job shape, secret wiring, action version pins). No project-specific logic belongs here.

### 10.4 `.github/dependabot.yml`

```yaml
version: 2
updates:
  - package-ecosystem: "cargo"
    directory: "/"
    schedule: { interval: "weekly" }
    open-pull-requests-limit: 10
    groups:
      tokio-stack:   { patterns: ["tokio*", "futures*"] }
      crypto:        { patterns: ["snow", "*dalek*", "chacha20poly1305", "blake3"] }
      observability: { patterns: ["tracing*", "metrics*"] }
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule: { interval: "weekly" }
```
