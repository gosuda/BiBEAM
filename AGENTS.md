# AGENTS.md — AI Coding Assistant Brief

This file gives an AI coding assistant the minimum it needs to make a useful first change. Keep it tight; if a section grows, link out instead of expanding here.

## Quick facts

- **Project.** BiBEAM (브랜드 케이스), 비빔 in Hangul. Identifier `bibeam` (lowercase). Never substitute hanja, never romanize the Hangul to `bibim`.
- **Edition.** Rust 2024 (`resolver = "3"`).
- **Toolchain.** Latest stable. **No MSRV pin.** `rust-toolchain.toml` declares `channel = "stable"`. CI runs `dtolnay/rust-toolchain@stable`. There is no nightly, no per-version matrix, no `cargo +nightly` anywhere.
- **Phase.** Init scaffold (Phase 1). Crate skeletons compile and pass the strict regime; no protocol or transport code exists yet.

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

See [`docs/architecture.md`](./docs/architecture.md) for the crate boundary map, the two-plane control/data split, and the request flow. The eleven crates live under `crates/`:

`bibeam-core`, `bibeam-protocol`, `bibeam-crypto`, `bibeam-transport`, `bibeam-tun`, `bibeam-discovery`, `bibeam-runtime` (libraries) · `bibeam-coordinator`, `bibeam-node`, `bibeam-cli` (daemons) · `xtask` (ops runner).

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
- Treating Phase 2 features (release-plz, cargo-dist, dependabot, replication protocol, anonymity-set enforcement code) as if they exist today. They do not. They are designed in the plan and will land in later PRs.
- Adding a third-party dependency without checking the rubric in [`CONTRIBUTING.md`](./CONTRIBUTING.md) — active in the last 12 months, no RustSec advisory, latest release not yanked.

## Where to look first

- A new lint failure: [`clippy.toml`](./clippy.toml) and `[workspace.lints.*]` in [`Cargo.toml`](./Cargo.toml).
- A new hook failure: [`.pre-commit-config.yaml`](./.pre-commit-config.yaml).
- A CI failure that does not reproduce locally: the [GitHub workflow](./.github/workflows/ci.yml) runs three operating systems; macOS and Windows runners catch path and line-ending issues.
- A "where does this fit?" question: [`docs/architecture.md`](./docs/architecture.md).
- A "why does the scaffold look like this?" question: [`docs/plan/init.md`](./docs/plan/init.md) — the spec that drove Phase 1.
