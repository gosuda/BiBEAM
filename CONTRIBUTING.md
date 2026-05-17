# Contributing to BiBeam

Thanks for reading before opening a PR. The rules below are enforced by hooks and CI; the rationale is in the linked plan or doc.

## Commits — conventional, validated by cocogitto

Every commit message is checked by `cog verify` at commit-msg time. The format is [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/):

```
<type>(<scope>)?: <subject>

<body — optional, wrap at 100 cols>

<footer — optional, BREAKING CHANGE: …>
```

Accepted types: `feat`, `fix`, `perf`, `refactor`, `docs`, `test`, `chore`, `ci`, `build`, plus the two project-specific types declared in [`cog.toml`](./cog.toml) (`hotfix`, `release`).

If `git commit` is rejected, read the line above the error — that is the offending commit text.

## Branches

- `main` is protected and always green.
- Feature branches are short-lived. Name them `<type>/<short-slug>` (e.g. `feat/noise-handshake`).
- Rebase before opening a PR; merge with squash or rebase, not merge commits.

## Strict regime — what gates you locally

Before any commit lands, `prek install` (run during `just bootstrap`) arms three Git hooks:

- **pre-commit (heavy).** `cargo fmt --check`, `taplo fmt --check`, `typos`, `xtask gen-readmes --check`, `cargo clippy -- -D warnings`, `cargo nextest run`, `cargo deny check`, `cargo machete`, `cargo doc -D warnings`. Failing here costs nothing — fix and re-stage.
- **commit-msg.** `cog verify`. Rejects anything that is not a Conventional Commit.
- **pre-push.** `cargo check` only. Intentionally light — CI is the cross-OS authority.

The heavy hook policy is deliberate: a contributor should fail before investing in a commit message they would then have to rewrite. See [`.pre-commit-config.yaml`](./.pre-commit-config.yaml) for the hook spec.

`just ci` runs the same checks the GitHub workflow runs. Use it before pushing.

## Lint policy

- `#![forbid(unsafe_code)]` is set workspace-wide. First-party code never writes `unsafe { … }`. Third-party crates that wrap unsafe (TUN device, sockets, crypto primitives) are acceptable; supply-chain risk is enforced via `cargo deny check advisories`.
- Clippy runs `pedantic` + `nursery` + `cargo` groups at warn; CI escalates to `-D warnings`.
- Cognitive complexity is capped at 15. State machines that genuinely exceed it may carry a per-function `#[allow(clippy::cognitive_complexity)]` with a one-line justification in the commit body.
- Surgical restriction-lint deny list (in [`Cargo.toml`](./Cargo.toml) under `[workspace.lints.clippy]`): `panic`, `unwrap_used`, `expect_used`, `todo`, `unimplemented`, `unreachable`, `dbg_macro`, `print_stdout`, `print_stderr`, `mem_forget`, `unwrap_in_result`, `let_underscore_must_use`. Tests are exempt for unwrap/expect/panic/dbg/print via [`clippy.toml`](./clippy.toml).
- See [`clippy.toml`](./clippy.toml) for thresholds and disallowed APIs (e.g. prefer `parking_lot::Mutex` over `std::sync::Mutex`).

## Per-crate READMEs are generated

Do **not** hand-edit `crates/*/README.md`. The xtask tool regenerates each one from `[package].description` in that crate's `Cargo.toml`:

```bash
cargo run -p xtask -- gen-readmes          # write
cargo run -p xtask -- gen-readmes --check  # drift gate (runs in pre-commit and CI)
```

To change the rendered text of a crate README, edit its `Cargo.toml` description and re-run the generator.

## Adding a third-party dependency

Review-time rubric — not a CI gate, but expected before any `cargo add`:

- **Maintenance.** Most recent commit within the last 12 months; no abandoned-status banner on the repo or crates.io page.
- **Advisories.** No open RustSec advisory against the version you are pulling in. CI enforces this via `cargo deny check advisories`.
- **Yanked.** The latest published release on crates.io is not yanked.
- **Fit.** Prefer the de-facto crate (the one most of the ecosystem uses) over a niche one, even if the niche one has a sleeker API. Workspace-pinned deps live in `[workspace.dependencies]`; add them there and consume via `{ workspace = true }` in the consuming crate.
- **License.** Compatible with MIT — check `deny.toml` allowlist before adding anything outside it.

If a dep clears the rubric but you are not sure it belongs, open an issue with the rationale before opening the PR.

## What gets reviewed

PRs are reviewed against three axes, in order:

1. **Correctness.** Does the change do what the description says, and does it not break anything else?
2. **Hygiene.** All hooks green, no `cargo doc` warnings, no new clippy `#[allow]` without commit-body justification.
3. **Footprint.** Does the change add complexity proportional to the value it delivers? Speculative abstractions, unused fields, and "we might want this later" code are removed before merge.

## Reporting security issues

Do not open a public issue for vulnerabilities. See [`SECURITY.md`](./SECURITY.md) for disclosure.
