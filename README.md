# BiBEAM (비빔)

[![ci](https://img.shields.io/badge/ci-stable--linux--macos--windows-blue)](./.github/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT-blue)](./LICENSE)
[![edition](https://img.shields.io/badge/rust-2024-orange)](./rust-toolchain.toml)

Bibeam is an open source, collaborative, distributed, E2E, non-exhaustive Peer-To-Peer VPN. Inspired by Korean food "Bibimbap". Also interpreted as Bidirectional-Beam (Bi-Beam); loose Privacy-enhancing Network.

## Status

**Phase 1 init scaffold.** The workspace builds on the latest stable toolchain, the strict regime is wired (`#![forbid(unsafe_code)]`, strict clippy, conventional commits enforced by `cog verify`), and CI runs fmt + clippy + nextest matrix + doc + deny + machete + coverage on every PR.

**No tunnel functionality has been implemented yet.** Crate skeletons declare boundaries; modules are empty. The two daemon binaries (`bibeam-node`, `bibeam-cli`) currently print `bootstrap version=0.0.1` and exit on SIGINT. Protocol code lands in subsequent PRs.

## Quickstart

```bash
# install the Phase-1 dev tooling once (prek, nextest, typos, cocogitto, taplo)
just bootstrap

# build the workspace on the latest stable toolchain
cargo build --workspace --all-features

# run the full local CI pipeline (fmt + clippy + tests + doc + deny + machete)
just ci
```

## Workspace

Seven libraries + two role-specific daemons + one ops runner. See [docs/architecture.md](./docs/architecture.md) for the crate boundary map and request flow.

| Crate | Role |
|---|---|
| [`bibeam-core`](./crates/bibeam-core) | Shared types, errors, identity primitives |
| [`bibeam-protocol`](./crates/bibeam-protocol) | Wire frames + postcard codec |
| [`bibeam-crypto`](./crates/bibeam-crypto) | Noise IK, AEAD, PASETO, key management |
| [`bibeam-transport`](./crates/bibeam-transport) | QUIC + Noise datagram tunnel + STUN hole-punch |
| [`bibeam-tun`](./crates/bibeam-tun) | Cross-platform TUN device + L3 packet pipeline |
| [`bibeam-discovery`](./crates/bibeam-discovery) | Coordinator client + rendezvous types |
| [`bibeam-runtime`](./crates/bibeam-runtime) | Tracing, metrics, config, signals, health |
| [`bibeam-node`](./crates/bibeam-node) | Merged data-plane (relay/exit/forwarder) + control-plane (rendezvous/admission/rotation) daemon, gated by `is_coordinator` flag (per §11 R-1) |
| [`bibeam-cli`](./crates/bibeam-cli) | End-user client daemon + CLI |
| [`xtask`](./crates/xtask) | Workspace ops runner (CI, docs, release helpers) |

Per-crate `README.md` files are **generated** by `cargo run -p xtask -- gen-readmes` from each `[package].description`. Do not hand-edit them; edit `Cargo.toml` instead. The drift-check runs in pre-commit and CI.

## Reading order

1. [`docs/architecture.md`](./docs/architecture.md) — two-plane diagram, crate boundaries, request flow.
2. [`docs/protocol.md`](./docs/protocol.md) — wire format, handshake, token claims, cohort lifecycle.
3. [`docs/threat-model.md`](./docs/threat-model.md) — adversaries, scope, mitigations.
4. [`docs/operator-runbook.md`](./docs/operator-runbook.md) — bringing up a coordinator or node.
5. [`CONTRIBUTING.md`](./CONTRIBUTING.md) — strict regime, dep-selection rubric, commit conventions.
6. [`AGENTS.md`](./AGENTS.md) — brief for AI coding assistants.
7. [`docs/plan/init.md`](./docs/plan/init.md) — the spec that drove the Phase-1 init scaffold (as-built rationale).

## License

MIT — see [LICENSE](./LICENSE). Copyright the BiBEAM contributors.
