# BiBEAM — Exhaustive Task Breakdown (Phase 2 + Feature Crates)

> **Source.** Derived from `docs/plan/init.md` (the as-built Phase-1 plan). Phase 1 (init scaffold) landed at HEAD `5d8817a`; all seven §0 steps are complete. This file enumerates the work that remains.
>
> **Activation rule (verbatim from plan §2.5).** The Phase 2 PR opens the moment the **first non-stub merge** lands on `main` — i.e., as soon as any feature crate gains its first real (non-skeleton) module via a merged PR. Until then, the templates in §10 of the plan live in `docs/plan/init.md` only; no `release-plz.toml` / `dependabot.yml` / `cliff.toml` file exists in the repo.
>
> **Sequencing rule.** Tasks are grouped by phase and ordered by dependency. Per-crate feature tasks (`F-*`) follow the crate dependency graph: `core → protocol|crypto|runtime|tun → transport|discovery → coordinator|node|cli`. Each task is intended to be one or more atomic commits scoped to a single concern; `git move --fixup` is the splitting tool when a single PR spans more than one concern.
>
> **Gate rule.** No task is "done" until its named gate passes. Pre-commit and pre-push hooks run on every commit per `.pre-commit-config.yaml`; the CI workflow `.github/workflows/ci.yml` is the cross-OS authority.

---

## Phase 1 — Init Scaffold (status: complete at HEAD `5d8817a`)

| # | Step | Status |
|---|---|---|
| 0.1 | Project structure (11 crates × `src/`, `docs/`, `.github/workflows/`, `.cargo/`) | done |
| 0.2a | Workspace `Cargo.toml` + 10 crate stubs + hand-written placeholder READMEs | done |
| 0.2b | xtask binary + `gen-readmes` subcommand + workspace-member append | done |
| 0.2c | Drop MSRV pin (workspace + 11 per-crate manifests) | done |
| 0.2d | Bump workspace deps to latest stable | done |
| 0.3 | Lint / format / supply-chain configs (rustfmt, clippy, deny, .cargo, editorconfig, typos, cog) | done |
| 0.4 | Pre-commit hooks (prek) + `.taplo.toml` + `Justfile` + `bootstrap` recipe | done |
| 0.5 | CI workflow (fmt + clippy + nextest matrix + doc + deny + machete + llvm-cov) | done |
| 0.6 | Doc skeletons (`README`, `CONTRIBUTING`, `SECURITY`, `CHANGELOG`, `AGENTS`, `docs/{architecture,protocol,threat-model,operator-runbook}.md`) | done |
| 0.7 | `.gitignore` extension (editor / OS / coverage / dist) | done |

---

## Phase 2 — Release Tooling Templates (gated on first non-stub merge)

These four files are documented in plan §10 and **must not** be created until the first feature-crate PR has merged. They land in a single follow-up PR.

### P2T-1 — Add `cliff.toml` (changelog template)

- **File.** `cliff.toml` at repo root.
- **Content source.** Plan §10.1 (verbatim).
- **Why.** Drives `git cliff` changelog generation against conventional commits; release-plz consumes the generated CHANGELOG.md fragment.
- **Gate.** `git cliff --tag v0.0.1` exits 0 and emits the expected `### [0.0.1]` header against the current commit history.

### P2T-2 — Add `release-plz.toml` (release-PR automation config)

- **File.** `release-plz.toml` at repo root.
- **Content source.** Plan §10.2 (verbatim).
- **Publish flag.** Stays `publish = false` until the team is ready to push to crates.io.
- **Gate.** `release-plz update --dry-run` exits 0 with a non-empty diff plan (or "nothing to release" on a no-feat-no-fix history).

### P2T-3 — Add `.github/workflows/release-plz.yml` (release workflow)

- **File.** `.github/workflows/release-plz.yml`.
- **Content source.** Plan §10.3 — copy the upstream release-plz Quickstart workflow verbatim from <https://release-plz.dev/docs/github/quickstart>. No project-specific customization.
- **Secret.** Requires `CARGO_REGISTRY_TOKEN` (later, when `publish = true`) and `GITHUB_TOKEN` (default).
- **Gate.** Push to a draft PR; workflow runs and emits a `release-plz` PR body without error. No tag is created in dry-run.

### P2T-4 — Add `.github/dependabot.yml` (weekly dep PRs)

- **File.** `.github/dependabot.yml`.
- **Content source.** Plan §10.4 (verbatim — cargo + github-actions, weekly, grouped).
- **Groups.** `tokio-stack`, `crypto`, `observability` (matches plan §10.4 patterns).
- **Gate.** GitHub Settings → Dependabot shows the manifest parsed without error.

### P2T-5 — Add coverage threshold gate to CI

- **File.** `.github/workflows/ci.yml` (edit the existing `coverage` job).
- **Change.** Append `--fail-under-lines <N>` to the `cargo llvm-cov nextest` invocation; pick `N` empirically against the first feature-crate merge baseline (start at 60 %, ratchet up per merge).
- **Why.** Plan §2.5 says Phase-1 coverage is report-only; Phase-2 introduces the gate.
- **Gate.** PR with coverage below `N` fails the `coverage` job.

### P2T-6 — Run `cargo dist init` and commit generated artifacts

- **Files.** Whatever `cargo dist init` emits — typically `.github/workflows/release.yml` + `dist-workspace.toml` (or per-package `[workspace.metadata.dist]`). Do not hand-author target lists; D-2 governs target selection.
- **Targets.** Per D-2; defer to the interactive walkthrough.
- **Why.** Multi-target binary releases on Git-tag.
- **Gate.** `cargo dist plan` enumerates the targets D-2 selected; `cargo dist build --artifacts=archives` succeeds locally for the host target.

### P2T-7 — Verify `just bootstrap-phase2` installs Phase-2 tooling

- **No file change.** This is a verification task.
- **Run.** `just bootstrap-phase2` on a clean shell → installs `git-cliff`, `release-plz`, `cargo-dist`.
- **Gate.** Each binary is on `$PATH` after the recipe completes; `git cliff --version`, `release-plz --version`, `cargo dist --version` all exit 0.

---

## Phase 2 — Architectural-Research Checkpoint (plan §2.5.1)

### P2A-1 — Pick coordinator replication protocol

- **File.** `docs/architecture.md` (edit; no new file).
- **Options.** (a) gossip + Δ-CRDT, (b) lightweight leader-election with lease + heartbeat, (c) openraft-Raft.
- **Direction.** "Lightweight but robust" per plan §2 decision #7.
- **Deliverable.** One subsection in `docs/architecture.md` that names the pick, lists the two rejected options with one-sentence dismissals, and links to the follow-up PR that will implement it. Implementation lands separately.
- **Gate.** PR review approves the pick on rationale; `cargo doc -D warnings` still passes.

---

## Phase 2 — Decision Checkpoints (must land before the implementations they unblock)

Each item is a docs-only PR that edits `docs/architecture.md` (or `docs/protocol.md` where the surface is wire-format) to name the pick, the dismissed alternatives, and the implementation-task list the decision unblocks. No implementation code lands inside a decision PR; that is what the downstream task is for.

### D-1 — ECH (Encrypted ClientHello) strategy

- **Context.** Plan §2 decision #8 names TLS 1.3 ECH as the *primary* 451 defense, but rustls's ECH support is experimental / feature-flagged at time of writing, and the architectural question of *which hop* ECH protects is unresolved: (i) BiBEAM's own control-plane connections (CLI → coordinator), (ii) the user-app's end-to-end TLS to the destination (BiBEAM is transparent and ECH is the user-app's responsibility), (iii) a TLS-terminating HTTPS proxy at the exit (privacy-hostile — exit would see plaintext). Locking F-TRANS.2 / F-NODE.4 / F-CLI.7 to ECH without picking is speculation.
- **Options.** (a) best-effort ECH on BiBEAM's own outgoing TLS (control-plane only); user-app TLS is transparent and operator-documented as the user's responsibility. (b) defer ECH entirely; primary 451 defense becomes cohort mixing + IP washing alone (plan §2 decision #8's "secondary" layer becomes the actual primary). (c) skipped — explicit decision not to attempt ECH at MVP. (TLS-terminating proxy at the exit is **rejected** by `docs/threat-model.md` — the exit must not see plaintext.)
- **Deliverable.** `docs/architecture.md` subsection naming the pick + dismissed alternatives.
- **Blocks.** F-TRANS.2, F-NODE.4 (SNI-obfuscation behavior), F-CLI.7 (policy exposure).

### D-2 — Release-binary target list

- **Context.** `cargo dist init` is interactive; the target list is the decision it asks for. Locking the list inside an implementation PR mixes a decision (which targets ship at MVP) with an execution step (running `cargo dist init`). Separating them keeps reviewer attention on the policy question.
- **Options.** (a) the four targets named in plan §2 decision #14 — Linux `x86_64-unknown-linux-gnu` + `aarch64-unknown-linux-gnu`, macOS `aarch64-apple-darwin`, Windows `x86_64-pc-windows-msvc`. (b) a reduced set (e.g. Linux x86_64 only at MVP, others post-MVP). (c) an expanded set (e.g. add `x86_64-apple-darwin` for Intel Macs).
- **Deliverable.** `docs/architecture.md` subsection naming the picked target list + rationale (per-target cost vs. coverage trade-off).
- **Blocks.** P2T-6 (the `cargo dist init` execution itself, which consumes this decision and commits the tool-emitted `dist-workspace.toml` + release workflow).

### D-3 — Exit-mode L3 forwarding mechanism

- **Context.** Two viable mechanisms for raw-IP exit traffic: OS-level NAT (Linux `nftables` / macOS `pf` / Windows ICS) versus a userspace TCP/UDP stack via `smoltcp`. OS NAT is operationally simpler but requires NAT-table mutation on the host; userspace `smoltcp` is operator-isolation-friendly but adds a full TCP/UDP stack to the dependency surface and forecloses on cross-platform parity.
- **Options.** (a) OS NAT only at MVP, userspace `smoltcp` as a post-MVP enhancement; (b) userspace `smoltcp` at MVP, no OS-NAT path; (c) both, selected by per-node config.
- **Deliverable.** `docs/architecture.md` subsection naming the pick + dismissed alternatives.
- **Blocks.** F-NODE.4 L3 path.

### D-4 — VPN protocol family (de-facto vs purpose-built)

- **Context.** The plan's data-plane is purpose-built — Noise_IK_25519_ChaChaPoly_BLAKE3 over QUIC datagrams (plan §2 decisions #9, #10). Project-owner direction added mid-stream: *"Use more de-facto VPN protocols and structures for more general availability/compat."* That surfaces a trade-off the plan did not surface — ride an existing wire protocol so existing clients, configs, and tooling interoperate, vs. ship a custom protocol optimized for cohort-mixing. Locking F-CRYPTO.1 and the QUIC-specific F-TRANS sub-items to the custom path without a decision is now speculation.
- **Options.** (a) **WireGuard wire-compat** — use `boringtun` or a pure-Rust WG implementation as the data plane; the coordinator becomes a discovery + cohort-assignment layer over standard WG. Existing WireGuard clients and configs interoperate. (b) **Custom Noise_IK + QUIC** per the original plan — purpose-built, no off-the-shelf-client compat. (c) **Multi-protocol** — WireGuard as the primary data plane for general clients + custom Noise_IK + QUIC as an opt-in alternate for advanced / latency-sensitive flows. (OpenVPN bridging is **rejected**: OpenVPN's TLS-tunneled-OpenSSL design conflicts with our `rustls`-only + `forbid(unsafe_code)` posture.)
- **Deliverable.** `docs/architecture.md` subsection naming the pick + dismissed alternatives + a compatibility-vs-control rationale.
- **Blocks.** F-CRYPTO.1 (Noise IK wrapper — may become WireGuard's Noise_IK exact variant or move into a wg crate). F-TRANS.1, F-TRANS.3, F-TRANS.5, F-TRANS.6 (Quinn endpoint, datagram extension, hole-punch, relay-fallback — semantics differ between WG and custom QUIC). F-NODE.4 (exit path uses whichever data plane D-4 selects).

---

## Per-Crate Feature Implementation (dependency-ordered)

Each per-crate task is the **first non-stub merge** for that crate. Sub-items are concerns within the crate; each sub-item is one atomic commit per the `<git>` charter ("one concern per commit"). The first sub-item that lands on `main` triggers Phase 2 activation (see P2T-1..P2T-7 above).

### F-CORE — `bibeam-core` (foundational; no upstream deps)

- **F-CORE.1** PeerId / NodeId / CohortId — ULID newtypes with `serde` + `Display` + `FromStr`.
- **F-CORE.2** `Error` enum — `thiserror` derive; one variant per failure class (`Config`, `Crypto`, `Transport`, `Protocol`, `Storage`, `Io`).
- **F-CORE.3** Identity primitives — public-key fingerprint type (32-byte BLAKE3 over X25519 pub-key), constant-time equality.
- **F-CORE.4** BLAKE3-keyed PII redaction — `RedactionKey` newtype, `redact_peer_id`, `redact_ip` helpers; key loaded from env in `bibeam-runtime` and threaded through.
- **F-CORE.5** `Result<T>` type alias — `pub type Result<T> = std::result::Result<T, Error>;`.
- **F-CORE.6** Time wrapper types — `Timestamp` newtype around `time::OffsetDateTime` with serde/postcard formatting pinned to RFC 3339.
- **Gate.** `cargo clippy -p bibeam-core --all-targets --all-features -- -D warnings` + `cargo doc -p bibeam-core --no-deps` clean.

### F-PROTO — `bibeam-protocol` (depends on `bibeam-core`)

- **F-PROTO.1** `Frame` enum + magic bytes — 4-byte magic, 1-byte version, postcard-serialized body.
- **F-PROTO.2** postcard codec — `Frame::encode(&self) -> bytes::Bytes`, `Frame::decode(&[u8]) -> Result<Self>`; round-trip property test using `proptest`.
- **F-PROTO.3** Control-plane messages — `Register`, `RegisterAck`, `MatchRequest`, `MatchResponse`, `Heartbeat`, `Disconnect`; all `#[derive(Serialize, Deserialize)]`.
- **F-PROTO.4** Data-plane datagram frame — `Tunnel { peer_id: PeerId, payload: bytes::Bytes }` — for Noise-sealed-IP payloads carried in QUIC datagrams.
- **F-PROTO.5** Cohort lifecycle messages — `CohortAdmit`, `CohortLive`, `CohortRotate` per plan §2 decision #8 and `docs/protocol.md`.
- **F-PROTO.6** PASETO claim struct — `SessionClaims { sub: PeerId, cohort: CohortId, exp: Timestamp, exit_set: Vec<NodeId> }`; matches `bibeam-crypto`'s PASETO issuer.
- **F-PROTO.7** Error codes enum — `ProtocolError` with `From` impls for `postcard::Error` and `bibeam_core::Error`.
- **Gate.** `cargo clippy -p bibeam-protocol …` clean + property tests under `cargo nextest run -p bibeam-protocol` pass.

### F-CRYPTO — `bibeam-crypto` (depends on `bibeam-core`; scope narrowed by D-4)

D-4 (WireGuard wire-compat via `boringtun`) places the data-plane packet handle in `bibeam-transport` (see F-TRANS.1) — boringtun owns the Noise_IK_25519_ChaChaPoly_BLAKE2s handshake and per-packet AEAD internally. This crate's responsibility narrows to **pure key and material helpers**: the X25519 / Ed25519 keys BiBEAM mints, the PASETO v4 session tokens the coordinator issues, the BLAKE3-keyed-hash invite-code derivation, the HKDF key-stretching used in both planes, and the Zeroize + constant-time-compare hygiene primitives. No packet processing, no config-file rendering, no `wg-quick`-shaped serialization — those live in `bibeam-transport`.

**Secret lifecycle (load-bearing — defines who owns which derivation):** invite-code material flows through this crate in two distinct stages with **non-overlapping ownership**:
1. **Per-invite (long-term).** F-CRYPTO.6 BLAKE3-keyed-hashes `(master_invite, invite_code)` → `SessionPSK` (32 bytes). One per invite redemption. Persists across rotations.
2. **Per-rotation (short-term).** F-CRYPTO.5 HKDF-extracts-then-expands `SessionPSK` with rotation-scoped info (`b"bibeam/wg-psk/v1"` plus the rotation counter) → `WgPsk` (32 bytes). One per session-rotation window. Fed into F-TRANS.1's WG peer setup.

F-CRYPTO.1 does **not** derive any PSK — it only generates the X25519 keypair and exposes its WG-wire base64 form. Config-shape assembly (combining keypair + PSK + endpoint + allowed-IPs into a peer-config record + rendering `wg-quick`-parseable text) lives in `bibeam-transport`.

- **F-CRYPTO.1** **X25519 keypair primitives for WG peers** — generate an `x25519-dalek` `StaticSecret` + derived `PublicKey`; encode the public key in WireGuard-wire base64 form and decode the inverse; round-trip preserves bytes. **No PSK derivation, no config rendering, no boringtun dep here.**
- **F-CRYPTO.2** **control-plane AEAD wrapper** — `chacha20poly1305` `Aead::seal` / `Aead::open` for non-WG sealing needs (PASETO claim-extension sealing, redb audit-log entry sealing). The data-plane AEAD is owned by boringtun inside `bibeam-transport` and is not exposed here.
- **F-CRYPTO.3** Long-term identity keypair — `ed25519-dalek` `SigningKey` / `VerifyingKey`; PEM-encoded persistence helpers. Used for invite-code signing (coordinator side) and verification (client side) — separate from F-CRYPTO.1's X25519 WG-peer keys.
- **F-CRYPTO.4** PASETO v4 issuer + verifier — `pasetors::v4` public-key flow; `Issuer::issue(claims) -> Token`, `Verifier::verify(token) -> Claims`. The token authorizes the coordinator-issued WG peer config for a cohort assignment.
- **F-CRYPTO.5** **HKDF rotation-scoped key derivation** — `derive_wg_psk(session_psk: &SessionPSK, rotation_counter: u64) -> WgPsk`; HKDF-extract-then-expand with info `b"bibeam/wg-psk/v1"` + the rotation counter encoded LE. Sole owner of the per-rotation WG PSK derivation. Also exposes a general `derive_subkey(prk, info) -> [u8; 32]` for any other control-plane sub-key need (matching the original spec but with the WG PSK case promoted to a named, dedicated entry-point).
- **F-CRYPTO.6** **Invite-code → SessionPSK derivation** — `derive_session_psk(master_invite: &MasterInviteKey, invite_code: &InviteCode) -> SessionPSK`; BLAKE3-keyed-hash. Sole owner of the per-invite long-term PSK. Does not produce the WG PSK directly — that is F-CRYPTO.5's job.
- **F-CRYPTO.7** `Zeroizing` wrappers for `[u8; 32]` secrets — `derive Zeroize, ZeroizeOnDrop`. Applies to `SessionPSK`, `WgPsk`, and the X25519 `StaticSecret`.
- **F-CRYPTO.8** Constant-time compare — `subtle::ConstantTimeEq` on tokens, MAC tags, and key fingerprints.
- **Gate.** `cargo clippy -p bibeam-crypto …` clean + integration tests in this crate pass: (a) PASETO v4 issue → verify round-trip produces the same claims; (b) F-CRYPTO.6 `derive_session_psk` is deterministic across runs given identical inputs; (c) F-CRYPTO.5 `derive_wg_psk` produces distinct outputs for distinct rotation counters on the same `SessionPSK`; (d) X25519 WG keypair base64 encode → decode preserves the public-key bytes.

### F-RT — `bibeam-runtime` (depends on `bibeam-core`)

- **F-RT.1** `tracing-subscriber` JSON formatter — env-filter from `RUST_LOG`, JSON output to stdout.
- **F-RT.2** BLAKE3-keyed PII redaction layer — `tracing::Layer` impl that wraps `peer_id` / `ip` fields with `bibeam_core::redact_*`.
- **F-RT.3** Prometheus `/metrics` exporter — `metrics-exporter-prometheus` mounted under an axum router; histogram + counter helpers.
- **F-RT.4** `/healthz` + `/readyz` endpoints — `axum::Router` with `200 OK` once readiness latch is set.
- **F-RT.5** `figment` config loader — TOML file (path from `--config` or `BIBEAM_CONFIG` env) + `BIBEAM_` env-prefix overlay.
- **F-RT.6** Signal handling — `tokio::signal::unix::signal(SignalKind::interrupt|terminate)`; no SIGHUP for MVP per plan §8.
- **F-RT.7** Graceful shutdown helper — `CancellationToken` plumbed to every spawned task; bounded shutdown deadline.
- **F-RT.8** `mimalloc` allocator wiring — `#[global_allocator]` on the three server binaries (gate-controlled by a `mimalloc` feature on each bin).
- **Gate.** `cargo clippy -p bibeam-runtime …` clean + `curl http://localhost:<port>/healthz` returns `200 OK` in an integration smoke test.

### F-TUN — `bibeam-tun` (depends on `bibeam-core`)

- **F-TUN.1** TUN device creation — `tun-rs` async wrapper; per-OS branch (Linux netlink, macOS utun, Windows wintun).
- **F-TUN.2** L3 IP packet parser — `etherparse::PacketHeaders` for v4 / v6, `Result<(IpHeader, payload)>` accessor.
- **F-TUN.3** Outbound pipeline — `read TUN → classify (v4/v6, src/dst) → seal (bibeam-crypto AEAD) → emit datagram-out channel`.
- **F-TUN.4** Inbound pipeline — `datagram-in channel → decrypt (bibeam-crypto) → unseal → write TUN`.
- **F-TUN.5** IPv4 + IPv6 — both must be testable end-to-end.
- **F-TUN.6** MTU negotiation + TCP MSS clamping — derive MSS from negotiated path MTU, rewrite TCP SYN options for traversal.
- **F-TUN.7** Per-flow tracking — 5-tuple `(proto, src_ip, src_port, dst_ip, dst_port)` keyed `DashMap` of `FlowState`.
- **F-TUN.8** Backpressure — bounded `tokio::sync::mpsc` channels at every queue boundary; transport-neutral uniform drop-newest-on-overflow policy in the MVP. No QoS classifier lives in the tunnel; per-class scheduling (DSCP-aware, flow-keyed) is a deferred enhancement that lands as its own task only after a classifier exists.
- **Gate.** `cargo clippy -p bibeam-tun …` clean + on Linux, a loopback test brings up a TUN, writes a UDP packet, and reads it on the other side.

### F-TRANS — `bibeam-transport` (depends on `core`, `protocol`, `crypto`; data-plane reshaped by D-4)

Per D-4, the data plane is **WireGuard (UDP)** via `boringtun`, not Quinn QUIC + RFC 9221 datagrams. This crate owns: the UDP socket plumbing wrapping boringtun, the BiBEAM-side `WgTunnel` packet handle (peer add/remove, encrypt/decrypt path), the `WgPeerConfig` shape + `wg-quick`-parseable rendering (moved here from F-CRYPTO per D-4's architecture line — config-shape rendering encodes a transport peer relationship, not a key derivation), the STUN-based hole-punch, the relay-fallback path, the SOCKS5-fallback bridge, the rate limiter, and the rustls config for BiBEAM's *own* coordinator-bound HTTPS only (not user-app TLS — that's end-to-end). QUIC / RFC 9221 references are retired.

- **F-TRANS.1** **boringtun + UDP socket wrapper** — add `boringtun` to `[workspace.dependencies]` and to this crate's `[dependencies]`. `tokio::net::UdpSocket` plus a `WgTunnel` handle wrapping boringtun's `Tunn` (or current equivalent). Receives incoming UDP packets, feeds them through boringtun's decap, surfaces decrypted IP frames upward; takes outgoing IP frames downward, feeds them through boringtun's encap, sends as UDP packets. Peer add/remove + per-peer counters surface upward. Replaces the original Quinn endpoint wrapper.
- **F-TRANS.2** **rustls config for coordinator-bound HTTPS only** — `rustls-ring` base config for BiBEAM's own control-plane HTTPS (CLI/node → coordinator). Per D-1, user-app TLS is end-to-end and BiBEAM-transparent; this crate does NOT terminate user TLS. ECH on BiBEAM's own HTTPS lands as a follow-up PR once rustls's ECH stabilizes.
- **F-TRANS.3** **`WgPeerConfig` assembly + `wg-quick` rendering** *(repurposed from the retired RFC 9221 datagram extension, which is moot under D-4)*. Define `pub struct WgPeerConfig { public_key, preshared_key, endpoint, allowed_ips, persistent_keepalive }` combining F-CRYPTO.1's X25519 public key + F-CRYPTO.5's `WgPsk`. Implement `to_wg_quick(&self) -> String` producing a `wg-quick`-parseable `[Peer]` section. Used by the coordinator to mint configs and by `bibeam-cli` to render configs for stock WireGuard clients. Round-trip-verified against a captured `wg-quick` fixture.
- **F-TRANS.4** STUN client (RFC 8489) — public-address discovery; one binding-request to a configured STUN server. Operates directly on this crate's UDP socket.
- **F-TRANS.5** ICE-lite simultaneous-open hole-punch — both peers send WG handshake initiations to each other's STUN-discovered addr at a sync'd timestamp orchestrated by the coordinator. The hole-punch packets ARE the boringtun handshake first message.
- **F-TRANS.6** Relay fallback — when hole-punch fails (5-s timeout), redirect WG packets via the assigned relay node. Relay forwards WG datagrams between two cohort members.
- **F-TRANS.7** SOCKS5 fallback — `fast-socks5` over a side-channel for restricted networks where TUN is not available. The `bibeam-cli` daemon hosts the local SOCKS5 listener (F-CLI.8) and forwards via this transport.
- **F-TRANS.8** Per-session rate limiter — `governor::RateLimiter` on bytes/sec per session; coordinator-configurable.
- **F-TRANS.9** Connection telemetry — `tracing` spans for WG handshake, hole-punch, relay-fallback, decrypt-failure counters.
- **Gate.** `cargo clippy -p bibeam-transport …` clean + a two-process integration test establishes a WireGuard tunnel over localhost UDP through `WgTunnel` and exchanges a 1-MB payload; `WgPeerConfig::to_wg_quick()` output is byte-identical to a captured `wg-quick` fixture for a fixed input.

### F-DISC — `bibeam-discovery` (depends on `core`, `protocol`, `crypto`)

- **F-DISC.1** Coordinator HTTP client — `reqwest::Client` with rustls; endpoints from plan §6 `docs/protocol.md`.
- **F-DISC.2** WebSocket client — `tokio-tungstenite` for coordinator-pushed match / rotation notifications.
- **F-DISC.3** Coordinator round-robin failover — 2–3 super-peers configured; retry next on transport error per plan §2 decision #7.
- **F-DISC.4** pkarr-on-Mainline-DHT fallback — when **all** configured coordinators are unreachable; pkarr-published peer records.
- **F-DISC.5** Rendezvous types — `PeerRecord`, `RelayRecord`, `ExitRecord` with serde + postcard.
- **F-DISC.6** Invite-code validator — verify Ed25519 signature on invite payload against coordinator's published pubkey.
- **F-DISC.7** Session bootstrap protocol — happy path: `redeem invite → register → receive session token (PASETO) → receive cohort assignment`.
- **Gate.** `cargo clippy -p bibeam-discovery …` clean + an in-process mock coordinator drives the full bootstrap to a PASETO-issued session.

### F-COORD — `bibeam-coordinator` (depends on all libs; bin)

- **F-COORD.1** axum HTTP server — `/v1/register`, `/v1/match`, `/v1/heartbeat`, `/v1/disconnect` plus WS upgrade endpoint.
- **F-COORD.2** redb-backed peer registry — peers keyed by `PeerId`, value = `PeerRecord` (last-seen, exit-capability flag, capacity).
- **F-COORD.3** redb-backed cohort assignments — cohorts keyed by `CohortId`, value = `{ members: Vec<PeerId>, exit_set: Vec<NodeId>, rotation_deadline: Timestamp }`.
- **F-COORD.4** PASETO token issuance — at successful admission, issue session token with `SessionClaims` (F-PROTO.6).
- **F-COORD.5** Anonymity-set ≥30 invariant at admission — per plan §2 decision #8; refuse `MatchResponse` when current cohort has < 30 live members; bucket pending clients until threshold met.
- **F-COORD.6** Cohort rotation scheduler — re-pool every 15 min or 500 MB per-session (admission-time); enforce ≥30 invariant on re-pool.
- **F-COORD.7** Invite-code admission flow — verify Ed25519 invite signature, log redemption (BLAKE3-keyed-hash of invite + IP), debit redemption count.
- **F-COORD.8** Operator audit log — append-only redb table; one entry per admission / rotation / token-issuance / invite-redeem.
- **F-COORD.9** Rate limiting — `governor` per source-IP + per-PeerId; aggressive thresholds tuned for Oracle ARM Free Tier.
- **F-COORD.10** BLAKE3-keyed PII hash before logging — wraps every `tracing::info!(peer_id = …)` via the `bibeam-runtime` redaction layer.
- **F-COORD.11** Health / readiness — `/healthz` always-200, `/readyz` reflects redb open + axum bound state.
- **F-COORD.12** Multi-coordinator failover wiring — independent coordinators per plan §2 decision #7; no inter-coord state (until P2A-1's replication-protocol PR lands).
- **Gate.** `cargo clippy -p bibeam-coordinator …` clean + an end-to-end test on a single coordinator process: register two peers, satisfy admission floor with a 30-member fixture, issue a token, verify token against `bibeam-crypto` verifier.

### F-NODE — `bibeam-node` (depends on all libs; bin)

- **F-NODE.1** Coordinator registration flow — at startup, register self with all configured coordinators in parallel; succeed on first quorum.
- **F-NODE.2** Quinn server accept loop — inbound tunnel acceptance from peers in the same cohort.
- **F-NODE.3** Relay traffic between peers — when matched as relay, forward Noise-sealed datagrams between two cohort members.
- **F-NODE.4** Exit traffic to internet — two paths corresponding to the CLI's TUN-or-SOCKS5 choice (F-CLI.2 / F-CLI.8). **L3 path (TUN-side ingress):** decrypt inbound `Tunnel` datagrams, hand raw IP packets to an OS-level NAT/routing layer — Linux `nftables` / `iptables` `MASQUERADE`, macOS `pf` NAT, or Windows ICS — operator-documented in `docs/operator-runbook.md`. Userspace TCP/UDP termination via `smoltcp` is a deferred enhancement — see D-3. **L4 path (SOCKS5-side ingress):** decrypt inbound `Tunnel` datagrams as L4 stream payloads, terminate SOCKS5 server semantics locally (via `fast-socks5`), forward to the destination via the OS socket layer (no NAT mutation required). SNI-obfuscation behavior follows D-1, not assumed here.
- **F-NODE.5** Cohort assignment receiver — WS message from coordinator; updates local `CohortState`.
- **F-NODE.6** Rotation event handler — on `CohortRotate`, drain current exit, accept the new cohort, atomically swap.
- **F-NODE.7** DNS resolution — `hickory-resolver` system-config; required for exit-mode outbound connections.
- **F-NODE.8** Rate limiting — `governor` per cohort + per-peer; mirrors coordinator-side limits.
- **F-NODE.9** Telemetry export — Prometheus `/metrics` (datagrams in/out, decrypt-failure count, exit RTT histogram).
- **Gate.** `cargo clippy -p bibeam-node …` clean + an end-to-end test: register with mock coordinator, accept an inbound tunnel from a mock CLI, relay 1 MB roundtrip.

### F-CLI — `bibeam-cli` (depends on all libs; bin; ASCII binary name `bibeam`)

- **F-CLI.1** CLI subcommand structure — `init` (write default config), `up` (start daemon), `down` (stop daemon), `status` (read /healthz of local daemon), `config` (print resolved config), `version`.
- **F-CLI.2** TUN device setup with privilege escalation — `setcap cap_net_admin+ep` on Linux build (instructed in `docs/operator-runbook.md`); admin on Windows wintun; root on macOS utun.
- **F-CLI.3** Coordinator registration — `up` command: read invite code, redeem against coordinator, receive PASETO session token.
- **F-CLI.4** Exit selection — pick exit from received `CohortAssignment`'s `exit_set`; random with `rand` per session.
- **F-CLI.5** Per-session rotation — 15-min wall-clock OR 500-MB cumulative bytes, whichever fires first; rotation drains current exit and prompts coordinator for re-pool.
- **F-CLI.6** Config persistence — `figment` TOML at `~/.config/bibeam/config.toml` (Linux/macOS) or `%APPDATA%\bibeam\config.toml` (Windows).
- **F-CLI.7** ECH policy exposure — surface whichever policy D-1 selects as a config-visible flag (e.g. `ech = "best-effort" | "deferred" | "skipped"`) and a `status` line for operator visibility; the actual ECH hop (DNS HTTPS record lookup, rustls ECH-extension wiring) lives in F-TRANS.2 (and is consumed at the exit via F-NODE.4 when D-1 places the hop server-side). The CLI consumes the policy; it does **not** load DNS HTTPS records itself.
- **F-CLI.8** SOCKS5 fallback — when TUN setup fails (no capabilities, restricted environment), expose `127.0.0.1:1080` SOCKS5 over QUIC datagram tunnel.
- **Gate.** `cargo clippy -p bibeam-cli …` clean + `cargo run --bin bibeam -- --help` and `cargo run --bin bibeam -- version` exit 0 with non-empty stdout.

---

## Strategic Pivots (newly added)

### T-FRAME — Re-frame README and public docs around generic P2P VPN positioning

- **Context.** Per project-owner direction: BiBEAM's *public* framing should be a generically useful P2P VPN, not a Korean-Cloudflare-451-specific tool. The Korean 451 / SNI-geo-block use-case stays as **internal** context (operator runbook, threat-model adversary discussion) but is purged from the README, AGENTS.md, and the top of `docs/architecture.md`.
- **New public framing (verbatim from project owner).** *"Bibeam is an open source, collaborative, distributed, E2E, non-exhaustive Peer-To-Peer VPN. Inspired by Korean food 'Bibimbap'. Also interpreted as Bidirectional-Beam (Bi-Beam); loose Privacy-enhancing Network."*
- **Scope.** Edit `README.md` (replace the "Why" Korean-451 paragraph with the new framing; keep the badges + workspace table + reading-order list). Edit `AGENTS.md` "Quick facts" to mention the Bi-Beam alternate expansion. Generalize "Korean users" / "Cloudflare 451" mentions in `docs/architecture.md` and `docs/threat-model.md` to "users in restrictive networks" / "geo-blocks". Leave `docs/operator-runbook.md` Korean-context references intact — the operator runbook is for operators, not the public-facing surface.
- **Name fidelity preserved.** ASCII identifiers stay `bibeam` / `BiBEAM`; the Hangul `비빔` stays where it currently appears (etymology block); never substitute hanja; never romanize standalone to `bibim`.
- **Do NOT touch.** `docs/plan/init.md` — that is the as-built planning record; rewriting it would lose historical rationale. `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md` — none reference the Korean use-case directly. (`docs/plan/tasks.md` is a *living* planning document — appending new tasks here is expected; only `init.md` is frozen.)
- **Gate.** `cargo run -p xtask --release -- gen-readmes --check` exits 0 (per-crate READMEs unaffected — they come from `[package].description`). `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features` clean. Spot-check `grep -rEi "cloudflare-?451|sni-?(based)?-?geo-?block|korean users" README.md AGENTS.md docs/architecture.md docs/threat-model.md` returns no results. (The string `Korean food` is **permitted** in the etymology block per the verbatim framing above; the gate forbids only the use-case-specific phrases.)

---

## Cross-Cutting Cleanup Sweeps (run after each feature-crate merge)

### X-1 — `/cleanup-codebase` sweep

- **Run.** After every feature-crate's first non-stub merge.
- **Scope.** Files touched by the merge.
- **Look for.** Dead struct fields, redundant single-line wrappers, stale config / feature flags, mirrored state across services, abstraction towers added speculatively.
- **Discipline.** Cleanup is its own atomic commit, separate from behavior change. `git move --fixup` is the splitting tool.
- **Gate.** `cargo build` + `cargo nextest run -p <crate>` green after cleanup; no consumers left for any deleted symbol.

### X-2 — `/tests-purge-unneeded` sweep

- **Run.** After every feature-crate's first non-stub merge.
- **Discriminator.** A test exists only if deleting it would let a real bug reach prod. Static-guarantee carve-out applies (Rust): boundary shape / type tests are redundant; contract / protocol / error-semantics / security-invariant / real-I/O tests stay.
- **Bug-injection drill.** For every keep candidate, inject the failure mode the test claims to catch; if the test still passes, delete it.
- **Gate.** Suite still green; deletions land in their own atomic commits with rationale.

---

## Final Verification (after F-CLI merges)

### Q-1 — Full strict-regime green-light

- **Run.**
  ```bash
  just bootstrap            # confirm Phase-1 tooling
  just bootstrap-phase2     # confirm Phase-2 tooling (if not already installed)
  just ci                   # fmt-check + clippy + nextest + doc + deny + machete
  prek run --all-files
  prek run --stage pre-push --all-files
  cargo run -p xtask --release -- gen-readmes --check
  ```
- **Gate.** Every command exits 0; no clippy warnings, no doc warnings, no banned licenses, no advisories, no unused deps, no README drift, hooks complete in < 60 s wall-clock.
- **Promise.** When Q-1 is green and end-to-end smoke tests (mock-coordinator + mock-cli + mock-node) pass, the codebase is clean and the implementations work properly.

---

## Out-of-Scope (deferred per plan §8)

The following items are explicitly deferred and **must not** appear in any task above:

- OpenTelemetry-OTLP distributed tracing
- cosign / sigstore binary signing
- cargo-vet supply-chain attestations
- cargo-audit as a separate job (covered by `cargo deny check advisories`)
- human-panic / sentry-rs error reporting
- SIGHUP hot-reload of config
- Mobile clients (iOS NetworkExtension, Android VpnService)
- Full Loopix / Sphinx mixnet, cover traffic, on-chain incentives
- Container hardening beyond `distroless/cc-debian12` (no seccomp profile bundling)
- Kubernetes Helm chart (systemd is the deployment target)
