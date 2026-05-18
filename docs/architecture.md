# Architecture

비빔 = mixing. Two planes: a thin control plane that brokers introductions, and a data plane that runs the mixed traffic. Everything else is a detail of one of those two.

This file is the **target architecture reference**. The repository now contains substantial protocol/control-plane code, but several request-flow and deployment sections below still describe the intended end state rather than a fully wired production daemon. Use [`docs/protocol.md`](./protocol.md) and the crate docs for the implemented wire/API surface; treat the rest here as architectural direction unless a subsection says otherwise.

## Two-plane overview

```
                          ┌──────────────────────────────────────────┐
                          │            Control plane                 │
                          │  (hybrid super-peer rendezvous)          │
                          │                                          │
   client invite ─────────┤  ┌──────────────┐    ┌──────────────┐   │
                          │  │ coordinator A│    │ coordinator B│   │
                          │  │   (axum +    │    │   (axum +    │   │
                          │  │    redb)     │    │    redb)     │   │
                          │  └──────┬───────┘    └──────┬───────┘   │
                          │         │ independent (Phase 1)         │
                          │         │ replication = Phase 2 ckpt    │
                          └─────────┼─────────────────────┼─────────┘
                                    │ PASETO token        │
                                    ▼                     ▼
                          ┌──────────────────────────────────────────┐
                          │            Data plane                    │
                          │  (Model D+ shared exit pool)             │
                          │                                          │
   user ─ WireGuard UDP ► │  exit pool {N nodes}  ──► public Internet│
                          │   ▲                                      │
                          │   │ random per session, rotate           │
                          │   │ every 15 min or 500 MB               │
                          │   └─ cohort gated coordinator-side       │
                          │      (anonymity-set floor at admission)  │
                          └──────────────────────────────────────────┘
```

## Control plane

Two to three federated coordinator nodes run `iroh-relay`-derived rendezvous plus invite-gated peer admission. They hold registration metadata (peer IDs, capability advertisements, NAT type, location hints) in a local redb instance and issue PASETO v4 session tokens to clients that pass admission.

**Phase 1 — independent coordinators with client-side round-robin.** Each coordinator is authoritative for its own admission decisions. Clients are configured with a list of coordinator endpoints and try them in round-robin order. There is **no inter-coordinator replication**. If a client registers with coordinator A and A goes down, the client re-registers with B; B treats this as a fresh registration.

When **every** configured coordinator is unreachable, clients fall back to pkarr-on-Mainline-DHT for peer discovery. The DHT path is degraded — no admission gate, no anonymity-set guarantee — and exists only to keep peer discovery alive during an outage.

**Phase 2 — coordinator replication via lightweight leader-election (lease + heartbeat).** The leader serves admission writes; followers serve reads. Lease window: 5 seconds; heartbeat: 1 second; election quorum: majority of configured peers. On leader loss, admission temporarily pauses for the re-election window (target: <2 s) while clients see registration retries. State replicated: cohort membership, admission counters, audit-log tail. Single-writer-at-admission is load-bearing for the anonymity-set ≥30 invariant — eventual-consistency replication (gossip + Δ-CRDT) was rejected because two coordinators could each admit a sub-30 cohort that only merges into a ≥30 cohort post-rotation, violating the invariant at the issuance moment. openraft was rejected as over-engineered for a 2–3-node deployment when the replicated state is just admission counters + cohort membership. Implementation lands in a follow-up PR (F-COORD.12).

### Crates that ship the control plane

- [`bibeam-discovery`](../crates/bibeam-discovery) — coordinator client, rendezvous types, DHT fallback.
- [`bibeam-crypto`](../crates/bibeam-crypto) — PASETO v4 token mint and verify.

The control-plane daemon itself (axum REST + WS, redb storage) lives as the `coordinator/` module inside [`bibeam-node`](../crates/bibeam-node), mounted behind the `is_coordinator` config flag (per §11 R-1). A federated deployment runs 2–3 `bibeam-node` instances with `is_coordinator = true`; data-plane-only nodes leave the flag unset.

## Data plane

The data plane speaks the WireGuard wire-protocol (Noise_IK_25519_ChaChaPoly_BLAKE2s over UDP, per the WireGuard whitepaper) via `boringtun`. NAT traversal is a control-plane responsibility: the coordinator orchestrates STUN-based endpoint discovery, and the discovered UDP endpoints are then used as WireGuard peer endpoints. Coord-enabled `bibeam-node` instances pair client + exit registered WireGuard public keys, with the *cohort* serving as the admission and rotation unit rather than the keying unit (per §11 D-6 RESOLVED option (c) key custody — the coordinator never holds private keys; client and exit each generate their own X25519 WG keypairs at registration time and publish only public keys). The PASETO v4 session token still binds `{client_id, exit_id, expires_at, max_bytes}` at the coordinator level and gates the public-key pairing, but WireGuard itself does not carry the token on the wire.

The shared exit pool follows Model D+: one bucket, K clients egress through M exits, each client assigned to a random exit per session. Rotation happens every 15 minutes or after 500 MB egress, whichever comes first. On rotation the client re-requests a token from the coordinator, which re-runs admission and mints a fresh WireGuard peer configuration.

The **anonymity-set floor** is the load-bearing data-plane invariant: at the moment a cohort is admitted to an exit, the cohort must contain at least 30 users. This is enforced coordinator-side at PASETO token issuance — a single auditable point. Between rotations, decay (sessions ending naturally) is bounded by the rotation window and accepted as the MVP trade-off; there is no continuous re-gating. See [`docs/protocol.md`](./protocol.md) for the cohort lifecycle (pending → live → rotation re-pool) and the matching admission rules.

The SNI-confidentiality layers:

- **Primary defense: shared-exit IP washing + cohort mixing.** Even when a destination SNI is observable on the exit-to-destination hop (the common case — most origins do not publish ECH configs), the observer sees a stream coming from a shared exit IP carrying traffic from a cohort of users. Tying a specific request back to a specific user requires correlating across hops, which the threat model does not assume an adversary can do (see [`docs/threat-model.md`](./threat-model.md)). This is what the anonymity-set floor protects: a cohort of ≥30 users on a shared exit IP is the load-bearing structure for unlinkability, not the SNI encryption status of any one request.
- **Tunnel concealment from the user's ISP.** The user-to-exit hop is a WireGuard tunnel over UDP. The user's ISP sees the exit's IP and a stream of WireGuard datagrams — not the destination SNI or any other inner-traffic detail. This holds independently of ECH.
- **User-app ECH is end-to-end and BiBeam-transparent.** ECH on the user-app's TLS to a destination is negotiated browser-to-destination; BiBeam does not terminate that TLS and cannot inject ECH. (TLS-MITM at the exit is explicitly rejected by the threat model.) Where the user's app and the destination both support ECH, the inner SNI is encrypted on the exit-to-destination hop as a bonus; where they do not, the inner SNI is visible to on-path observers of the exit's upstream. Either way, the primary defense above does the unlinkability work.
- **BiBeam's own coordinator-bound TLS: best-effort ECH when rustls supports it.** The CLI / node → coordinator HTTPS connections are terminated inside BiBeam. Once rustls's ECH feature stabilizes, those connections enable ECH on a best-effort basis as a low-cost obfuscation win on BiBeam's own metadata path. The CLI surface advertises this as a policy knob (`ech = "best-effort" | "deferred"`) so operators can opt out where required.

**Client compatibility.** Because the data-plane wire format is stock WireGuard, existing WireGuard clients (iOS WireGuard, Android WireGuard, Windows WireGuard, NetworkManager, OpenWrt's WireGuard support) can connect to BiBeam-managed exits using a coordinator-issued WG configuration. The bibeam-cli adds value on top of that surface — auto-rotation at the 15-min / 500-MB boundary, cohort-aware exit selection, coordinator failover, the local TUN integration — but is not required for basic egress. The choice is deliberate: leaning on the existing WG client ecosystem is what the project-owner direction "use more de-facto VPN protocols and structures for more general availability/compat" decided.

### Crates that ship the data plane

- [`bibeam-protocol`](../crates/bibeam-protocol) — wire frames + postcard codec.
- [`bibeam-crypto`](../crates/bibeam-crypto) — Noise_IK_25519_ChaChaPoly_BLAKE2s handshake (WireGuard's variant), PASETO v4 mint/verify, Ed25519 identity, invite-code derivation, AEAD primitives, key management.
- [`bibeam-transport`](../crates/bibeam-transport) — WireGuard data plane (`boringtun`) over UDP socket + STUN-coordinated hole-punching.
- [`bibeam-tun`](../crates/bibeam-tun) — TUN device wrapper + L3 packet pipeline (`tun-rs`).
- [`bibeam-node`](../crates/bibeam-node) — the dual-role daemon (relay + exit).
- [`bibeam-cli`](../crates/bibeam-cli) — the end-user client daemon and CLI.

### Crates that ship everywhere

- [`bibeam-core`](../crates/bibeam-core) — IDs (ULID), errors, identity types.
- [`bibeam-runtime`](../crates/bibeam-runtime) — tracing-subscriber JSON, Prometheus `/metrics`, `/healthz` and `/readyz`, config loading, signal handling.
- [`xtask`](../crates/xtask) — workspace ops runner. Phase 1 implements `gen-readmes`; future subcommands will add release plumbing.

## Request flow

The path from "a user opens the client" to "a packet leaves the exit" is four steps. Each step is a different crate, and the seams correspond directly to the wire format defined in [`docs/protocol.md`](./protocol.md).

```
   1. REGISTER       2. MATCH              3. HANDSHAKE          4. TUNNEL
   ────────────      ────────────          ────────────          ────────────
   client → coord    coord chooses exit    client ↔ exit         client TUN
   POST /register    from pool, mints      WireGuard handshake   ↓
   { invite,         a PASETO token + a    over UDP, using the   IP frame
     identity,       per-client WG peer    cohort-minted WG      ↓
     capability }    config binding the    peer config           WireGuard seal
                     client to that exit                         ↓ UDP datagram
                     for ≤15 min or                              ↓
                     ≤500 MB                                     exit decap →
                                                                 public Internet
```

1. **Register.** Client presents an invite code + long-term Ed25519 identity to a coordinator. Coordinator verifies the invite signature, records the registration in redb, and returns a coordinator-signed registration receipt.

2. **Match.** Client asks the coordinator for an exit assignment. Coordinator runs the admission gate (anonymity-set floor check on the candidate cohort), picks an exit, and mints a PASETO v4 session token binding `{client_id, exit_id, expires_at, max_bytes}`.

3. **Handshake.** Client generates a fresh WireGuard keypair locally (private key never leaves the client) and sends its public key to the coordinator. The coordinator returns a WG peer configuration scoped to the assigned exit (containing the exit's public key, UDP endpoint, and AllowedIPs) and, over the control plane, pushes the coordinator-signed PASETO v4 session token binding `{client_id, exit_id, expires_at, max_bytes}` together with the client's WG public key to that exit. The exit verifies the token signature and records `{client_wg_pubkey → lease}` in its admission table. The client then opens a WireGuard handshake to the exit's UDP endpoint using the returned config; the exit admits the handshake by public-key match against the validated, coordinator-issued lease entry, then continues to enforce lease expiry and per-session byte budget out-of-band against that entry. WireGuard itself only carries peer-and-tunnel parameters on the wire — the PASETO token authorizes the admission, the WG protocol carries the data.

4. **Tunnel.** Client's TUN device captures IP frames; they are sealed by `boringtun` with the WireGuard transport keys derived in the handshake and sent as UDP-encapsulated WireGuard data messages to the exit. The exit decapsulates, runs the L3 forwarding stage (see *Operational decisions — Exit-mode L3 forwarding* below), and emits packets onto the public Internet. Reverse path mirrors.

## Operational decisions

These two operational choices shape what the MVP ships and where the work goes; both are revisited on operator feedback after first deployments.

### Release-binary targets

The MVP ships pre-built release binaries for four targets, produced by `cargo dist`:

- `x86_64-unknown-linux-gnu` — the dominant Linux server / contributor desktop target.
- `aarch64-unknown-linux-gnu` — the Oracle ARM Free Tier target the project explicitly names for operator self-hosting, and the modal ARM Linux desktop / SBC target.
- `aarch64-apple-darwin` — Apple Silicon macOS, now the modal macOS hardware. (Intel Mac is intentionally not shipped: Apple has already deprecated Intel Mac in its own toolchain, and a CI-minute audit does not justify the coverage.)
- `x86_64-pc-windows-msvc` — Windows 10/11 desktop.

P2T-6 runs `cargo dist init` with exactly this target list. Adding targets later is cheap; cutting them is contractual and harder, which is why the list is deliberately small.

### Exit-mode L3 forwarding

The exit's L3 path forwards decapsulated client packets onto the public Internet via the host OS's native NAT facility at MVP:

- Linux: `nftables` `MASQUERADE` (the operator runbook documents the rule set).
- macOS: `pf` (stretch goal within MVP, gated on operator demand).
- Windows: ICS / Routing and Remote Access (stretch goal within MVP, gated on operator demand).

OS-level NAT is the operationally-simpler path — well-trodden setup, observable via the host's standard tooling, runs at full kernel speed, and inherits the host's existing connection-tracking, conntrack timeouts, and counter machinery. A userspace TCP/UDP stack (`smoltcp`) was considered for stronger operator-process isolation but rejected at MVP: it adds a non-trivial dependency surface, introduces its own debugging needs, and has substantially less mature cross-platform support (its Windows / macOS story is much weaker than Linux's). The operator-isolation argument that motivates a userspace stack is a Phase-3 concern that revisits after MVP deployments produce a usage signal.

## Read next

- Wire-format and handshake specifics — [`docs/protocol.md`](./protocol.md).
- Adversary list and what each can see — [`docs/threat-model.md`](./threat-model.md).
- Bringing up a coordinator or node on Oracle ARM — [`docs/operator-runbook.md`](./operator-runbook.md).
