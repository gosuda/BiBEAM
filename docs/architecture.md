# Architecture

비빔 = mixing. Two planes: a thin control plane that brokers introductions, and a data plane that runs the mixed traffic. Everything else is a detail of one of those two.

This file is the **as-designed** spec. The Phase 1 init scaffold contains crate skeletons only — no protocol code, no coordinator code, no tunnel code. Where a section describes behaviour, that behaviour is the target, not the current state. Phase boundaries are called out inline.

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
   user ── QUIC+Noise ──► │  exit pool {N nodes}  ──► public Internet│
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

**Phase 2 architectural-research checkpoint — replication protocol.** Picking one of {gossip + Δ-CRDT, lightweight leader-election with lease+heartbeat, openraft-Raft} per the "lightweight but robust" project-owner direction. The decision lands as an edit to this file before coordinator implementation reaches feature-complete; the implementation follows in a separate PR.

### Crates that ship the control plane

- [`bibeam-discovery`](../crates/bibeam-discovery) — coordinator client, rendezvous types, DHT fallback.
- [`bibeam-coordinator`](../crates/bibeam-coordinator) — the daemon itself (axum REST + WS, redb storage).
- [`bibeam-crypto`](../crates/bibeam-crypto) — PASETO v4 token mint and verify.

## Data plane

The shared exit pool follows Model D+: one bucket, K clients egress through M exits, each client assigned to a random exit per session. Rotation happens every 15 minutes or after 500 MB egress, whichever comes first. On rotation the client re-requests a token from the coordinator, which re-runs admission.

The **anonymity-set floor** is the load-bearing data-plane invariant: at the moment a cohort is admitted to an exit, the cohort must contain at least 30 users. This is enforced coordinator-side at PASETO token issuance — a single auditable point. Between rotations, decay (sessions ending naturally) is bounded by the rotation window and accepted as the MVP trade-off; there is no continuous re-gating. See [`docs/protocol.md`](./protocol.md) for the cohort lifecycle (pending → live → rotation re-pool) and the matching admission rules.

The SNI-confidentiality layers:

- **Tunnel concealment from the user's ISP.** The user-to-exit hop is a single QUIC connection carrying Noise-sealed packets. The user's ISP sees the exit's IP and the QUIC handshake — not the destination SNI of the inner traffic. This holds independently of ECH.
- **Primary, on the exit egress: TLS 1.3 ECH where supported.** When the destination server publishes an ECH config (an HTTPS DNS record with an `ech` parameter), the exit will use ECH so the inner SNI is encrypted on the exit-to-destination hop. ECH is **destination-dependent**: many origins do not yet publish ECH, in which case the inner SNI is visible to on-path observers of the exit's upstream (including, for Cloudflare-fronted destinations, Cloudflare itself). This is a coverage trade-off, not a guarantee.
- **Secondary: pool mixing.** Even when a destination SNI is observable on the exit-to-destination hop, the observer sees a stream coming from a shared exit IP carrying traffic from a cohort of users. Tying a specific request back to a specific user requires correlating across hops, which the threat model does not assume an adversary can do (see [`docs/threat-model.md`](./threat-model.md)).

### Crates that ship the data plane

- [`bibeam-protocol`](../crates/bibeam-protocol) — wire frames + postcard codec.
- [`bibeam-crypto`](../crates/bibeam-crypto) — Noise_IK_25519_ChaChaPoly_BLAKE3 handshake.
- [`bibeam-transport`](../crates/bibeam-transport) — Quinn QUIC + datagram extension (RFC 9221) + STUN hole-punch.
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
   POST /register    from pool, mints      Noise_IK over QUIC    ↓
   { invite,         a PASETO token        datagrams (RFC 9221)  IP frame
     identity,       binding the           1-RTT, AEAD per       ↓ postcard
     capability }    client to that        packet                Noise seal
                     exit for ≤15 min                            ↓ QUIC dgram
                     or ≤500 MB                                  ↓
                                                                 exit decap →
                                                                 public Internet
```

1. **Register.** Client presents an invite code + long-term Ed25519 identity to a coordinator. Coordinator verifies the invite signature, records the registration in redb, and returns a coordinator-signed registration receipt.

2. **Match.** Client asks the coordinator for an exit assignment. Coordinator runs the admission gate (anonymity-set floor check on the candidate cohort), picks an exit, and mints a PASETO v4 session token binding `{client_id, exit_id, expires_at, max_bytes}`.

3. **Handshake.** Client opens a QUIC connection to the exit, performs a Noise_IK handshake using the exit's static key (advertised through the coordinator), and presents the PASETO token in the handshake payload. The exit verifies the token signature, checks expiry and byte budget, and binds the QUIC connection to the session.

4. **Tunnel.** Client's TUN device captures IP frames; they are postcard-encoded into protocol frames, sealed with the Noise transport keys, and sent as QUIC datagrams to the exit. The exit decapsulates and forwards to the public Internet. Reverse path mirrors.

## Read next

- Wire-format and handshake specifics — [`docs/protocol.md`](./protocol.md).
- Adversary list and what each can see — [`docs/threat-model.md`](./threat-model.md).
- Bringing up a coordinator or node on Oracle ARM — [`docs/operator-runbook.md`](./operator-runbook.md).
