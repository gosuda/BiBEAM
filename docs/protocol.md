# Protocol

This file is the **as-designed** wire-format and handshake spec. Phase 1 ships crate skeletons only; the implementation lands incrementally in later PRs. Where a section reads as if the system "does" something, that something is the target the implementation will conform to. Concrete numeric tags and field names are reserved here so impl PRs do not bikeshed them.

## Encoding

Control-plane messages and coordinator-pushed WS events are encoded with [postcard](https://docs.rs/postcard) — a no-std-friendly, length-delimited, [serde](https://docs.rs/serde) binary format. Postcard is non-self-describing: receivers must know the schema. Schemas are Rust types in [`bibeam-protocol`](../crates/bibeam-protocol).

The `WireGuard` data plane is **not** postcard-framed: once a session is admitted, payload traffic rides opaque `WireGuard` packets over UDP. BiBeam's own typed protocol surface covers only the control plane, token claims, and forwarder/lease metadata.

## Transport

Data plane speaks WireGuard wire protocol via boringtun. Control plane is REST over HTTPS plus WebSocket on axum.

## Identity and keys

- **Long-term peer identity.** Ed25519 keypair. The 32-byte public key is the canonical peer ID, and a ULID-derived 16-byte tag is the routing alias used in postcard frames (the full key is exchanged at registration; the alias is what flies on the wire).
- **Static key for WireGuard.** X25519 keypair used for the WireGuard handshake (boringtun). Exits advertise their public key through the coordinator's exit catalog. Clients learn an exit's static key as part of the match response, signed by the coordinator inside the PASETO token.
- **Invite material.** Each invite encodes a coordinator-signed bundle `{invite_id, max_uses, expires_at, signature}`. Invite admission proves possession of a fresh invite to the coordinator; the coordinator records the use and decrements `remaining_uses`.

## PASETO session tokens

Coordinator-issued, PASETO v4 (public) tokens are the data-plane admission credential. Library: [`pasetors`](https://docs.rs/pasetors) 0.7 with the `v4` feature.

Claims:

| Claim | Type | Purpose |
|---|---|---|
| `iss` | string | Coordinator identifier (e.g. `coord-a.bibeam.example`) |
| `sub` | string | Client peer ID alias |
| `aud` | string | Exit peer ID alias |
| `iat` | RFC3339 timestamp | Issue time |
| `exp` | RFC3339 timestamp | Expiry (≤ 15 minutes after `iat`) |
| `jti` | UUID v7 | Replay-detection nonce |
| `max_bytes` | integer | Byte budget for the session (default 500 × 2²⁰) |
| `cohort_id` | string | Identifier of the admitted cohort (for rotation accounting) |
| `proto_version` | integer | Protocol version the token is valid for |

Footer: a JSON object `{ "kid": "<coord-key-id>" }` so the verifier can pick the right verification key from the coordinator's published key set.

Verification path on the exit: parse v4.public, verify signature with coordinator's key set, check `aud` matches the exit's own peer alias, check `exp > now`, check `jti` is not in the seen-jti set.

**Replay-protection set.** Seen `jti` values are retained until each token's own `exp` passes (TTL-keyed, not LRU-keyed). Eviction is driven by expiry only, never by capacity; an unexpired `jti` cannot be evicted under churn. The set size is bounded above by the product `admission_rate × max_token_ttl` (default ≤ 15 min × per-exit admission rate); operators that need a hard cap should rate-limit admission upstream rather than shorten the replay window.

## Control-plane endpoints

All endpoints are served under `/v0/` on the coordinator. Versioning is path-based; breaking changes bump to `/v1/`.

| Method | Path | Body / params | Returns |
|---|---|---|---|
| `POST` | `/v0/register` | `RegisterRequest { invite, identity_pubkey, capability }` | `RegisterResponse { peer_alias, receipt }` |
| `POST` | `/v0/match` | `MatchRequest { peer_alias, signature }` | `MatchResponse { session_token, exit_endpoint, exit_static_key }` |
| `POST` | `/v0/rotate` | `RotateRequest { current_token, signature }` | `MatchResponse` (new token) |
| `GET` | `/v0/exits` | — | `ExitCatalog { exits: [ExitAdvert] }` (signed by coordinator) |
| `GET` | `/metrics` | — | Prometheus exposition (served by [`bibeam-runtime`](../crates/bibeam-runtime)) |
| `GET` | `/healthz` | — | `200 OK` if the process is alive |
| `GET` | `/readyz` | — | `200 OK` if the process is ready to serve registrations |
| `WS` | `/v0/subscribe` | server-pushed `CoordEvent`s (postcard-framed binary messages) | exit-catalog updates, cohort admission notifications |

Request and response bodies on JSON endpoints are serde-derived; the WS stream uses postcard.

## Error codes

Errors carry a stable string code plus a human-readable message. Codes form a closed enum on both sides.

| Code | HTTP | Meaning |
|---|---|---|
| `invite.invalid` | 400 | Invite signature does not verify |
| `invite.exhausted` | 403 | Invite has no remaining uses |
| `invite.expired` | 403 | Invite past `expires_at` |
| `admission.insufficient_cohort` | 503 | Anonymity-set floor not met; client should retry |
| `match.no_exit_available` | 503 | No exit with available capacity |
| `token.invalid` | 401 | PASETO signature or claims rejected |
| `token.expired` | 401 | `exp` in the past |
| `token.replay` | 409 | `jti` previously seen |
| `proto.version_unsupported` | 426 | `proto_version` not accepted |
| `rate.limited` | 429 | Per-peer rate limit hit |
| `internal` | 500 | Anything not explicitly mapped above |

There is no separate data-plane `ProtocolError` frame in the `WireGuard` design. Data-plane failures surface through local handler errors, audit rows, transport metrics, or the coordinator-facing control-plane error codes above.

## Cohort admission lifecycle

Backs the **anonymity-set floor of 30 users at admission** declared as decision #8 in the init plan. The lifecycle has three states:

```
   ┌──────────┐  cohort size ≥ floor   ┌──────────┐  rotation tick   ┌──────────┐
   │ pending  │ ─────────────────────► │   live   │ ───────────────► │  re-pool │
   │ (queued) │                        │ (active) │                  │ (admit   │
   └──────────┘                        └────┬─────┘                  │  next)   │
        ▲                                   │ session ends            └────┬─────┘
        │                                   │ (decay)                      │
        └───────────── re-admit ◄───────────┴──────────────────────────────┘
```

- **pending.** A client has called `POST /v0/match`, the coordinator has chosen a candidate exit, but the candidate cohort on that exit has not yet reached the floor (default 30). The match request blocks (with a short server-side timeout returning `admission.insufficient_cohort` so the client can retry with backoff) until enough pending peers accumulate.
- **live.** Cohort size reached the floor; coordinator mints PASETO tokens for every pending member of the cohort in a single batch and transitions them to live. From this point the cohort is bound to the exit until the rotation deadline (15 min / 500 MB cumulative).
- **re-pool.** Rotation deadline fires (per-session, not per-cohort). The client calls `POST /v0/rotate`. The coordinator returns the client to pending with a fresh candidate exit; admission re-runs. The cohort on the old exit shrinks. Decay within a cohort (sessions ending naturally) is bounded by the rotation window and accepted as the MVP trade-off — there is no continuous re-gating between rotations.

The floor is configurable but defaults to 30. Lower floors are permitted for development networks; production deployments must run with ≥ 30 or refuse to mint tokens.

## Versioning

`proto_version` is carried in control-plane schemas and in the PASETO `proto_version` claim. Exit verification fails fast with `proto.version_unsupported` when a token or control-plane message advertises an unsupported version; there is no separate `ClientHello` handshake frame in the `WireGuard` data plane.

The error-code enum is **closed**: every code that may be emitted by the control plane or token verifier at a given `proto_version` is listed in the table above for that version. Adding a new code requires a `proto_version` bump. A peer that receives an error code it does not recognize MUST treat it as `internal` for handling purposes and surface the raw string in logs for diagnostic use; this preserves a single, deterministic recovery path under skew while keeping the enum closed per version.

Forward-compatible additions (new optional postcard fields with default-on-absence semantics) do not bump the version. Wire-format breaks, semantic changes to existing fields, and new error codes do.
