# Protocol

This file is the **current protocol/reference shape** for the coordinator control plane, PASETO session tokens, and the `WireGuard`-based data plane. The implementation is no longer an empty scaffold, but several surfaces are still evolving; where a section reads as if the system \"does\" something, treat that as the current intended contract the code is converging on.

## Encoding

Coordinator-facing control-plane traffic uses [JSON](https://www.json.org/) over HTTPS and WebSocket text frames. Lower-level protocol structs in [`bibeam-protocol`](../crates/bibeam-protocol) also derive [postcard](https://docs.rs/postcard) when modules need compact binary serialization (for example relay frames and lease metadata), but the public coordinator API is JSON, not postcard.

The direct `WireGuard` data plane is **not** `postcard`-framed: once a session is admitted, client↔exit payload traffic rides opaque `WireGuard` packets over UDP. BiBeam's own typed protocol surface covers only the control plane plus the relay/lease metadata that surrounds those packets when a `WireGuard` payload is wrapped for forwarding.

## Transport

Data plane speaks WireGuard wire protocol via boringtun. Control plane is REST over HTTPS plus WebSocket on axum.

## Identity and keys

- **Long-term peer identity.** Ed25519 keypair. The 32-byte public key is the canonical peer ID, and a ULID-derived 16-byte tag is the routing alias used in postcard frames (the full key is exchanged at registration; the alias is what flies on the wire).
- **Static key for WireGuard.** X25519 keypair used for the WireGuard handshake (boringtun). Exits advertise their public key through the coordinator's exit catalog. Clients learn an exit's static key as part of the match response and associated coordinator control-plane state, not from the PASETO token itself.
- **Invite material.** Each invite carries `code`, `issuer`, `issued_at`, optional `expires_at`, and an Ed25519 `signature` over the domain-separated `(code, issued_at, expires_at)` payload. `issuer` is an unsigned routing hint checked against the trusted coordinator key at verification time. Redemption budget is tracked server-side in the coordinator's `RedemptionLedger`, not encoded into the signed wire shape.

## PASETO session tokens

Coordinator-issued, PASETO v4 (public) tokens are the data-plane admission credential. Library: [`pasetors`](https://docs.rs/pasetors) 0.7 with the `v4` feature.

The implementation stores the typed session payload under a single custom JSON claim, `"bibeam_session"`, whose value is [`SessionClaims`](../crates/bibeam-core/src/claims.rs):

| Field | Type | Purpose |
|---|---|---|
| `sub` | string | Subject peer ID |
| `cohort` | string | Cohort identifier |
| `exp` | RFC3339 timestamp | Session expiry instant |
| `exit_set` | array of strings | Exit nodes the peer is authorised to route through |
| `path` | array of strings | Ordered forwarder chain for this session (last entry is the exit) |

The current implementation uses standard `iat`, `nbf`, and `exp` claims at the PASETO layer. It does **not** currently attach a footer / `kid`; the verifier is configured with the coordinator key it should trust and then decodes the `bibeam_session` custom claim.

Verification path on the exit/client side: parse `v4.public`, verify the signature with the coordinator's key set, apply the default `iat` / `nbf` / `exp` validation rules, then deserialize the `bibeam_session` custom claim into `SessionClaims`.

The current implementation does **not** add a separate `jti` replay cache or `aud` binding layer on top of those claims. Replay resistance today comes from short token lifetimes plus signature / expiry checks; any stronger per-token replay story would be an additional protocol change.

## Control-plane endpoints

All HTTP endpoints are served under `/api/v1/` on the coordinator. The event stream follows the same namespace at `/api/v1/events`.

| Method | Path | Body / params | Returns |
|---|---|---|---|
| `POST` | `/api/v1/register` | `Register { peer_id, addr_hint, can_exit, capacity_hint, at }` | `RegisterAck { session_token, expires_at }` |
| `POST` | `/api/v1/match` | `MatchRequest { peer_id, at }` | `MatchResponse` (`SingleHop` or `MultiHopAssignment`) |
| `POST` | `/api/v1/heartbeat` | `Heartbeat { peer_id, at }` | `200 OK` |
| `POST` | `/api/v1/disconnect` | `Disconnect { peer_id, reason, at }` | `200 OK` |
| `GET` | `/metrics` | — | Prometheus exposition (served by [`bibeam-runtime`](../crates/bibeam-runtime)) |
| `GET` | `/healthz` | — | `200 OK` if the process is alive |
| `GET` | `/readyz` | — | `200 OK` if the process is ready to serve registrations |
| `WS` | `/api/v1/events` | server-pushed `CoordinatorEvent` JSON text frames | `CohortAssigned`, `CohortRotated`, `Disconnect` |

HTTP request/response bodies are serde-derived JSON. The WS stream uses tagged JSON text frames, not binary postcard messages.

## Error codes

Errors carry a stable string code plus a human-readable message. The current implementation uses these as coordinator/control-plane response classifiers rather than as a separate data-plane frame family.

| Code | HTTP | Meaning |
|---|---|---|
| `invite.invalid` | 400 | Invite signature does not verify |
| `invite.exhausted` | 403 | Invite has no remaining uses |
| `invite.expired` | 403 | Invite past `expires_at` |
| `admission.insufficient_cohort` | 503 | Anonymity-set floor not met; client should retry |
| `match.no_exit_available` | 503 | No exit with available capacity |
| `token.invalid` | 401 | PASETO signature or embedded claims rejected |
| `token.expired` | 401 | Standard PASETO expiry validation failed |
| `rate.limited` | 429 | Per-peer or per-IP rate limit hit |
| `internal` | 500 | Anything not explicitly mapped above |

There is no separate data-plane `ProtocolError` frame in the `WireGuard` design. Data-plane failures surface through local handler errors, audit rows, transport metrics, or the coordinator-facing control-plane errors above.

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

- **pending.** A client has called `POST /api/v1/match`, the coordinator has chosen a candidate exit, but the candidate cohort on that exit has not yet reached the floor (default 30). The match request blocks (with a short server-side timeout returning `admission.insufficient_cohort` so the client can retry with backoff) until enough pending peers accumulate.
- **live.** Cohort size reached the floor; coordinator mints PASETO tokens for every pending member of the cohort in a single batch and transitions them to live. From this point the cohort is bound to the exit until the current rotation deadline (15 minutes today; byte-cap enforcement remains a follow-up side-table / scheduler path rather than an active token field).
- **re-pool.** When the coordinator later pushes a `CoordinatorEvent::CohortRotated` frame on `/api/v1/events`, the client re-enters the same `/api/v1/match` flow for a fresh assignment. The cohort on the old exit shrinks. Decay within a cohort (sessions ending naturally) is bounded by the rotation window and accepted as the MVP trade-off — there is no continuous re-gating between rotations.

The floor is configurable but defaults to 30. Lower floors are permitted for development networks; production deployments must run with ≥ 30 or refuse to mint tokens.

Coordinator path versioning is namespace-based: the current control-plane surface is `/api/v1/...` plus `/api/v1/events`. Breaking HTTP / WS changes bump that path prefix.

Lower-level binary envelopes in [`bibeam-protocol`](../crates/bibeam-protocol) still carry their own explicit schema/version bytes when serialized, but the `WireGuard` data plane has no extra BiBeam handshake frame or in-band version negotiation step.

Forward-compatible additions (new optional JSON / postcard fields with default-on-absence semantics) do not require a path bump. Wire-shape breaks, semantic changes to existing fields, and new externally-visible error codes do.
