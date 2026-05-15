# Protocol

This file is the **as-designed** wire-format and handshake spec. Phase 1 ships crate skeletons only; the implementation lands incrementally in later PRs. Where a section reads as if the system "does" something, that something is the target the implementation will conform to. Concrete numeric tags and field names are reserved here so impl PRs do not bikeshed them.

## Encoding

All control-plane and data-plane frames are encoded with [postcard](https://docs.rs/postcard) — a no-std-friendly, length-delimited, [serde](https://docs.rs/serde) binary format. Postcard is non-self-describing: receivers must know the schema. Schemas are Rust types in [`bibeam-protocol`](../crates/bibeam-protocol).

Endianness: all multi-byte integers postcard emits are little-endian varints; framing is length-prefixed varint per top-level message.

## Transport

- **Data plane.** [QUIC](https://datatracker.ietf.org/doc/html/rfc9000) using [Quinn](https://docs.rs/quinn) 0.11.x with the rustls-ring crypto provider. Bulk packet payloads ride [QUIC unreliable datagrams (RFC 9221)](https://datatracker.ietf.org/doc/html/rfc9221). Reliable side-channels (control messages within a session) ride QUIC streams.
- **Control plane.** REST over HTTPS plus WebSocket subscriptions, both served by [axum](https://docs.rs/axum) on the coordinator. Bodies are JSON for human debuggability; the WS subscription stream carries postcard frames inside binary WS messages.

### Layering: Noise runs over QUIC, not as QUIC

QUIC's own TLS 1.3 layer provides the network-level secure channel: server authentication via the exit's QUIC cert chain, packet protection on the wire, congestion control. Noise IK runs **on top of that QUIC connection as an application-layer end-to-end channel** between client and exit. Noise does not replace QUIC's packet protection; it adds a second envelope. The two AEAD layers are nested, not alternatives — Noise owns the payload contents inside QUIC frames; QUIC owns the transport.

### QUIC mapping contract

Each established client-to-exit QUIC connection carries two reliable stream channels plus one datagram channel. The data channel rides QUIC unreliable datagrams (RFC 9221) and is recognized by being a datagram, not by stream order; the two stream channels are recognized by client-initiated open order.

**Stream channels.** Stream IDs are not fixed by this spec — Quinn allocates them in standard order — but role-to-open-order is normative. The client opens exactly two client-initiated bidirectional streams per connection, in this order:

1. **Handshake stream** (first client-initiated bidi stream). Carries two postcard-encoded Noise IK messages: client → exit, then exit → client. The stream closes cleanly after message 2 is delivered.
2. **Control stream** (second client-initiated bidi stream, opened immediately after handshake completion). Carries Noise-sealed postcard frames for rekey salts, rotation announcements, byte-budget accounting, and `ProtocolError` reports. The stream remains open for the lifetime of the session.

The exit MUST NOT open additional streams to the client in either direction. A peer that receives a client-initiated stream beyond the second, or any server-initiated stream, MUST close that stream with the QUIC application error code corresponding to `proto.stream_unexpected`.

**Datagram channel.** After handshake completion, both sides MAY send QUIC unreliable datagrams. Each datagram payload is exactly one Noise-AEAD-sealed postcard data frame carrying an L3 IP packet; no fragmentation of a sealed frame across datagrams and no batching of multiple sealed frames into one datagram. Datagrams received before handshake completion MUST be dropped without error.

## Identity and keys

- **Long-term peer identity.** Ed25519 keypair. The 32-byte public key is the canonical peer ID, and a ULID-derived 16-byte tag is the routing alias used in postcard frames (the full key is exchanged at registration; the alias is what flies on the wire).
- **Static key for Noise IK.** X25519 keypair, distinct from the Ed25519 identity. Exits advertise their static public key through the coordinator's exit catalog. Clients learn an exit's static key as part of the match response, signed by the coordinator inside the PASETO token.
- **Invite material.** Each invite encodes a coordinator-signed bundle `{invite_id, max_uses, expires_at, signature}`. Invite admission proves possession of a fresh invite to the coordinator; the coordinator records the use and decrements `remaining_uses`.

## Noise IK handshake

Pattern: `Noise_IK_25519_ChaChaPoly_BLAKE3`, run by [snow](https://docs.rs/snow) 0.10 with the `ring-accelerated` backend.

- **IK** — the client knows the responder's static key (acquired from the coordinator) before the handshake begins. Standard one-RTT exchange, suitable for client-initiated connections to known exits.
- **25519** — X25519 for ephemeral and static key agreement.
- **ChaChaPoly** — ChaCha20-Poly1305 AEAD for transport keys.
- **BLAKE3** — hash function for the Noise mixing chain.

Handshake payloads:

- **Message 1 (`e, es, s, ss`).** Client → Exit. Payload carries the PASETO session token issued by the coordinator and a postcard-encoded `ClientHello { proto_version, capabilities }`.
- **Message 2 (`e, ee, se`).** Exit → Client. Payload carries `ExitAck { transport_params, session_alias }`.

After message 2, both sides derive symmetric transport keys (`k1`, `k2`) from the Noise mixing chain and switch to AEAD-per-packet sealing of QUIC datagrams.

### Key schedule

- Noise establishes the initial transport keys after handshake completion (Noise spec `Split()` output).
- Rekey happens when either side has sealed `2^20` packets under the current key, or at exit-driven rotation (every 15 min / 500 MB), whichever comes first. Rekey is a HKDF-BLAKE3 derivation from the current chaining key + a fresh 16-byte salt exchanged on a reliable stream.

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
| `proto.stream_unexpected` | n/a (QUIC stream close only) | Peer opened a stream beyond the two-stream topology defined in [QUIC mapping contract](#quic-mapping-contract); raised only on the data plane. |
| `rate.limited` | 429 | Per-peer rate limit hit |
| `internal` | 500 | Anything not explicitly mapped above |

Data-plane equivalents (carried inside Noise-sealed protocol frames) reuse the same string codes inside a `ProtocolError { code, message }` frame.

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

`proto_version` is a single integer carried in `ClientHello` and the PASETO `proto_version` claim. The handshake fails fast with `proto.version_unsupported` on mismatch.

The error-code enum is **closed**: every code that may be emitted on the wire at a given `proto_version` is listed in the table above for that version. Adding a new code requires a `proto_version` bump. A peer that receives an error code it does not recognize MUST treat it as `internal` for handling purposes and surface the raw string in logs for diagnostic use; this preserves a single, deterministic recovery path under skew while keeping the enum closed per version.

Forward-compatible additions (new optional postcard fields with default-on-absence semantics) do not bump the version. Wire-format breaks, semantic changes to existing fields, and new error codes do.
