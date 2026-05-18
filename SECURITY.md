# Security

BiBeam is in **Phase 1 init scaffold**. No protocol code has been written yet; there is nothing to attack on the data plane. This file describes the threat model BiBeam is designed against, the disclosure path for when there is something to disclose, and what is explicitly out of scope.

## Threat model — summary

BiBeam is **not** Tor and does not aim to be. Full enumeration lives in [`docs/threat-model.md`](./docs/threat-model.md); the headline:

**In scope.**

- Cloudflare 451 and SNI-based geo-blocks (the primary problem).
- An ISP or transit provider observing a user's egress and attempting to fingerprint a single foreign exit IP back to a single person.
- A curious exit operator inspecting the traffic it forwards.
- A curious coordinator operator inspecting metadata (registration, matchmaking).
- Honest-but-curious peers in the shared exit pool.
- Replay, downgrade, and impersonation against the control plane (PASETO + WireGuard handshake).

**Out of scope (explicitly).**

- A **global passive adversary** that can correlate traffic across every link simultaneously. BiBeam is not a mixnet. There is no cover traffic, no Sphinx packet format, no on-chain incentive layer.
- An exit operator that actively MITMs TLS to their own clients with a forged CA — outside the protocol's authority.
- Endpoint compromise (a user's machine, a coordinator host, an exit host) — defended by operating-system controls, not by BiBeam.
- Physical-layer or NIC-firmware attacks.

## Admission

Both planes are gated. Joining the network requires an invite code; admission to the shared exit pool is gated coordinator-side and only granted when the cohort size meets the anonymity-set floor declared in the protocol spec (see [`docs/protocol.md`](./docs/protocol.md)).

## PII handling

Peer IDs and IP addresses are sensitive. The logging layer hashes both with a BLAKE3-keyed MAC before they reach a log line or metric label. Operators never see raw values in their logs; correlation between log entries within a single deployment is still possible (same key), but cross-deployment correlation is not.

## Reporting a vulnerability

If you find a vulnerability — design flaw, implementation bug, supply-chain issue — please report it privately. **Do not open a public GitHub issue.**

- Email: `security@gosuda.dev` (placeholder; rotated when the project gains a maintainer with a published key).
- Encrypt with the maintainer's age or PGP public key when one is published; until then, send a plain-text report and follow up to confirm receipt.
- Expected response: acknowledgement within 7 days. A fix or mitigation plan within 30 days for high-severity issues, longer for design-level concerns that need an architectural change.

There is **no bug bounty** yet. Credit in the security advisory is offered if you want it.

## Supply-chain hygiene

The init repo enforces `cargo deny check` on every CI run, sourcing advisories from the RustSec database. The dep-selection rubric for new third-party crates is described in [`CONTRIBUTING.md`](./CONTRIBUTING.md). Binary signing (cosign / sigstore) and crates.io publication are Phase 2 concerns.
