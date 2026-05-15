# Threat Model

비빔 makes a specific bargain: trade Tor-grade anonymity for usable latency and a defensible answer to "is the lone user behind this exit *you*?" This file enumerates who the adversaries are, what each can see, and how the design responds.

The protocol it describes lives in [`docs/protocol.md`](./protocol.md); the architecture in [`docs/architecture.md`](./architecture.md). Phase 1 ships crate skeletons only — the mitigations below are design intent, not measured properties of running code.

## Out of scope (stated up front so creep cannot reintroduce them)

- **Global passive adversary.** An attacker who can passively observe every link of the Internet simultaneously and correlate flows across them is **not** in the threat model. BiBEAM has no cover traffic, no Sphinx packet format, no constant-rate padding. If a deployment needs defense against this adversary, use Tor.
- **Endpoint compromise.** A user whose machine is compromised loses to a key recovery and traffic-tap regardless of BiBEAM. Same for a coordinator host or an exit host. Defended at the OS/process layer (rootless containers, systemd hardening), not at the protocol layer.
- **Active TLS MITM by the exit with a forged CA the user trusts.** If the user has accepted a CA the exit also controls, the protocol cannot help.
- **Physical-layer attacks.** Cold-boot key extraction, NIC firmware backdoors, etc.
- **On-chain incentives, exit-operator slashing, reputation systems.** Out of scope for the MVP entirely.

## Adversaries

### Cloudflare and other 451-enforcing destinations

**Capability.** Observes the source IP of every connection that reaches them. Sees the SNI of TLS handshakes that do not use ECH. Can return 451 / refuse service based on either signal.

**Visibility.**

- Source IP: the exit's IP, **not** the user's IP. The exit is shared across the cohort, so a 451 keyed on IP locks out the entire cohort, not one user.
- SNI on the exit-to-destination hop: visible to the destination itself (it must terminate the TLS to serve content). Visibility to on-path observers of that hop (including, for Cloudflare-fronted destinations, Cloudflare itself in transit) depends on whether the destination advertises an ECH config.

**Mitigations.**

- **Exit-IP rotation.** Clients rotate exits every 15 min / 500 MB. A 451 on an exit means the next match assigns a different exit; the cohort moves.
- **ECH where the destination supports it.** Removes the inner SNI from the exit-to-destination path when an HTTPS DNS record advertises ECH. Coverage is destination-dependent — not a guarantee.
- **Pool mixing.** Multiple users behind the same exit IP at the same time; the destination cannot tie a specific request to a specific user without out-of-band correlation.

### The user's ISP (and any on-path observer between user and exit)

**Capability.** Observes every packet between the user's modem and the exit's IP. Can see the exit's IP, packet timing, byte volumes, and that the link is QUIC.

**Visibility.**

- Destination SNI: **not visible** on this hop. The user-to-exit link carries Noise-sealed traffic inside QUIC datagrams. The ISP sees only the exit's IP and a QUIC handshake, with no information about what the user is fetching.
- Exit IP: visible. The ISP knows the user talks to this exit; it does not know what the user does through it.
- Traffic volume and timing: visible. Long-term flow analysis can correlate that the user is online and using BiBEAM; it does not reveal the content.

**Mitigations.**

- **Noise IK over QUIC.** All data-plane traffic is sealed by Noise (ChaCha20-Poly1305) inside QUIC's own packet protection. The ISP sees encrypted bytes.
- **Datagram-based transport.** No reliable-stream side-channel for content; the ISP cannot reconstruct application-layer flows even with deep packet inspection.
- **Exit diversity.** The set of exits used by a single user changes every rotation, blurring any "this user always talks to exit X" pattern.

### A curious exit operator

**Capability.** Runs the exit binary. Terminates the user-to-exit QUIC connection. Sees each connecting client's source IP, the PASETO session alias bound to that connection, decrypted L3 IP frames as they egress, and the destination IP/port of every onward connection. Sees inner SNI when the destination does not advertise ECH.

**Visibility — be precise about what is and is not unlinkable.** The exit-operator threat splits into two distinct questions, and they have different answers:

1. **Can the destination identify the user?** *No, not from network metadata.* The destination sees only the exit's IP, with traffic that may belong to any user in the current cohort. This is the property pool mixing buys.
2. **Can the exit itself link a specific egress packet back to a specific client?** *Yes.* Because the exit terminates the user-to-exit QUIC connection, every Noise-sealed packet arrives on a specific connection bound to a specific client source IP and session alias. The exit can correlate "client at source IP A, session alias S sent these L3 frames, which I forwarded to destination D." Pool mixing does **not** break that link — mixing produces unlinkability against observers downstream of the exit, not against the exit itself.

So the exit knows:

- The decrypted L3 packets from each client it is currently serving.
- The mapping `(client_source_ip, session_alias) → egress destinations` for every active session.
- The session alias is opaque without the coordinator's secret, so the exit cannot turn a session back into a long-term peer ID by itself; **but** the source IP is a strong identifier on its own, and rotation does not change it during a session.

And does **not** know:

- The user's long-term peer ID (only the session alias, which is rotation-scoped).
- The plaintext of user TLS to destinations (still encrypted by the destination's own TLS).
- Whether two sessions from the same IP at different times belong to the same long-term identity — that linkage requires the coordinator's BLAKE3 key.

**Mitigations and their actual scope.**

- **Anonymity-set floor at admission** ([protocol §cohort admission lifecycle](./protocol.md#cohort-admission-lifecycle)) buys unlinkability against the **destination and any on-path observer downstream of the exit**, not against the exit operator. The exit always sees per-session ingress.
- **Rotation every 15 min / 500 MB** limits how long the exit can accumulate a single `(source_ip, alias) → destinations` history. After rotation, the same client appears at a different exit; no single exit operator gets a full session history of a user.
- **No cross-exit correlation without the coordinator's BLAKE3 key.** Two exits comparing logs see two unrelated session aliases for the same user; only the coordinator can collapse them. This raises collusion cost.
- **PII redaction in operator logs.** Source IPs and peer IDs are hashed with a BLAKE3-keyed MAC before reaching log lines or metric labels; what the exit operator runs in memory is unavoidable, but what they retain on disk is not raw.
- **Operator agreement (out-of-protocol).** Exit operators sign an acceptable-use policy at onboarding. A deterrent, not a cryptographic mitigation.

**Honest bottom line.** A malicious exit operator can identify which of its current clients sent a given egress packet. BiBEAM does not defend against an exit that is actively logging its own ingress — it defends against an exit that is *passively curious* (the operator-agreement adversary) and against everyone downstream of the exit. Users who need defence against a malicious exit must rotate exits and avoid using the same exit across sessions where linkage matters; this is a usage discipline, not a protocol guarantee.

### A curious coordinator operator

**Capability.** Runs the coordinator binary. Sees registration requests (invite use, peer ID, declared capability, NAT type), match requests, and the PASETO tokens it issues. Does **not** see data-plane traffic — data flows client-to-exit, never through the coordinator.

**Visibility.**

- Peer ID + invite linkage: yes. The coordinator knows which invite each peer used.
- Match history: yes. The coordinator can reconstruct "peer X was assigned to exit Y at time Z for cohort C."
- Data-plane content: **no**. The coordinator never sees a packet from the tunnel.
- Cross-coordinator correlation: depends on Phase 1 vs Phase 2. In Phase 1, coordinators are independent — one coordinator's view does not extend to another's. Phase 2 replication will share more state; the chosen replication protocol determines how much.

**Mitigations.**

- **Out-of-band invite distribution.** Coordinators do not generate invites for arbitrary requesters; invites originate from a separate trust path (community channels, trusted introducer). This shifts the trust target from "the coordinator operator" to "whoever distributes invites."
- **Hashed identifiers in logs.** Same BLAKE3-keyed MAC as on the exit.
- **Federation.** Multiple coordinators exist by design. A user who does not trust coordinator A registers with coordinator B. Multi-homing on the client allows degrading from one to another mid-session.

### Honest-but-curious peers in the cohort

**Capability.** Holds a valid PASETO token for the same exit. Can attempt to enumerate other cohort members.

**Visibility.**

- Other peers' identities: **not directly visible.** Cohort members never communicate with each other through the data plane; they only share an egress exit IP.
- Exit's static key: visible (it's published in the coordinator's exit catalog).
- Side-channel timing: a colluding pair of cohort members on the same exit can attempt traffic-pattern correlation, but each holds only their own session keys and cannot decrypt the other's frames.

**Mitigations.**

- **Per-session Noise keys.** Each client-to-exit session has independent transport keys.
- **No peer-to-peer signalling through the exit.** The exit forwards L3 packets toward the public Internet, not laterally to other cohort members.
- **Coordinator gating.** A peer attempting to flood admission with many invites to dominate a cohort runs into per-invite rate limits and the invite-distribution chokepoint.

## Replay, downgrade, impersonation

- **Replay.** PASETO `jti` is a UUID v7 and is checked against a per-exit seen-set retained until each token's `exp` passes (TTL-keyed, no capacity-driven eviction). Tokens are bound to a single exit via `aud`; replay against a different exit fails the `aud` check.
- **Downgrade.** `proto_version` in `ClientHello` and the PASETO claim must match. There is no negotiation step a MITM can use to push both sides to a weaker version.
- **Impersonation.** Exit static keys are coordinator-signed inside the match response. A client checks the signature before initiating the Noise handshake; a network attacker cannot substitute a static key without forging the coordinator's signature.

## What we do not promise

- That a user under sustained, targeted correlation by a multi-AS adversary cannot be identified.
- That a coordinator with the BLAKE3 log-key cannot reconstruct user behaviour from its own logs.
- That a destination service that already fingerprints users (browser-level fingerprinting, login cookies) loses that ability when traffic arrives via BiBEAM. It does not.

BiBEAM raises the cost of identifying a Korean user behind a single foreign exit from "trivial" to "requires correlation across multiple observation points." That is the bargain.
