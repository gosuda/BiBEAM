# Operator Runbook

Target host: **Oracle Cloud ARM Free Tier** (Ampere A1, 4 OCPUs, 24 GB RAM, Ubuntu 24.04 LTS). The crate set compiles for `aarch64-unknown-linux-gnu` from the start; no x86_64 assumption.

This file is split in two. Section 1 describes what an operator can run **today** against the Phase 1 init scaffold. Section 2 describes the **target deployment** that the design points toward — none of the behaviours in section 2 are implemented yet, and operators must not rely on them.

---

## 1. Phase 1 — runnable today

The current state of the two daemons:

| Binary | What it does today |
|---|---|
| `bibeam-node` | Prints `bootstrap version=0.0.1` and waits for SIGINT, then exits cleanly with status 0. No network listener, no storage, no config file. |
| `bibeam-cli` | Same as above. No connection to a coordinator. |

There is **no** REST API, **no** `/metrics`, **no** `/healthz`, **no** `/readyz`, **no** `--config` flag, **no** redb storage, **no** Noise tunnel, **no** cohort admission, **no** pkarr fallback. None of this is wired up.

### Build

```bash
git clone https://github.com/gosuda/BiBEAM.git
cd BiBEAM

# install Phase 1 dev tooling once
just bootstrap

# build the workspace
cargo build --workspace --release --all-features
```

Binaries land in `target/release/`.

### Run the smoke test

Each binary is exercised by the same one-liner:

```bash
./target/release/bibeam-node   # prints bootstrap version=0.0.1
# Ctrl-C to send SIGINT; process exits 0.
```

This is the entire Phase 1 operator contract. The point of running it today is to verify the toolchain, the build, and the strict regime end-to-end. Repeat for `bibeam-cli`.

### Confirming the strict regime

```bash
just ci   # fmt + clippy -D warnings + nextest + doc -D warnings + deny + machete
```

`just ci` is what CI runs. Green locally means green in CI.

There is no production deployment of BiBEAM at Phase 1. Do **not** put these binaries on a public host expecting them to do anything.

---

## 2. Target deployment notes (NOT IMPLEMENTED — design intent only)

Everything in this section describes the deployment shape the design points toward. **None of it works yet.** Each subsection lands when the corresponding crate gains feature code, in a later PR. Operators should read this as a forward-looking sketch, not a runbook.

> **Phase ≥ 2** applies to this entire section unless a subsection says otherwise.

### 2.1 Host prerequisites (target)

Once the daemons accept network connections, the expected host setup on Oracle ARM Free Tier:

```bash
sudo apt-get install -y curl ca-certificates build-essential pkg-config libssl-dev
sudo ufw allow 4433/udp        # QUIC data plane (chosen port)
sudo ufw allow 8443/tcp        # coordinator REST + WS
# /metrics, /healthz, /readyz bind loopback only — no firewall rule needed
```

Oracle Cloud's Virtual Cloud Network security list must mirror any opened ports — `ufw` alone is not sufficient.

### 2.2 Install layout (target)

A federated rendezvous deploys 2–3 `bibeam-node` instances with `is_coordinator = true` (control + data plane in one binary); data-plane-only nodes leave the flag unset (per §11 R-1).

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin bibeam
sudo install -m 0755 target/release/bibeam-node /usr/local/bin/
```

### 2.3 systemd units (target)

Both units assume a `--config` flag and persistent state directories that do not exist today. They are presented here so the deployment shape is settled before the implementation lands.

The single `bibeam-node` binary services both roles (per §11 R-1); the unit below covers the coord-enabled deployment (with `is_coordinator = true` in `node.toml`) and the data-plane-only deployment (with the flag unset). Operators running both roles on the same host should run two `bibeam-node@<instance>.service` instances with separate config files and state directories rather than a single unit.

#### `bibeam-node.service` — coord-enabled (target)

```ini
[Unit]
Description=BiBEAM node (control + data plane, is_coordinator = true)
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
User=bibeam
Group=bibeam
ExecStart=/usr/local/bin/bibeam-node --config /etc/bibeam/node-coord.toml
Restart=on-failure
RestartSec=5s

StateDirectory=bibeam-node-coord
WorkingDirectory=/var/lib/bibeam-node-coord

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ReadWritePaths=/var/lib/bibeam-node-coord
LockPersonality=true
RestrictRealtime=true
RestrictNamespaces=true
RestrictSUIDSGID=true
SystemCallArchitectures=native
CapabilityBoundingSet=
AmbientCapabilities=

StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

#### `bibeam-node.service` — data-plane-only (target)

```ini
[Unit]
Description=BiBEAM node (relay + exit daemon)
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
User=bibeam
Group=bibeam
ExecStart=/usr/local/bin/bibeam-node --config /etc/bibeam/node.toml
Restart=on-failure
RestartSec=5s

StateDirectory=bibeam-node
WorkingDirectory=/var/lib/bibeam-node

# The node will open a TUN device — needs CAP_NET_ADMIN.
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ReadWritePaths=/var/lib/bibeam-node
LockPersonality=true
RestrictRealtime=true
RestrictSUIDSGID=true
SystemCallArchitectures=native

StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

### 2.4 Observability (target)

Once `bibeam-runtime` ships its HTTP server, both server binaries will expose:

| Endpoint | Purpose | Bind |
|---|---|---|
| `GET /metrics` | Prometheus exposition | loopback or internal-only |
| `GET /healthz` | Liveness | loopback or internal-only |
| `GET /readyz` | Ready to serve (after key load + storage open) | loopback or internal-only |

Planned logging shape: JSON via `tracing-subscriber` to stderr (captured by journald), default level `info`, override per-module via `RUST_LOG`. PII (peer IDs, IPs) hashed via BLAKE3-keyed MAC before reaching log lines.

### 2.5 Common failure modes (target)

This table assumes the daemons actually accept connections and use redb. **All entries are speculative until the corresponding code lands.**

| Symptom | Likely cause | Recovery |
|---|---|---|
| Coord-enabled `bibeam-node` exits at startup with a redb error | State directory not writable by `bibeam` user | `chown bibeam:bibeam /var/lib/bibeam-node-coord` and restart. |
| Node startup fails with `Operation not permitted` opening `/dev/net/tun` | `CAP_NET_ADMIN` missing | Verify the systemd unit, `systemctl daemon-reload`, restart. |
| `/readyz` returns 503 indefinitely | Coordinator unreachable from the node, or invite key not provisioned | Check the coordinator endpoint list in `node.toml`; verify outbound. |
| Clients see `admission.insufficient_cohort` repeatedly | Cohort floor (default ≥ 30) not yet met on the chosen exit | Expected at low load. Clients back off and retry. Production deployments must keep the floor ≥ 30; lower floors are development-only. See [`docs/protocol.md`](./protocol.md#cohort-admission-lifecycle). |
| Prometheus scrape returns connection refused | Metrics bind is loopback-only | Scrape from the same host or set up a tunnel; do not move the bind to a public address. |
| Coord-enabled `bibeam-node` keeps restarting | Configuration syntax error, port already bound, or storage corruption | `journalctl -u bibeam-node -n 200`; fix the underlying cause; do not mask with `Restart=always`. |
| All coordinators unreachable from a client | Network-level block of every configured coordinator | Client falls back to pkarr-on-Mainline-DHT for discovery — degraded path with no admission gate, no anonymity-set guarantee. See [`docs/architecture.md`](./architecture.md#control-plane). |

### 2.6 Upgrades (target)

Once releases exist (Phase ≥ 2, via `release-plz` + `cargo-dist`):

1. `systemctl stop bibeam-<role>`
2. Install the new binary in-place.
3. `systemctl start bibeam-<role>`; verify `/readyz`.

Forward-compatibility within a major version is a design goal for the on-disk redb format. Downgrades across a major are not supported.

### 2.7 Backup (target)

A coord-enabled `bibeam-node` will hold invite state and peer registrations in `/var/lib/bibeam-node-coord/`. Online snapshots are a design goal; concrete commands land with the coordinator implementation. Data-plane-only nodes have no critical persistent state in the target design — they can be reprovisioned from scratch.
