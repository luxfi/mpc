# Lux MPC Installation Guide

This guide covers the **consensus-mode** deployment path — the production default. It requires no external dependencies (no NATS, no Consul). Nodes discover each other via `--peer` flags over the embedded ZAP peer-to-peer transport.

Legacy NATS+Consul transport is still supported via `--mode=legacy`. See [Appendix A](#appendix-a--legacy-nats--consul-transport-deprecated) below.

---

## Prerequisites

- **Go 1.23+** — [install](https://go.dev/doc/install)
- **SQLite dev headers** — required for CGO build (macOS: shipped with Xcode; Debian/Ubuntu: `apt install libsqlite3-dev`)
- A cloud HSM / KMS for production ZapDB password storage — AWS KMS, GCP KMS, or Azure Key Vault. `--hsm-provider=env` is permitted for local/dev only; setting `environment: production` with `env` or `file` providers is rejected at startup.

No NATS server. No Consul server. No external message bus.

---

## Build

```bash
git clone https://github.com/luxfi/mpc.git
cd mpc
make          # produces ./mpcd and ./mpc
```

The two binaries:

- `mpcd` — the node daemon (runs a consensus-mode MPC node with embedded API).
- `mpc` — CLI utility for peer generation, identity generation, and initiator setup.

---

## Quick Start — 3-Node Local Cluster

A minimal 2-of-3 CGGMP21 cluster on a single host, three terminal windows:

```bash
# Node 0
mpcd start --node-id node0 --listen :9651 --api :9800 \
  --threshold 2 --peer node1@127.0.0.1:9652 --peer node2@127.0.0.1:9653 \
  --data /tmp/mpc/node0

# Node 1
mpcd start --node-id node1 --listen :9652 --api :9801 \
  --threshold 2 --peer node0@127.0.0.1:9651 --peer node2@127.0.0.1:9653 \
  --data /tmp/mpc/node1

# Node 2
mpcd start --node-id node2 --listen :9653 --api :9802 \
  --threshold 2 --peer node0@127.0.0.1:9651 --peer node1@127.0.0.1:9652 \
  --data /tmp/mpc/node2
```

Verify the cluster is healthy (any node):

```bash
curl http://localhost:9800/healthz
# {"status":"healthy","node_id":"node0","mode":"consensus","connected_peers":2,"expected_peers":2,"ready":true,"threshold":2,"version":"0.3.3"}
```

Then run the end-to-end smoke test:

```bash
./scripts/smoke-test.sh
```

The smoke test opens a session, generates a throwaway key, signs a nonce, verifies the signature, and exits 0 on success. See [`scripts/smoke-test.sh`](../scripts/smoke-test.sh) and the [HEALTH.md](./HEALTH.md) endpoint spec.

---

## Configuration

`config.yaml` is read from the current working directory; environment variables with the prefix `LUX_MPC_*` override values. Secrets (ZapDB password, event initiator private key) are **never** kept in `config.yaml` in production — they come from the HSM provider.

Minimal `config.yaml`:

```yaml
mode: consensus
environment: local             # mainnet | testnet | local
mpc_threshold: 2
max_concurrent_keygen: 2
db_path: "."                   # SQLite default. Set --api-db=postgres://... to switch to Postgres.
backup_enabled: true
backup_period_seconds: 300
backup_dir: backups
event_initiator_pubkey: "<hex-ed25519-pubkey-of-the-initiator>"
```

All consensus-mode flags on `mpcd start`:

| Flag | Env | Default | Purpose |
|------|-----|---------|---------|
| `--node-id` | — | — | Node identity (must match peer URIs on other nodes) |
| `--listen` | — | `:9651` | P2P ZAP listen address |
| `--api` | — | `:9800` | Internal API listen address (healthz, keys, backup, keygen) |
| `--api-listen` | — | `:8081` | Dashboard API listen address (`/v1/...`) |
| `--data` | — | cwd | Data directory (key shares, ZapDB, backups) |
| `--keys` | — | — | Keys directory (identity files) |
| `--threshold` / `-t` | — | `2` | Signing threshold |
| `--peer` | — | — | Peer URI `nodeX@host:port` (repeat for each peer) |
| `--jwt-secret` | — | — | JWT signing secret for dashboard auth |
| `--hsm-provider` | `MPC_HSM_PROVIDER` | `env` | `aws` / `gcp` / `azure` / `env` / `file` |
| `--hsm-key-id` | `MPC_HSM_KEY_ID` | — | HSM key ARN/name/path for ZapDB password decryption |
| `--hsm-signer` | `MPC_HSM_SIGNER` | `local` | Signer provider for intent co-signing (`aws`/`gcp`/`azure`/`zymbit`/`mldsa`/`local`) |
| `--hsm-signer-key-id` | `MPC_HSM_SIGNER_KEY_ID` | — | HSM signer key ARN/name |
| `--hsm-attest` | `MPC_HSM_ATTEST` | `false` | Bind threshold signature shares to HSM hardware attestation |
| `--log-level` | — | `info` | `debug` / `info` / `warn` / `error` |

> Production guard: setting `environment: production` with `--hsm-provider=env` or `--hsm-provider=file` is rejected at startup — ZapDB passwords must come from a cloud HSM so they are not readable via `kubectl exec`.

---

## Peer & Identity Setup

Peers and node identities are bootstrapped with the `mpc` CLI.

### Generate Peer Manifest

```bash
mpc generate-peers -n 3 > peers.json
```

Example output:

```json
{
  "node0": "12345678-1234-1234-1234-123456789abc",
  "node1": "23456789-2345-2345-2345-23456789abcd",
  "node2": "34567890-3456-3456-3456-3456789abcde"
}
```

### Generate Per-Node Identity

Run from each node's data directory:

```bash
mpc generate-identity --node node0 --peers peers.json --output-dir identity
```

For production, encrypt the private key with age:

```bash
mpc generate-identity --node node0 --peers peers.json --output-dir identity --encrypt
```

### Distribute Public Identities

Each node needs the **public** identity files (`nodeX_identity.json`) for every peer, and its own **private** key (`nodeX_private.key`). A minimal layout:

```
node0/
├── config.yaml
├── peers.json
└── identity/
    ├── node0_identity.json
    ├── node0_private.key      # <-- secret to node0
    ├── node1_identity.json
    └── node2_identity.json
```

### Generate Event Initiator

The event initiator signs keygen / sign requests that are broadcast to the cluster. Generate it once, distribute the public key to every node via `event_initiator_pubkey` in `config.yaml`:

```bash
mpc generate-initiator --encrypt
# writes event_initiator.identity.json and event_initiator.key.age
```

Copy `public_key` from `event_initiator.identity.json` into every node's `config.yaml`:

```yaml
event_initiator_pubkey: "09be5d070816aadaa1b6638cad33e819a8aed7101626f6bf1e0b427412c3408a"
```

---

## Docker Compose

The included `compose.yml` ships a single-node API + dashboard for local development with SQLite:

```bash
JWT_SECRET=$(openssl rand -hex 32) docker compose up
```

Dashboard at http://localhost:3000, API at http://localhost:8081. For multi-node local clusters, use the launcher script:

```bash
./scripts/launch-3-nodes.sh
```

For production Postgres + Valkey, uncomment the `postgres` and `valkey` services in `compose.yml` and set `POSTGRES_PASSWORD`.

---

## Kubernetes

The `k8s/` directory contains a Kustomize overlay for a 5-node StatefulSet with parallel pod management:

```bash
cd k8s && kubectl kustomize . | kubectl apply -f -
```

The StatefulSet:

- Runs 5 replicas with deterministic peer URIs (`node0@mpc-node-0.mpc-node-headless.lux-mpc.svc:9651`, etc.).
- Uses `readOnlyRootFilesystem: true`, `runAsNonRoot`, `seccompProfile: RuntimeDefault`.
- Exposes `/healthz` on the internal API port for liveness + readiness probes (see [HEALTH.md](./HEALTH.md)).

For production operation — key rotation, backup/restore, incident triage — see [RUNBOOK.md](./RUNBOOK.md).

---

## Production Hardening Checklist

1. Set `environment: production` in `config.yaml`.
2. Set `--hsm-provider=aws|gcp|azure` and `--hsm-key-id=<arn>`. Store the ZapDB password ciphertext in `ZAPDB_ENCRYPTED_PASSWORD`.
3. Set `--hsm-signer=aws|gcp|azure|zymbit|mldsa` and `--hsm-signer-key-id=<arn>` for signer co-signing.
4. Set `--hsm-attest=true` to bind share generation to hardware attestation.
5. Encrypt all identity files at rest (`--encrypt` on generation).
6. Terminate TLS at your ingress (IngressRoute in `k8s/ingressroute.yaml`) — the dashboard API trusts it.
7. Rotate shares periodically via `/v1/wallets/{id}/reshare`. See [RUNBOOK.md → Key Rotation](./RUNBOOK.md#key-rotation).
8. Enable encrypted periodic backups (`backup_enabled: true`) and ship them off-host. The `/backup` internal endpoint is rate-limited and requires internal-auth.

---

## Appendix A — Legacy NATS + Consul Transport (Deprecated)

> **Deprecated.** The NATS+Consul transport is retained for backward compatibility with existing deployments but is no longer the recommended path. New deployments should use consensus mode. This section exists so operators migrating from older installs can understand their current configuration while they plan a switch.

### When to use

- You are running a 0.1.x / 0.2.x install where the NATS and Consul services are already provisioned, and migrating to consensus mode requires a coordinated cutover.
- You have an operational reason to keep an external pub/sub bus (e.g. shared observability, existing NATS auth federation).

### Prerequisites

- **NATS** server (JetStream recommended).
- **Consul** server for peer registration and discovery.
- Go 1.23+, SQLite dev headers as above.

### Docker Compose (dev only)

```yaml
services:
  nats-server:
    image: nats:latest
    command: -js --http_port 8222
    ports: ["4222:4222", "8222:8222", "6222:6222"]
    restart: always

  consul:
    image: consul:1.15.4
    ports: ["8500:8500", "8601:8600/udp"]
    command: "agent -server -ui -node=server-1 -bootstrap-expect=1 -client=0.0.0.0"
    restart: always
```

### Legacy `config.yaml`

```yaml
mode: legacy
nats:
  url: nats://127.0.0.1:4222
consul:
  address: localhost:8500

mpc_threshold: 2
environment: development
event_initiator_pubkey: "<hex-ed25519-pubkey>"
```

### Register peers to Consul

```bash
mpc register-peers
```

### Start each node with `--mode=legacy`

```bash
mpcd start --mode=legacy --node-id node0 --threshold 2 --data node0
```

Operational notes for legacy mode:

- Key rotation procedure is the same; `/v1/wallets/{id}/reshare` works on both transports.
- NATS credentials and Consul tokens should be sourced from the HSM provider the same way ZapDB passwords are (`ZAPDB_ENCRYPTED_PASSWORD`, `NATS_ENCRYPTED_CREDS`, `CONSUL_ENCRYPTED_TOKEN`).
- The smoke test in `scripts/smoke-test.sh` runs against either transport — it just exercises the API.

### Migration to consensus mode

1. Drain traffic off one node at a time.
2. Restart each node with `--mode=consensus` and appropriate `--peer` flags; drop the `nats:` and `consul:` sections from `config.yaml`.
3. Health-check the cluster (`/healthz` on every node) before resuming signing load.
4. When all nodes report `mode: consensus` and the expected peer count, the NATS and Consul servers can be decommissioned.

---

## Appendix B — Decrypt the Initiator Private Key with age

Initiator keys generated with `--encrypt` are written as `event_initiator.key.age`. To decrypt before use (e.g. in a tightly-scoped broker):

```bash
age --decrypt -o event_initiator.key event_initiator.key.age
```

Keep the decrypted file out of source control and off shared volumes.
