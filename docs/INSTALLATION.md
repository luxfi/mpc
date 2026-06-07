# MPC Installation Guide

This guide walks an operator from a clean machine to a running `mpcd`
cluster in **consensus mode** — the production path the README leads
with: peer-to-peer ZAP transport, embedded ZapDB storage, no external
broker, no service-discovery layer.

If you have an existing deployment running NATS + Consul, see the
[Legacy transport appendix](#appendix-a-legacy-transport-nats--consul-deprecated)
at the bottom of this document.

---

## Prerequisites

- **Go** 1.23+ — [install instructions](https://go.dev/doc/install)
- **make** (build orchestration)
- For containerised deployments: **Docker** 24+ with the Compose v2 plugin
- For Kubernetes deployments: a cluster with **Kustomize** available
  (`kubectl kustomize`) and a `StorageClass` for persistent volumes

Consensus mode has **no external broker or service-discovery
dependency**. Inter-node messaging, peer registry, and the encrypted
key-share store (ZapDB) are all embedded in the `mpcd` binary.

---

## Clone and Build

```bash
git clone https://github.com/luxfi/mpc.git
cd mpc
```

```bash
make                 # builds ./bin/mpcd (and ./bin/mpc CLI helpers)
# or
go install ./cmd/mpcd
go install ./cmd/mpc
```

### Available binaries

| Binary | Purpose |
|--------|---------|
| `mpcd` | The MPC daemon. One binary, all topologies (standalone, t-of-n cluster). See `cmd/mpcd/README.md`. |
| `mpc`  | CLI helper for one-shot tasks: `generate-peers`, `generate-identity`, `register-peers`, `recovery`. |

---

## Consensus Mode Concepts

Consensus mode (the default; selectable explicitly via `--mode consensus`
in `config.yaml`) is what the README calls the *production path*. The
properties an operator needs to know:

- **Transport.** Peer-to-peer ZAP wire protocol over TLS 1.3 between
  `mpcd` nodes. Each node listens on a single `--listen` address (default
  `:9999`).
- **Peer discovery.** Static. Every node is started with one
  `--peer node<id>@host:port` flag per remote node. The cluster size is
  `n = len(--peer) + 1`.
- **Threshold.** `--threshold t` is the **minimum number of signers**
  required to produce a signature. The daemon refuses to start when
  `t > n`. See `pkg/transport/registry.go::HasSigningQuorum` for the
  arithmetic.
- **Identity.** Each node has a long-lived Ed25519 keypair under
  `<data>/keys/<node-id>_identity.json`. It is generated on first start
  if not present. Inter-node messages are signed and verified with this
  key.
- **State.** All persistent state — key shares, key metadata, peer
  registry, dashboard DB — lives under `--data` (default SQLite +
  ZapDB). Mount a volume here.
- **Backups.** A periodic ZapDB backup runs every
  `backup_period_seconds` (default 300 s) into `<data>/backups`. Optional
  S3 upload is configured via the standard `MPC_BACKUP_S3_*` env vars
  read by `pkg/backup`.

---

## Quick Start: 3-Node Local Cluster

The fastest way to see consensus mode work end-to-end on a single host.

### 1. Pick a threshold

`t-of-n` with `t >= floor(n/2) + 1`. For 3 nodes use `t = 2`.

### 2. Start each node

Run each block in its own terminal:

```bash
# Node 0
mpcd start \
    --node-id node0 --listen :9990 --api :9800 \
    --data ./data/node0 --threshold 2 \
    --peer node1@127.0.0.1:9991 --peer node2@127.0.0.1:9992
```

```bash
# Node 1
mpcd start \
    --node-id node1 --listen :9991 --api :9801 \
    --data ./data/node1 --threshold 2 \
    --peer node0@127.0.0.1:9990 --peer node2@127.0.0.1:9992
```

```bash
# Node 2
mpcd start \
    --node-id node2 --listen :9992 --api :9802 \
    --data ./data/node2 --threshold 2 \
    --peer node0@127.0.0.1:9990 --peer node1@127.0.0.1:9991
```

### 3. Verify quorum

```bash
curl -s http://127.0.0.1:9800/healthz | jq
```

Expected response once all peers connect:

```json
{
  "status": "healthy",
  "mode": "consensus",
  "signing_quorum": true,
  "ready_count": 3,
  "threshold": 2
}
```

The node reports `healthy` while `ready_count >= threshold + 1`,
`healthy-reduced` while signing quorum holds but a non-critical peer is
unreachable, and `degraded` (HTTP 503) once quorum is lost. See
`cmd/mpcd/main.go::healthHandler` for the full contract.

### 4. Generate a wallet

```bash
curl -X POST http://127.0.0.1:9800/keygen \
    -H "Authorization: Bearer ${MPC_INTERNAL_API_KEY}" \
    -H "Content-Type: application/json" \
    -d '{"org_id": "demo", "wallet_id": "w-001"}'
```

`MPC_INTERNAL_API_KEY` is required for every internal endpoint except
`/healthz`. If you do not set it, `mpcd` derives a deterministic key from
the node identity and logs a warning — fine for local testing, **not**
acceptable in production.

---

## Docker Compose

The repo ships a minimal single-node compose file at `compose.yml` for
demos and integration testing:

```bash
export JWT_SECRET=$(openssl rand -hex 32)
docker compose up
```

For multi-node clusters in containers, run one `ghcr.io/luxfi/mpc-api`
container per node and wire the `--peer` flags to the other containers'
network addresses. See `deployments/onprem/README.md` for a worked
example.

---

## Kubernetes

The repo ships a production-grade StatefulSet:

```bash
cd k8s && kubectl kustomize . | kubectl apply -f -
```

`k8s/mpc-statefulset.yaml` builds the peer list from the StatefulSet
ordinal — each pod resolves its siblings via the headless service
`mpc-node-headless.lux-mpc.svc` and starts as:

```bash
mpcd start --node-id node${ORDINAL} \
    --listen :9999 --api :9800 --data /data/mpc --threshold 3 \
    --peer node0@mpc-node-0.mpc-node-headless.lux-mpc.svc:9999 \
    --peer ...
```

The manifests include `secrets.yaml` (KMS-synced), a NetworkPolicy
restricting east-west traffic to the cluster, and an IngressRoute for
the dashboard. The default kustomization is `--threshold 3` over 5 pods;
adjust both in `mpc-statefulset.yaml` if you size differently.

For environment-specific overlays, see `deployments/k8s-primary/` and
`deployments/k8s-private/`.

---

## Configuration Surface (`config.yaml`)

`config.yaml` is read by Viper with `AutomaticEnv`, so every key has an
env-var override (`mpc_threshold` → `MPC_THRESHOLD`, etc.). The minimal
production file:

```yaml
mode: consensus
environment: mainnet           # mainnet | testnet | local

# Consensus
mpc_threshold: 2
max_concurrent_keygen: 2

# Storage
db_path: "."                   # SQLite + ZapDB live here

# Backup
backup_enabled: true
backup_period_seconds: 300
backup_dir: backups

# Event-initiator pubkey (Ed25519, hex). Set when running with an
# explicit initiator service; leave empty inside trusted clusters where
# all messages originate via the internal API.
event_initiator_pubkey: ""
```

Secrets are **never** placed in `config.yaml` in production. Source them
through the HSM password provider:

```bash
mpcd start ... \
    --hsm-provider aws \
    --hsm-key-id arn:aws:kms:us-east-1:...:key/...
```

In `environment: production`, `mpcd` refuses to start with an
`env`/`file` provider (see `resolveZapDBPassword` in `cmd/mpcd/main.go`).

---

## Operational Hardening

Before declaring a cluster production-ready, work through the
[Operator Runbook](RUNBOOK.md) — health-probe spec, key rotation, backup
and restore, node add/remove, and the deployment smoke test.

---

## Appendix A: Legacy Transport (NATS + Consul, deprecated)

> **Deprecated.** The legacy NATS + Consul transport is retained only
> for clusters that have not yet migrated. New deployments must use
> consensus mode (above). The legacy code path will be removed in a
> future major version. There is no `--mode=legacy` flag on `mpcd` —
> legacy deployments use the older `lux-mpc` binary out of `cmd/`.

The previous version of this document recommended NATS + Consul as
prerequisites. That guidance was correct for the legacy `lux-mpc` binary
and still applies if you are operating that path. For posterity:

### Legacy prerequisites

- **NATS** server (JetStream enabled)
- **Consul** server (for peer registration and service discovery)

### Legacy bring-up

```bash
docker compose -f compose.legacy.yaml up -d   # NATS + Consul
mpc generate-peers -n 3                       # peers.json
mpc register-peers                            # writes peers into Consul
mpc generate-identity --node node0 [--encrypt]
mpc generate-initiator [--encrypt]

cd node0 && lux-mpc start -n node0
```

The legacy bring-up script (`scripts/launch-3-nodes.sh`) and the legacy
status helper (`scripts/cluster-status.sh`) target this path. They will
not work against `mpcd` consensus deployments. New automation should
target the consensus-mode endpoints documented above.

### Migration

A migration path from legacy → consensus is **out of scope** for this
document; it requires reshare-based share rotation and is tracked in
`scripts/migration/`. Operators planning a migration should coordinate
with the maintainers.

---

## Appendix B: Decrypt an age-encrypted initiator key

```
age --decrypt -o event_initiator.key event_initiator.key.age
```
