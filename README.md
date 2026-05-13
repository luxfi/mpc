# MPC

Threshold signing engine -- CGGMP21 (ECDSA), FROST (EdDSA/Schnorr), BLS, SR25519, and post-quantum lattice signatures (Pulsar M-LWE, Corona R-LWE, and double-lattice composition) via the embedded `thresholdd` dispatcher. No full private key reconstruction, ever.

```
go get github.com/luxfi/mpc
```

## Architecture

`luxfi/mpc` is a production MPC node (`mpcd`) that performs distributed key generation and threshold signing across a cluster. Each node holds a key share; `t` of `n` nodes must cooperate to produce a signature. The full private key never exists on any single machine, in memory or on disk.

### Protocols

| Protocol | Curve / Lattice | Key Type | Use |
|----------|-----------------|----------|-----|
| CGGMP21 | secp256k1 | `secp256k1` | Bitcoin, Ethereum, Lux C-Chain, all EVM L2s, XRPL |
| FROST | Ed25519 | `ed25519` | Solana, TON, Polkadot, Cardano, Substrate chains |
| BLS | BLS12-381 | `bls` | Lux consensus, beacon chain, aggregated signatures |
| SR25519 | Ristretto255 | `sr25519` | Substrate/Polkadot native |
| Pulsar | M-LWE (FIPS 204 / ML-DSA-65 threshold) | `pulsar` | Post-quantum threshold signing — bridge anchors, strict-PQ profile |
| Corona | R-LWE (Ringtail) | `corona` | Post-quantum threshold signing — orthogonal lattice family to Pulsar |
| Double-lattice | Pulsar ⊕ Corona | `double-lattice` | Composed `u32_be(len) ‖ pulsar_sig ‖ corona_sig` — both must verify |

Pulsar, Corona, and double-lattice are exposed via the embedded
threshold dispatcher (`--threshold-listen`, default `127.0.0.1:7300`),
which is `luxfi/threshold/pkg/thresholdd`. The dispatcher is a JSON-RPC
2.0 surface shared with `cggmp21` / `frost` / `bls` — one wire, six
schemes — and is consumed by the teleport bus
(`~/work/lux/teleport/mpc/src/signers/`). The wire format is documented
in `~/work/lux/threshold/CLAUDE.md` under "thresholdd — unified
JSON-RPC daemon".

### Threshold Model

```
t >= floor(n/2) + 1
```

A 2-of-3 cluster tolerates 1 compromised or offline node. A 3-of-5 cluster tolerates 2. The threshold is configurable at key generation time.

### Transport Modes

**Consensus (default)**: Peer-to-peer ZAP protocol with built-in PoA consensus. No external dependencies. Nodes discover each other via `--peer` flags. This is the production path.

**Legacy**: NATS pub/sub + Consul service discovery. Deprecated but still supported via `--mode=legacy`.

### Packages

```
cmd/mpcd/            Daemon binary (CLI, API server, node lifecycle)
pkg/mpc/             Core MPC node -- session management, key generation, signing
  keygen_session.go    CGGMP21 distributed key generation
  signing_session.go   CGGMP21 threshold signing (secp256k1)
  signing_session_frost.go  FROST threshold signing (Ed25519)
  bls_keygen_session.go     BLS key generation
  bls_signing_session.go    BLS threshold signing
  sr25519_keygen_session.go SR25519 key generation
  sr25519_signing_session.go SR25519 threshold signing
  reshare_session.go   Key resharing (rotate shares without changing public key)
  recovery.go          Key share recovery
  tfhe_session.go      FHE threshold decryption sessions
pkg/api/             HTTP API (key generation, signing, key info, health)
pkg/transport/       P2P transport (consensus mode ZAP, legacy NATS)
pkg/messaging/       PubSub abstraction over transport layer
pkg/db/              Key share storage (SQLite default, PostgreSQL optional)
pkg/kvstore/         Encrypted key-value store (AES-256, age encryption)
pkg/keyinfo/         Key metadata management
pkg/identity/        Node identity (Ed25519 keypair, mutual authentication)
pkg/backup/          Encrypted periodic backups
pkg/encryption/      AES-256-GCM encryption for key material at rest
pkg/kms/             KMS integration for secret management
pkg/hsm/             HSM provider abstraction (env, AWS, GCP)
pkg/client/          Go client library for MPC API
pkg/event/           Event types (keygen, sign, reshare)
pkg/eventconsumer/   Event processing pipeline
pkg/protocol/        Wire protocol messages
pkg/settlement/      Trade settlement signing
pkg/smart/           Smart contract transaction construction
pkg/custody/         Custody policy engine
pkg/integrity/       Key share integrity verification
pkg/txtracker/       Transaction lifecycle tracking
```

### Security Properties

- Key shares encrypted at rest with AES-256-GCM (key from HSM/KMS)
- Inter-node messages authenticated with Ed25519 signatures
- No key share leaves the node unencrypted
- Resharing rotates shares without changing the public key or requiring all nodes
- Backup files encrypted with age (modern, audited encryption)
- Secret key bytes zeroed from memory after use (`pkg/mpc/secret.go`)

## Quick Start

### Consensus Mode (recommended)

```bash
# Node 0
mpcd start --node-id node0 --listen :9999 --api :9800 \
  --threshold 2 --peer node1:9999 --peer node2:9999

# Node 1
mpcd start --node-id node1 --listen :9999 --api :9801 \
  --threshold 2 --peer node0:9999 --peer node2:9999

# Node 2
mpcd start --node-id node2 --listen :9999 --api :9802 \
  --threshold 2 --peer node0:9999 --peer node1:9999
```

### Generate a Wallet

```bash
curl -X POST http://localhost:9800/v1/keygen \
  -H "Content-Type: application/json" \
  -d '{"wallet_id": "w-001", "key_type": "secp256k1"}'
```

### Sign a Transaction

```bash
curl -X POST http://localhost:9800/v1/sign \
  -H "Content-Type: application/json" \
  -d '{"wallet_id": "w-001", "message": "0xdeadbeef...", "key_type": "secp256k1"}'
```

### Go Client

```go
import "github.com/luxfi/mpc/pkg/client"

c := client.New("http://localhost:9800")
result, err := c.CreateWallet("w-001", "secp256k1")
sig, err := c.Sign("w-001", txHash, "secp256k1")
```

## Configuration

`config.yaml` or environment variables (`LUX_MPC_*`):

```yaml
mode: consensus
environment: local          # mainnet | testnet | local
mpc_threshold: 2
max_concurrent_keygen: 2
db_path: "."                # SQLite (default), or postgres:// URL
backup_enabled: true
backup_period_seconds: 300
backup_dir: backups
```

All secrets are sourced from KMS via `--hsm-provider=env|aws|gcp`. No plaintext secrets in config.

## Deployment

### Docker Compose

```bash
docker compose up
```

### Kubernetes

```bash
cd k8s && kubectl kustomize . | kubectl apply -f -
```

K8s manifests are in `k8s/` with Kustomize overlays. Production deployment uses `cloudbuild.yaml` for CI/CD to GHCR.

## Testing

```bash
go test ./...       # 331 test functions

# End-to-end (3-node cluster)
cd e2e && make test
```

## Papers

- [Lux Threshold MPC](https://github.com/luxfi/papers/blob/main/lux-threshold-mpc.pdf) -- protocol specification, security proofs
- [Lux LSS MPC](https://github.com/luxfi/papers/blob/main/lux-lss-mpc.pdf) -- linear secret sharing in MPC
- [Lux Validator MPC](https://github.com/luxfi/papers/blob/main/lux-validator-mpc.pdf) -- MPC integration with validator nodes
- [Lux HSM Boundary](https://github.com/luxfi/papers/blob/main/lux-hsm-boundary.pdf) -- HSM trust boundary analysis
- [Lux FHE MPC Hybrid](https://github.com/luxfi/papers/blob/main/lux-fhe-mpc-hybrid.pdf) -- FHE threshold decryption via MPC
- [Lux M-Chain MPC](https://github.com/luxfi/papers/blob/main/lux-mchain-mpc.pdf) -- MPC chain architecture

## Dependencies

- [`luxfi/threshold`](https://github.com/luxfi/threshold) -- CGGMP21 and FROST protocol implementations
- [`luxfi/fhe`](https://github.com/luxfi/fhe) -- FHE threshold decryption sessions
- [`luxfi/hsm`](https://github.com/luxfi/hsm) -- HSM abstraction layer
- [`hanzoai/base`](https://github.com/hanzoai/base) -- Application framework

## License

Lux Ecosystem License v1.2. See [LICENSE](LICENSE).
