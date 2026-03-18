# LLM.md - Hanzo MPC Signer Architecture & Development Guide

This document provides comprehensive guidance for AI assistants working with the Hanzo MPC (Multi-Party Computation) codebase.

## 🏭 Production Deployment State (2026-03-02)

### Namespaces
- `lux-mpc` — PRIMARY production consensus-mode MPC (3 nodes, dashboard API, postgres, valkey)
- `lux-bridge` — Bridge-specific MPC (3 consensus-mode nodes, dashboard API using bridge postgres)
- `hanzo` — Legacy NATS/Consul MPC nodes (5 nodes, older deployment)

### Key Decisions
- **Storage**: ZapDB (`github.com/luxfi/database/zapdb`) — our fork, NOT badger directly
- **Encryption**: `encdb.New(password, rawDB)` wraps ZapDB with ChaCha20-Poly1305; backups contain pre-encrypted values, restore into raw zapdb
- **Dashboard API**: Port 8081, enabled by `MPC_API_DB` env var; uses ORM's `_entities` JSONB table
- **Multi-tenancy**: One postgres instance, one `_entities` table, `kind` + `orgId` in JSONB data
- **Binary distribution**: S3 bucket `lux-mpc-backups/binaries/` (public read); startup script promotes `/data/mpcd.new`
- **S3 address**: Use ClusterIP `10.124.44.247:9000` from lux-bridge pods (cross-namespace DNS fails); internal: `s3.hanzo.svc.cluster.local:9000` works only from hanzo namespace

### Infrastructure Principles (keep it light)
- 1 postgres per cluster (MPC gets `mpc_api` db, bridge gets `bridge` db)
- 1 valkey/redis per cluster for KV cache
- 1 S3 bucket with org-prefixed paths for all backups
- All secrets via KMS (NOT plaintext in env vars) — FUTURE WORK
- Customer-controlled encryption: each org's ZapDB encrypted with org's KMS key — FUTURE WORK

### ORM Filter Behavior
- `Filter("keyHash=", value)` → SQL: `WHERE data->>'keyHash' = $1` (camelCase from Go field name)
- `Filter("key_hash=", value)` → SQL: `WHERE data->>'key_hash' = $1` (no conversion)
- ALWAYS use camelCase matching the struct's `json:""` tag when filtering

## 📚 Overview

Hanzo MPC is a threshold signing service that provides:
- **ECDSA (secp256k1)** for Bitcoin/Ethereum/EVM chains
- **EdDSA (Ed25519)** for Solana/Polkadot/Sui
- **Threshold signatures** (t-of-n) with CGGMP21 protocol
- **Key resharing** for rotation without changing addresses

### Architecture Position

Hanzo MPC is designed as a **pluggable signer backend** for Hanzo KMS:

```
┌─────────────────────────────────────────────────────────────────┐
│                      Hanzo KMS (Control Plane)                  │
│  ┌──────────┬─────────────┬──────────────┬─────────────────┐    │
│  │ Policy   │ Approvals   │  Audit Log   │  Key Registry   │    │
│  └────┬─────┴──────┬──────┴───────┬──────┴───────┬─────────┘    │
│       │            │              │              │              │
│  ┌────▼────────────▼──────────────▼──────────────▼─────────┐    │
│  │              Unified Signing API                         │    │
│  └────┬────────────┬──────────────┬──────────────┬─────────┘    │
│       │            │              │              │              │
│  ┌────▼────┐  ┌────▼────┐   ┌─────▼─────┐  ┌─────▼─────┐        │
│  │  HSM    │  │  MPC    │   │  Software │  │  Remote   │        │
│  │ Signer  │  │ Signer  │   │  Signer   │  │  Signer   │        │
│  └─────────┘  └─────────┘   └───────────┘  └───────────┘        │
└─────────────────────────────────────────────────────────────────┘
```

### Product Architecture

1. **Hanzo KMS Platform** (Control Plane)
   - Key registry + metadata
   - Policy + workflow (quorum, time locks, spend limits, allowlists)
   - Audit log
   - Unified API
   - Secrets manager

2. **Hanzo MPC Signer** (This Project - Data Plane)
   - DKG / key share management
   - Threshold signing sessions
   - Reshare/rotate shares
   - Optional hardware-rooted modes

3. **Hanzo HSM** (Alternative Signer)
   - HSM-backed keys for classic KMS workloads
   - HSM-sealed share storage for MPC nodes

4. **Hanzo Treasury** (Optional UI)
   - Transaction building + chain adapters
   - Simulation / policy previews
   - Approvals UI (backed by KMS workflow engine)

## 🚀 Quick Start

### Build and Install
```bash
# Build binaries
make build

# Or install directly (for consensus-embedded mode)
go install ./cmd/mpcd

# Or for legacy NATS/Consul mode
go install ./cmd/lux-mpc-cli
```

### Consensus Mode (NEW - Recommended)
```bash
# Start MPC node in consensus mode (no external dependencies)
mpcd start --mode consensus \
  --node-id node0 \
  --listen :9651 \
  --api :9800 \
  --data /data/mpc/node0 \
  --threshold 2 \
  --peer node1@127.0.0.1:9652 \
  --peer node2@127.0.0.1:9653

# Or via lux CLI
lux mpc init --threshold 2 --nodes 3
lux mpc start
```

### Legacy Mode (NATS + Consul)
```bash
# Generate peers configuration
lux-mpc-cli generate-peers -n 3

# Register peers to Consul
lux-mpc-cli register-peers

# Generate event initiator
lux-mpc-cli generate-initiator

# Generate node identity
lux-mpc-cli generate-identity --node node0

# Start MPC node in legacy mode
mpcd start --mode legacy -n node0
```

## 📁 Project Structure

```
/Users/z/work/lux/mpc/
├── cmd/                    # Command-line applications
│   ├── mpcd/              # Main MPC daemon (consensus-embedded)
│   └── lux-mpc-cli/       # CLI tools for configuration
├── pkg/                    # Core packages
│   ├── client/            # Go client library
│   ├── mpc/               # MPC implementation (TSS)
│   ├── kvstore/           # BadgerDB storage
│   ├── transport/         # Consensus-embedded transport (ZAP + PoA)
│   ├── messaging/         # NATS messaging (DEPRECATED - use transport)
│   ├── infra/             # Consul integration (DEPRECATED - use transport)
│   ├── identity/          # Ed25519 identity management
│   └── eventconsumer/     # Event processing
├── e2e/                    # End-to-end tests
├── examples/               # Usage examples
└── scripts/                # Utility scripts
```

## 🏗️ Core Components

### 1. MPC Engine
Based on threshold cryptography:
- **CGGMP21** protocol for ECDSA (secp256k1) - **IMPLEMENTED & TESTED**
- **FROST** protocol for EdDSA (Ed25519) - **IMPLEMENTED & TESTED** (keygen generates both ECDSA and EdDSA keys)
- Configurable threshold (t-of-n)
- Default: t = ⌊n/2⌋ + 1 (majority)

### 2. Storage Layer: BadgerDB
- AES-256 encrypted key shares
- Session data persistence
- Automatic backups

### 3. Transport Layer (NEW - Jan 2026)

The MPC daemon now supports **consensus-embedded transport** that eliminates external dependencies:

```
┌─────────────────────────────────────────────────────────────────┐
│                 MPC Node (Consensus-Embedded)                   │
│  ┌──────────┬─────────────┬──────────────┬─────────────────┐    │
│  │ PubSub   │ MessageQ    │  Registry    │  KeyInfoStore   │    │
│  └────┬─────┴──────┬──────┴───────┬──────┴───────┬─────────┘    │
│       │            │              │              │              │
│  ┌────▼────────────▼──────────────▼──────────────▼─────────┐    │
│  │              ZAP Transport (Wire Protocol)               │    │
│  └────┬────────────────────────────────────────────────────┘    │
│       │                                                         │
│  ┌────▼─────────────────────────────────────────────────────┐   │
│  │           Membership (Ed25519 PoA Validators)            │   │
│  └──────────────────────────────────────────────────────────┘   │
│       │                                                         │
│  ┌────▼─────────────────────────────────────────────────────┐   │
│  │              StateStore (BadgerDB + Replication)          │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

**What was replaced:**
- **NATS** → ZAP Transport with `Broadcast()`/`Query()`
- **Consul** → Consensus `Membership` with Ed25519 keys as PoA validators
- **PostgreSQL** → `StateStore` + BadgerDB for replicated state
- **Redis** → Consensus state queries via `Transport.Query()`

**What remains:**
- **BadgerDB** → Local encrypted key share storage (unchanged)
- **Ed25519 identities** → Now serve as PoA validator keys

**Usage (pkg/transport):**
```go
factory, err := transport.NewFactory(transport.FactoryConfig{
    NodeID:         "node0",
    ListenAddr:     ":9651",
    Peers:          map[string]string{"node0": ":9651", "node1": ":9652", "node2": ":9653"},
    PrivateKey:     privateKey,
    PublicKey:      publicKey,
    BadgerPath:     "/data/mpc/node0",
    BadgerPassword: "secure-password",
})

ctx := context.Background()
factory.Start(ctx)

// Use these instead of NATS/Consul:
pubSub := factory.PubSub()         // replaces messaging.PubSub
registry := factory.Registry()     // replaces mpc.PeerRegistry
kvstore := factory.KVStore()       // local BadgerDB
keyinfo := factory.KeyInfoStore()  // replaces Consul-based keyinfo.Store
```

### 3b. Messaging: NATS JetStream (DEPRECATED)
- Pub/sub for broadcasts
- Direct messaging for P2P
- Message persistence
- **⚠️ Use `pkg/transport` instead for new deployments**

### 4. Service Discovery: Consul (DEPRECATED)
- Node registration
- Health checking
- Configuration management
- **⚠️ Use `pkg/transport` Membership instead for new deployments**

### 5. Identity: Ed25519 keypairs
- Node authentication
- Message signing/verification
- Encrypted with Age

## 🔧 Configuration

### Consensus-Embedded Mode (NEW - Jan 2026)

```yaml
# config.yaml
environment: development
transport:
  listen_addr: ":9651"
  peers:
    node0: "10.0.0.1:9651"
    node1: "10.0.0.2:9651"
    node2: "10.0.0.3:9651"
badger:
  path: "/data/mpc"
  password: "secure-password"
  backup_dir: "/data/mpc/backups"
identity:
  key_file: "node0_identity.json"
event_initiator_pubkey: "hex-encoded-pubkey"
```

### Legacy Mode (NATS + Consul)

```yaml
# config.yaml
environment: development
consul:
  address: localhost:8500
nats:
  url: nats://localhost:4222
badger_password: "secure-password"
event_initiator_pubkey: "hex-encoded-pubkey"
```

### Environment Variables
- `LUX_MPC_CONFIG` - Path to config.yaml
- `LUX_MPC_BACKUP` - Backup file identifier
- `LUX_MPC_MODE` - "consensus" (new) or "legacy" (NATS/Consul)

## 🔐 Security Model

- **Threshold Security**: No single node has the complete key
- **Message Authentication**: All messages signed with Ed25519
- **Storage Encryption**: BadgerDB encrypted with user password
- **Network Security**: TLS + mutual authentication
- **Key Rotation**: Supports resharing without changing addresses

## 📊 Performance

- **Key Generation**: ~30s for 3 nodes
- **Signing**: <1s for threshold signatures
- **Storage**: ~100MB per node (with backups)
- **Network**: Low bandwidth, resilient to failures

## 🔗 Integration with Hanzo Commerce

The MPC Signer integrates with Commerce for crypto payments:

```go
// Commerce uses MPC via the processor interface
type MPCProcessor struct {
    kmsClient  *kms.Client   // Hanzo KMS for policy/approval
    mpcClient  *mpc.Client   // Hanzo MPC for signing
}

func (p *MPCProcessor) Charge(ctx context.Context, req PaymentRequest) (*PaymentResult, error) {
    // 1. KMS validates policy and approvals
    // 2. MPC signs the transaction
    // 3. Transaction broadcast to blockchain
}
```

## 🔧 Development Workflow

### Testing
```bash
# Run unit tests
make test

# Run with coverage
make test-coverage

# Run E2E tests
make e2e-test
```

### Common Tasks

1. **Generate 3-node test cluster**:
   ```bash
   ./setup_identities.sh
   ```

2. **Recover from backup**:
   ```bash
   hanzo-mpc-cli recover --backup-dir ./backups --recovery-path ./recovered-db
   ```

3. **Production deployment**:
   - Use `--encrypt` flag for identity generation
   - Enable TLS on all services
   - Use `--prompt-credentials` to avoid hardcoded passwords

## 🐛 Common Issues

1. **Port conflicts**: Default ports are 4222 (NATS), 8500 (Consul)
2. **Database locks**: Ensure single process per node
3. **Network delays**: Check NATS/Consul connectivity
4. **Backup failures**: Verify disk space and permissions

### CGGMP21 Protocol Issues (Debugged Jan 2026)

5. **Protocol message serialization**: Protocol messages MUST use `MarshalBinary/UnmarshalBinary` to preserve all fields (SSID, RoundNumber, etc.). Raw JSON marshaling loses critical protocol state.

6. **Party ID ordering**: Party IDs must be sorted consistently across all nodes. The `GetReadyPeersIncludeSelf()` function in `registry.go` sorts peer IDs to ensure deterministic ordering.

7. **NATS topic naming**: Result topics must match JetStream stream configuration:
   - Keygen results: `mpc.mpc_keygen_result.<walletID>` (note the `mpc.mpc_` prefix)
   - Signing results: `mpc.mpc_signing_result.<walletID>`
   - Stream expects pattern: `mpc.mpc_*_result.*`

8. **Self-message rejection**: It's NORMAL for nodes to log "Handler cannot accept message" warnings when they receive their own broadcast messages back. This is expected behavior in pub/sub systems.

9. **Binary rebuild for e2e tests**: E2E tests use `hanzo-mpc` from PATH. After code changes, run `go install ./cmd/hanzo-mpc && go install ./cmd/hanzo-mpc-cli` to update the installed binaries.

10. **Session result publishing pattern**: Individual protocol sessions (CGGMP21, FROST) should NOT publish success events directly to the result queue. The handler (`keygen_handler_cggmp21.go`) is responsible for publishing the combined result with both ECDSA and EdDSA keys. Sessions should only:
    - Publish FAILURE events to the queue (for immediate error notification)
    - Send success pubkey via `externalFinishChan` so `WaitForFinish()` returns
    - Always send to `externalFinishChan` (even empty string for errors) to prevent blocking

11. **Dual keygen architecture**: The `handleKeyGenEventCGGMP21` function runs both ECDSA (CGGMP21) and EdDSA (FROST) keygen protocols in parallel via goroutines with WaitGroup. Both sessions must complete before the handler publishes the combined result containing both public keys.

### FROST Signing Issues (Debugged Jan 2026)

12. **FROST config serialization (CRITICAL)**: `frost.TaprootConfig` contains crypto types (`*curve.Secp256k1Scalar`, `*curve.Secp256k1Point`) that **do NOT have JSON marshalers**. Using `json.Marshal()` corrupts the key shares. **MUST use CBOR serialization** via `MarshalFROSTConfig()` and `UnmarshalFROSTConfig()` in `frost_config_marshal.go`.

13. **FROST signing result type**: The FROST Taproot signing protocol returns `taproot.Signature` (which is `[]byte` of 64 bytes), NOT `*frost.Signature`. The `signing_session_frost.go` handles this correctly with: `s.signature = result.(taproot.Signature)`.

14. **BIP-340/Taproot signature format**: FROST signing produces BIP-340 compatible signatures (64 bytes: R_x || s). The `taproot.Signature` type is already in this format, so no additional conversion is needed in `publishResult()`.

### LSS Protocol Issues (Fixed Jan 2026)

15. **LSS config serialization (CRITICAL - FIXED)**: Similar to FROST, `lssConfig.Config` contains crypto types (`curve.Scalar`, `curve.Point`) that **do NOT have JSON marshalers**. Fixed by implementing `MarshalLSSConfig()` and `UnmarshalLSSConfig()` in `lss_config_marshal.go` using CBOR serialization.

16. **LSS capabilities vs CGGMP21**: LSS supports dynamic resharing (change T-of-N without reconstructing keys), threshold changes, and adding/removing participants. CGGMP21 only supports refresh (same committee). Both produce valid ECDSA signatures.

### Security Audit Findings (Jan 2026)

17. **Message authentication**: Protocol messages between nodes are not signed. Ed25519 signing code exists but is disabled. Consider re-enabling for production deployments.

18. **Deduplication map cleanup**: The `processing` map used for deduplication grows unbounded. Recommend adding TTL-based cleanup for long-running sessions.

19. **Protocol timeouts**: No timeout enforcement on protocol handlers. Recommend adding context with timeout to prevent indefinite hangs from stalling parties.

### Consensus-Embedded Transport (Jan 2026)

20. **ZAP Message Types**: MPC uses ZAP wire protocol message types 60-79:
    - `MsgMPCBroadcast (60)` - Pub/sub broadcasts
    - `MsgMPCDirect (61)` - Point-to-point messaging
    - `MsgMPCReady (62)` - Peer registry readiness
    - `MsgMPCKeygen (64)` - DKG protocol messages
    - `MsgMPCSign (65)` - Signing protocol messages
    - `MsgMPCReshare (66)` - Key resharing messages
    - `MsgMPCResult (67)` - Session result messages

21. **PoA Membership**: Ed25519 public keys are used as Proof-of-Authority validators. VoterIDs are derived via `SHA256("MPC/Ed25519" || pubkey)`.

22. **State Replication**: Key metadata is replicated via consensus transport. Local BadgerDB stores encrypted key shares (not replicated for security).

## 🌐 Blockchain Support

| Blockchain | Support | Curve | Protocol |
|------------|---------|-------|----------|
| Bitcoin (Legacy/SegWit) | ✅ Full | secp256k1 | CGGMP21/LSS |
| Bitcoin (Taproot) | ✅ Full | secp256k1 | FROST |
| Ethereum/EVM | ✅ Full | secp256k1 | CGGMP21/LSS |
| XRPL (XRP Ledger) | ✅ Full | secp256k1 | CGGMP21/LSS |
| Lux Network | ✅ Full | secp256k1 | CGGMP21/LSS |
| Polkadot/Kusama | ✅ Full | ristretto255 | FROST (SR25519) |
| Solana | ⚠️ Partial | Ed25519 | FROST (Taproot mode) |
| TON | ⚠️ Partial | Ed25519 | FROST (Taproot mode) |

**Note**: Solana/TON use Ed25519 natively but our FROST implementation produces Taproot/BIP-340 signatures. Native Ed25519 support requires implementing the Ed25519 FROST variant.

### SR25519 (Ristretto255/Schnorrkel) Implementation

SR25519 threshold signing uses the generic FROST protocol over the ristretto255 prime-order group:
- **Keygen**: `frost.Keygen(Ristretto255{}, ...)` produces `*frost.Config` with ristretto255 curve types
- **Signing**: `frost.Sign(config, signers, message)` with signing context prepended to message
- **Signing context**: Default "substrate", configurable per-session (Schnorrkel convention)
- **Storage**: Key shares stored with `sr25519:` prefix in BadgerDB, serialized via CBOR
- **Signature format**: R (32 bytes, ristretto point) || z (32 bytes, ristretto scalar) = 64 bytes
- **Ristretto255 curve types**: Implemented locally in `pkg/mpc/ristretto255.go` using `gtank/ristretto255` library, satisfying the threshold library's `curve.Curve` interface. Will be replaced when threshold library publishes native Ristretto255 support.

## 🎯 Best Practices

1. **Always backup** BadgerDB before major operations
2. **Test locally** with 3-node setup before production
3. **Monitor health** via Consul UI (http://localhost:8500)
4. **Rotate keys** periodically using reshare functionality
5. **Use Age encryption** for production identities
6. **Keep logs** for debugging MPC rounds

## Context for All AI Assistants

This file (`LLM.md`) is symlinked as:
- `.AGENTS.md`
- `CLAUDE.md`
- `QWEN.md`
- `GEMINI.md`

All files reference the same knowledge base. Updates here propagate to all AI systems.

## Rules for AI Assistants

1. **ALWAYS** update LLM.md with significant discoveries
2. **NEVER** commit symlinked files (.AGENTS.md, CLAUDE.md, etc.) - they're in .gitignore
3. **NEVER** create random summary files - update THIS file
