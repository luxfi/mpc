# LLM.md - Lux MPC Architecture & Development Guide

This document provides comprehensive guidance for AI assistants working with the Lux MPC (Multi-Party Computation) codebase.

## 🚀 Quick Start

### Build and Install
```bash
# Build both binaries
make build

# Or install directly
go install ./cmd/lux-mpc
go install ./cmd/lux-mpc-cli
```

### Basic Usage
```bash
# Generate peers configuration
lux-mpc-cli generate-peers -n 3

# Register peers to Consul
lux-mpc-cli register-peers

# Generate event initiator
lux-mpc-cli generate-initiator

# Generate node identity
lux-mpc-cli generate-identity --node node0

# Start MPC node
lux-mpc start -n node0
```

## 📁 Project Structure

```
/Users/z/work/lux/mpc/
├── cmd/                    # Command-line applications
│   ├── lux-mpc/           # Main MPC node binary
│   └── lux-mpc-cli/       # CLI tools for configuration
├── pkg/                    # Core packages
│   ├── client/            # Go client library
│   ├── mpc/               # MPC implementation (TSS)
│   ├── kvstore/           # BadgerDB storage
│   ├── messaging/         # NATS messaging
│   ├── identity/          # Ed25519 identity management
│   └── eventconsumer/     # Event processing
├── e2e/                    # End-to-end tests
├── examples/               # Usage examples
└── scripts/                # Utility scripts
```

## 🏗️ Architecture Overview

### Core Components

1. **MPC Engine**: Based on Lux's threshold
   - ECDSA (secp256k1) for Bitcoin/Ethereum
   - EdDSA (Ed25519) for Solana/Polkadot
   - Threshold signatures (t-of-n)

2. **Storage Layer**: BadgerDB
   - Encrypted key shares
   - Session data persistence
   - Automatic backups

3. **Messaging**: NATS JetStream
   - Pub/sub for broadcasts
   - Direct messaging for P2P
   - Message persistence

4. **Service Discovery**: Consul
   - Node registration
   - Health checking
   - Configuration management

5. **Identity**: Ed25519 keypairs
   - Node authentication
   - Message signing/verification
   - Encrypted with Age

### Key Technical Details

- **Environment Variable**: `LUX_MPC_CONFIG` (points to config.yaml)
- **Backup Magic**: `LUX_MPC_BACKUP` (identifies backup files)
- **Default Threshold**: t = ⌊n/2⌋ + 1 (majority)
- **Database**: BadgerDB with AES-256 encryption
- **Network**: TLS for production, mutual Ed25519 auth

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

### Configuration
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

### Common Tasks

1. **Generate 3-node test cluster**:
   ```bash
   ./setup_identities.sh
   ```

2. **Recover from backup**:
   ```bash
   lux-mpc-cli recover --backup-dir ./backups --recovery-path ./recovered-db
   ```

3. **Production deployment**:
   - Use `--encrypt` flag for identity generation
   - Enable TLS on all services
   - Use `--prompt-credentials` to avoid hardcoded passwords

## 🔐 Security Model

- **Threshold Security**: No single node has the complete key
- **Message Authentication**: All messages signed with Ed25519
- **Storage Encryption**: BadgerDB encrypted with user password
- **Network Security**: TLS + mutual authentication
- **Key Rotation**: Supports resharing for key rotation

## 📊 Performance Characteristics

- **Key Generation**: ~30s for 3 nodes
- **Signing**: <1s for threshold signatures
- **Storage**: ~100MB per node (with backups)
- **Network**: Low bandwidth, resilient to failures

## 🐛 Common Issues

1. **Port conflicts**: Default ports are 4222 (NATS), 8500 (Consul)
2. **Database locks**: Ensure single process per node
3. **Network delays**: Check NATS/Consul connectivity
4. **Backup failures**: Verify disk space and permissions

## 📚 Additional Resources

- **Lux Network Docs**: https://docs.lux.network/mpc
- **TSS Library**: https://github.com/luxfi/threshold
- **Client Libraries**:
  - TypeScript: https://github.com/luxfi/mpc-client-ts
  - Go: See `/pkg/client/`

## 🎯 Best Practices

1. **Always backup** BadgerDB before major operations
2. **Test locally** with 3-node setup before production
3. **Monitor health** via Consul UI (http://localhost:8500)
4. **Rotate keys** periodically using reshare functionality
5. **Use Age encryption** for production identities
6. **Keep logs** for debugging MPC rounds

This guide is continuously updated. Check git history for recent changes.
