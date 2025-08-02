# Lux MPC vs Lux TSS-Lib Analysis

## Overview

Lux MPC is **NOT a fork** of Lux's tss-lib, but rather a **wrapper/orchestration layer** built on top of it. The project uses tss-lib v2.0.2 as a core dependency and adds significant infrastructure around it.

## Relationship to TSS-Lib

### Direct Usage
```go
// From go.mod:
github.com/bnb-chain/tss-lib/v2 v2.0.2
```

Lux MPC directly imports and uses tss-lib for all cryptographic operations:
- `github.com/bnb-chain/tss-lib/v2/ecdsa/keygen`
- `github.com/bnb-chain/tss-lib/v2/ecdsa/signing`
- `github.com/bnb-chain/tss-lib/v2/ecdsa/resharing`
- `github.com/bnb-chain/tss-lib/v2/eddsa/keygen`
- `github.com/bnb-chain/tss-lib/v2/eddsa/signing`
- `github.com/bnb-chain/tss-lib/v2/eddsa/resharing`
- `github.com/bnb-chain/tss-lib/v2/tss`
- `github.com/bnb-chain/tss-lib/v2/common`

## What Lux MPC Adds

### 1. **Production Infrastructure**
While tss-lib provides the cryptographic primitives, Lux MPC adds:
- **Messaging Layer**: NATS JetStream for reliable message delivery
- **Service Discovery**: Consul for node registration and health checking
- **Storage**: BadgerDB with encryption for key share persistence
- **Identity Management**: Ed25519-based node authentication

### 2. **Session Management**
```go
type session struct {
    walletID           string
    pubSub             messaging.PubSub
    direct             messaging.DirectMessaging
    party              tss.Party  // <-- tss-lib party
    // ... orchestration fields
}
```
Lux MPC wraps tss-lib's Party interface with session management for:
- Message routing and authentication
- Error handling and recovery
- Progress tracking
- Result persistence

### 3. **Event-Driven Architecture**
```go
// Event consumers that orchestrate tss-lib operations
type KeygenConsumer struct {
    // Handles key generation requests
}

type SigningConsumer struct {
    // Handles signing requests
}

type ReshareConsumer struct {
    // Handles key resharing
}
```

### 4. **Message Authentication & Security**
```go
// Every TSS message is wrapped with authentication
type TssMessage struct {
    WireMsg        []byte  // tss-lib message
    Signature      []byte  // Ed25519 signature
    SessionID      string
    Sender         string
    // ... additional metadata
}
```

### 5. **Operational Features**
- **Automatic Backups**: Encrypted BadgerDB backups every 5 minutes
- **CLI Tools**: `lux-mpc-cli` for peer management, identity generation
- **Configuration Management**: YAML-based config with environment overrides
- **Monitoring**: Structured logging, health checks, metrics

### 6. **Network Communication**
- **Pub/Sub**: For broadcast messages (via NATS)
- **Direct Messaging**: For unicast messages
- **Message Persistence**: JetStream for reliability
- **TLS Support**: For production deployments

## Key Differences from Raw TSS-Lib

### 1. **Ready for Production**
TSS-lib provides algorithms; Lux MPC provides a complete system:
- Service discovery and orchestration
- Persistent storage with encryption
- Message authentication and delivery guarantees
- Operational tooling (CLI, backups, monitoring)

### 2. **Multi-Node Coordination**
```go
// Lux MPC handles node coordination automatically
registry.WaitForPeers(sessionID, requiredPeers)
```

### 3. **Error Recovery**
- Automatic retries with exponential backoff
- Session timeout handling
- Graceful degradation when nodes fail

### 4. **Key Management**
```go
// Lux MPC provides complete key lifecycle
keyinfoStore.SaveKeyInfo(walletID, keyInfo)
kvstore.Put(walletID, encryptedKeyShare)
```

## Architecture Comparison

### TSS-Lib Architecture
```
Application
    ↓
TSS-Lib API
    ↓
Cryptographic Protocols
```

### Lux MPC Architecture
```
Client Application
    ↓
Lux MPC API (Events/RPC)
    ↓
Event Consumers & Session Management
    ↓
TSS-Lib Integration ← Message Auth ← Network Layer
    ↓                      ↓              ↓
Crypto Operations    Identity Mgmt   NATS/Consul
    ↓
Encrypted Storage (BadgerDB)
```

## Should You Use TSS-Lib Directly?

### Use TSS-Lib Directly If:
- Building a custom MPC system from scratch
- Need only the cryptographic primitives
- Have existing infrastructure for coordination
- Want minimal dependencies

### Use Lux MPC If:
- Need a production-ready MPC system
- Want built-in node coordination and discovery
- Require persistent, encrypted key storage
- Need operational tools and monitoring
- Want message authentication and secure delivery

## Notable Enhancements in Lux MPC

1. **Version Management**: Party IDs include version for upgrade compatibility
2. **Concurrent Sessions**: Support for multiple signing sessions
3. **Key Types**: Unified interface for ECDSA and EdDSA
4. **Result Queues**: Async result delivery with persistence
5. **Audit Trail**: All operations logged with context

## Conclusion

Lux MPC is a **production wrapper** around Lux's tss-lib, not a fork or modification. It uses tss-lib as-is for all cryptographic operations while adding the infrastructure needed to run MPC in production environments. The relationship is similar to how Kubernetes uses Docker - it doesn't modify the core engine but provides orchestration and operational capabilities around it.