// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package transport provides a consensus-embedded transport layer for MPC
// that replaces NATS, Consul, PostgreSQL, and Redis with:
//
//   - ZAP wire protocol for messaging (replaces NATS)
//   - Consensus Membership with Ed25519 keys as PoA validators (replaces Consul)
//   - StateStore for replicated key-value state (replaces PostgreSQL/Redis)
//   - ZapKVStore (Valkey via hanzoai/kv-go) for key share storage (replaces BadgerDB)
//
// Architecture:
//
//	┌─────────────────────────────────────────────────────────────────┐
//	│                      MPC Node (Consensus-Embedded)              │
//	│  ┌──────────┬─────────────┬──────────────┬─────────────────┐    │
//	│  │ PubSub   │ MessageQ    │  Registry    │  KeyInfoStore   │    │
//	│  └────┬─────┴──────┬──────┴───────┬──────┴───────┬─────────┘    │
//	│       │            │              │              │              │
//	│  ┌────▼────────────▼──────────────▼──────────────▼─────────┐    │
//	│  │              ZAP Transport (Wire Protocol)               │    │
//	│  └────┬────────────────────────────────────────────────────┘    │
//	│       │                                                         │
//	│  ┌────▼─────────────────────────────────────────────────────┐   │
//	│  │           Membership (Ed25519 PoA Validators)            │   │
//	│  └──────────────────────────────────────────────────────────┘   │
//	│       │                                                         │
//	│  ┌────▼─────────────────────────────────────────────────────┐   │
//	│  │              StateStore (BadgerDB + Replication)          │   │
//	│  └──────────────────────────────────────────────────────────┘   │
//	└─────────────────────────────────────────────────────────────────┘
//
// Usage:
//
//	factory, err := transport.NewFactory(transport.FactoryConfig{
//	    NodeID:     "node0",
//	    ListenAddr: ":9651",
//	    Peers: map[string]string{
//	        "node0": "localhost:9651",
//	        "node1": "localhost:9652",
//	        "node2": "localhost:9653",
//	    },
//	    PrivateKey: privateKey,
//	    PublicKey:  publicKey,
//	    BadgerPath: "/data/mpc/node0",
//	})
//
//	// Start the transport
//	ctx := context.Background()
//	if err := factory.Start(ctx); err != nil {
//	    log.Fatal(err)
//	}
//
//	// Get components for MPC node
//	pubSub := factory.PubSub()
//	registry := factory.Registry()
//	kvstore := factory.KVStore()
//	keyinfoStore := factory.KeyInfoStore()
package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"os"

	"github.com/luxfi/mpc/pkg/kvstore"
	"github.com/luxfi/mpc/pkg/logger"
)

// FactoryConfig configures the consensus-embedded transport stack
type FactoryConfig struct {
	// NodeID is this node's unique identifier
	NodeID string

	// ListenAddr is the ZAP transport listen address (e.g., ":9651")
	ListenAddr string

	// Peers maps node IDs to their network addresses
	Peers map[string]string

	// PrivateKey is this node's Ed25519 private key
	PrivateKey ed25519.PrivateKey

	// PublicKey is this node's Ed25519 public key
	PublicKey ed25519.PublicKey

	// ZapDBPath is the path for local ZapDB storage (embedded, replaces BadgerDB)
	ZapDBPath string

	// ZapDBPassword for at-rest AES-256 encryption
	ZapDBPassword string

	// BackupDir for ZapDB incremental S3 backups
	BackupDir string
}

// Factory creates and manages the consensus-embedded transport stack
type Factory struct {
	config *FactoryConfig

	transport  *Transport
	pubsub     *PubSub
	registry   *Registry
	membership *Membership
	badger     kvstore.KVStore
	state      *StateStore
	keyinfo    *KeyInfoStore
}

// NewFactory creates a new transport factory
func NewFactory(config FactoryConfig) (*Factory, error) {
	// Validate config
	if config.NodeID == "" {
		return nil, fmt.Errorf("NodeID is required")
	}
	if config.ListenAddr == "" {
		return nil, fmt.Errorf("ListenAddr is required")
	}
	if len(config.Peers) == 0 {
		return nil, fmt.Errorf("at least one peer is required")
	}
	if config.PrivateKey == nil || config.PublicKey == nil {
		return nil, fmt.Errorf("Ed25519 keypair is required")
	}
	if config.ZapDBPath == "" {
		return nil, fmt.Errorf("ZapDBPath is required")
	}

	// Create transport config
	transportConfig := &Config{
		NodeID:       config.NodeID,
		ListenAddr:   config.ListenAddr,
		Peers:        config.Peers,
		PrivateKey:   config.PrivateKey,
		PublicKey:    config.PublicKey,
		ReadTimeout:  DefaultConfig().ReadTimeout,
		WriteTimeout: DefaultConfig().WriteTimeout,
		BufferSize:   DefaultConfig().BufferSize,
	}

	// Create transport
	transport, err := New(transportConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create transport: %w", err)
	}

	// Create ZapDB (embedded ZAP-native KV store) for local key-share storage
	encKey := deriveEncryptionKey(config.ZapDBPassword)
	if encKey == nil {
		encKey = make([]byte, 32) // Default key if none provided
	}
	zapDBConfig := kvstore.BadgerConfig{
		NodeID:              config.NodeID,
		DBPath:              config.ZapDBPath,
		BackupDir:           config.BackupDir,
		EncryptionKey:       encKey,
		BackupEncryptionKey: encKey,
	}

	// Ensure directory exists
	if err := os.MkdirAll(config.ZapDBPath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create zapdb path: %w", err)
	}

	badger, err := kvstore.NewBadgerKVStore(zapDBConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create zapdb: %w", err)
	}

	// Create state store with replication
	state := NewStateStore(badger, transport, config.NodeID)

	// Create key info store
	keyinfo := NewKeyInfoStore(state, config.NodeID)

	// Create membership with all peer public keys
	membership := NewMembership(transport)

	// Create PubSub adapter
	pubsub := NewPubSub(transport)

	// Get peer IDs for registry
	peerIDs := make([]string, 0, len(config.Peers))
	for id := range config.Peers {
		peerIDs = append(peerIDs, id)
	}

	// Create registry
	registry := NewRegistry(config.NodeID, peerIDs, transport)

	return &Factory{
		config:     &config,
		transport:  transport,
		pubsub:     pubsub,
		registry:   registry,
		membership: membership,
		badger:     badger,
		state:      state,
		keyinfo:    keyinfo,
	}, nil
}

// Start initializes and starts all components
func (f *Factory) Start(ctx context.Context) error {
	logger.Info("Starting consensus-embedded MPC transport",
		"nodeID", f.config.NodeID,
		"listenAddr", f.config.ListenAddr,
		"peers", len(f.config.Peers),
	)

	// Add self as validator
	f.membership.AddValidator(f.config.NodeID, f.config.PublicKey)

	// Start transport (listener + peer connections)
	if err := f.transport.Start(ctx); err != nil {
		return fmt.Errorf("failed to start transport: %w", err)
	}

	// Start registry watch
	go f.registry.WatchPeersReady()

	// Mark self as ready
	if err := f.registry.Ready(); err != nil {
		logger.Warn("Failed to broadcast ready signal", "err", err)
	}

	logger.Info("MPC transport started successfully",
		"nodeID", f.config.NodeID,
		"validators", f.membership.Count(),
	)

	return nil
}

// Stop gracefully shuts down all components
func (f *Factory) Stop() error {
	logger.Info("Stopping MPC transport", "nodeID", f.config.NodeID)

	// Resign from registry
	if err := f.registry.Resign(); err != nil {
		logger.Warn("Failed to resign from registry", "err", err)
	}

	// Close registry
	if err := f.registry.Close(); err != nil {
		logger.Warn("Failed to close registry", "err", err)
	}

	// Stop transport
	if err := f.transport.Stop(); err != nil {
		logger.Warn("Failed to stop transport", "err", err)
	}

	// Close state store (which closes ZapDB)
	if err := f.state.Close(); err != nil {
		logger.Warn("Failed to close state store", "err", err)
	}

	logger.Info("MPC transport stopped", "nodeID", f.config.NodeID)
	return nil
}

// Transport returns the ZAP transport
func (f *Factory) Transport() *Transport {
	return f.transport
}

// PubSub returns the pub/sub adapter
func (f *Factory) PubSub() *PubSub {
	return f.pubsub
}

// Registry returns the peer registry
func (f *Factory) Registry() *Registry {
	return f.registry
}

// Membership returns the PoA membership
func (f *Factory) Membership() *Membership {
	return f.membership
}

// KVStore returns the local ZapDB store (embedded ZAP-native key-value store)
func (f *Factory) KVStore() kvstore.KVStore {
	return f.badger
}

// StateStore returns the replicated state store
func (f *Factory) StateStore() *StateStore {
	return f.state
}

// KeyInfoStore returns the key info store
func (f *Factory) KeyInfoStore() *KeyInfoStore {
	return f.keyinfo
}

// deriveEncryptionKey derives a 32-byte key from password
func deriveEncryptionKey(password string) []byte {
	if password == "" {
		return nil
	}
	// Use SHA-256 for key derivation (in production, use Argon2 or PBKDF2)
	h := sha256.Sum256([]byte(password))
	return h[:]
}
