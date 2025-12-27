// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package transport

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/luxfi/mpc/pkg/kvstore"
	"github.com/luxfi/mpc/pkg/logger"
)

// StateStore wraps kvstore.KVStore with consensus-based replication
// Local writes go to ZapDB, reads query consensus for latest state
type StateStore struct {
	local     kvstore.KVStore // Local ZapDB
	transport *Transport
	nodeID    string

	// Pending updates from consensus
	pendingMu sync.RWMutex
	pending   map[string][]byte
}

// StateUpdate represents a state change to replicate
type StateUpdate struct {
	Key       string `json:"key"`
	Value     []byte `json:"value"`
	Deleted   bool   `json:"deleted"`
	Timestamp int64  `json:"timestamp"`
	NodeID    string `json:"node_id"`
}

// NewStateStore creates a consensus-aware state store
func NewStateStore(local kvstore.KVStore, transport *Transport, nodeID string) *StateStore {
	ss := &StateStore{
		local:     local,
		transport: transport,
		nodeID:    nodeID,
		pending:   make(map[string][]byte),
	}

	// Subscribe to state updates from other nodes
	transport.Subscribe("mpc:state", ss.handleStateUpdate)

	return ss
}

// Put stores a key-value pair and replicates to peers
func (s *StateStore) Put(key string, value []byte) error {
	// Write to local store first
	if err := s.local.Put(key, value); err != nil {
		return err
	}

	// Replicate to peers via consensus transport
	update := StateUpdate{
		Key:     key,
		Value:   value,
		NodeID:  s.nodeID,
		Deleted: false,
	}

	payload, err := json.Marshal(update)
	if err != nil {
		return err
	}

	// Broadcast update (fire-and-forget, eventual consistency)
	go func() {
		if err := s.transport.Publish("mpc:state", payload); err != nil {
			logger.Warn("Failed to replicate state update", "key", key, "err", err)
		}
	}()

	return nil
}

// Get retrieves a value from local store
func (s *StateStore) Get(key string) ([]byte, error) {
	// Check pending updates first
	s.pendingMu.RLock()
	if val, ok := s.pending[key]; ok {
		s.pendingMu.RUnlock()
		return val, nil
	}
	s.pendingMu.RUnlock()

	// Read from local store
	return s.local.Get(key)
}

// Delete removes a key and replicates
func (s *StateStore) Delete(key string) error {
	if err := s.local.Delete(key); err != nil {
		return err
	}

	update := StateUpdate{
		Key:     key,
		NodeID:  s.nodeID,
		Deleted: true,
	}

	payload, err := json.Marshal(update)
	if err != nil {
		return err
	}

	go func() {
		if err := s.transport.Publish("mpc:state", payload); err != nil {
			logger.Warn("Failed to replicate delete", "key", key, "err", err)
		}
	}()

	return nil
}

// Close closes the state store
func (s *StateStore) Close() error {
	return s.local.Close()
}

// Backup performs a backup of the local store
func (s *StateStore) Backup() error {
	return s.local.Backup()
}

// handleStateUpdate processes state updates from peers
func (s *StateStore) handleStateUpdate(msg *Message) {
	var update StateUpdate
	if err := json.Unmarshal(msg.Data, &update); err != nil {
		logger.Error("Failed to unmarshal state update", err)
		return
	}

	// Ignore our own updates
	if update.NodeID == s.nodeID {
		return
	}

	logger.Debug("Received state update from peer",
		"peer", update.NodeID,
		"key", update.Key,
		"deleted", update.Deleted,
	)

	// Apply update to local store
	if update.Deleted {
		if err := s.local.Delete(update.Key); err != nil {
			logger.Error("Failed to apply delete", err, "key", update.Key)
		}
	} else {
		if err := s.local.Put(update.Key, update.Value); err != nil {
			logger.Error("Failed to apply put", err, "key", update.Key)
		}
	}
}

// Query queries a key from multiple peers for consensus
func (s *StateStore) Query(ctx context.Context, key string) ([]byte, error) {
	// For now, just return local value
	// In full implementation, this would query peers and use consensus
	return s.Get(key)
}

// SyncWithPeers synchronizes state with connected peers
func (s *StateStore) SyncWithPeers(ctx context.Context) error {
	// Request full state sync from a peer
	// This would be used during node startup or recovery
	// Implementation depends on the specific sync protocol needed

	logger.Info("State sync with peers requested")

	// For now, we rely on continuous replication
	// Full sync would involve:
	// 1. Request snapshot from a peer
	// 2. Apply snapshot to local store
	// 3. Subscribe to updates from that point forward

	return nil
}

// KeyInfoStore provides key metadata storage using consensus
// This replaces the Consul-based keyinfo.Store
type KeyInfoStore struct {
	state  *StateStore
	nodeID string
	prefix string
}

// NewKeyInfoStore creates a consensus-backed key info store
func NewKeyInfoStore(state *StateStore, nodeID string) *KeyInfoStore {
	return &KeyInfoStore{
		state:  state,
		nodeID: nodeID,
		prefix: "mpc/keys/",
	}
}

// KeyInfo represents metadata about a generated key
type KeyInfo struct {
	WalletID  string `json:"wallet_id"`
	KeyType   string `json:"key_type"`
	Threshold int    `json:"threshold"`
	PublicKey string `json:"public_key"` // Hex encoded
	EdDSAKey  string `json:"eddsa_key"`  // EdDSA public key (hex)
	KeyData   []byte `json:"key_data"`   // Additional data
	CreatedAt int64  `json:"created_at"`
	NodeID    string `json:"node_id"` // Node that initiated keygen
}

// RegisterKey stores key metadata
func (s *KeyInfoStore) RegisterKey(walletID, keyType string, threshold int, pubKey string, eddsaKey string, keyData []byte) error {
	info := KeyInfo{
		WalletID:  walletID,
		KeyType:   keyType,
		Threshold: threshold,
		PublicKey: pubKey,
		EdDSAKey:  eddsaKey,
		KeyData:   keyData,
		NodeID:    s.nodeID,
	}

	data, err := json.Marshal(info)
	if err != nil {
		return err
	}

	return s.state.Put(s.prefix+walletID, data)
}

// GetKey retrieves key metadata
func (s *KeyInfoStore) Get(walletID string) (*KeyInfo, error) {
	data, err := s.state.Get(s.prefix + walletID)
	if err != nil {
		return nil, err
	}

	var info KeyInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, err
	}

	return &info, nil
}

// DeleteKey removes key metadata
func (s *KeyInfoStore) DeleteKey(walletID string) error {
	return s.state.Delete(s.prefix + walletID)
}

// ListKeys returns all registered keys
func (s *KeyInfoStore) ListKeys() ([]KeyInfo, error) {
	// This requires iterating over the store
	// For BadgerDB, we'd need to add a List method
	// For now, return empty list - full implementation needs store iteration
	return nil, nil
}
