// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package transport

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/luxfi/mpc/pkg/kvstore"
	"github.com/luxfi/mpc/pkg/logger"
	"github.com/luxfi/mpc/pkg/types"
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

// NewStateStore creates a consensus-aware state store.
//
// transport may be nil, which yields a store that is purely local: no
// subscription, no replication. That is the single-node shape, and it is what
// lets the metadata store be exercised without standing up a consensus ring.
func NewStateStore(local kvstore.KVStore, transport *Transport, nodeID string) *StateStore {
	ss := &StateStore{
		local:     local,
		transport: transport,
		nodeID:    nodeID,
		pending:   make(map[string][]byte),
	}

	// Subscribe to state updates from other nodes
	if transport != nil {
		transport.Subscribe("mpc:state", ss.handleStateUpdate)
	}

	return ss
}

// replicate broadcasts a state update to peers, fire-and-forget. A nil
// transport is a local-only store and has nobody to tell.
func (s *StateStore) replicate(update StateUpdate) error {
	if s.transport == nil {
		return nil
	}
	payload, err := json.Marshal(update)
	if err != nil {
		return err
	}
	go func() {
		if err := s.transport.Publish("mpc:state", payload); err != nil {
			logger.Warn("Failed to replicate state update", "key", update.Key, "err", err)
		}
	}()
	return nil
}

// Put stores a key-value pair and replicates to peers
func (s *StateStore) Put(key string, value []byte) error {
	// Write to local store first
	if err := s.local.Put(key, value); err != nil {
		return err
	}

	// Replicate to peers via consensus transport (eventual consistency)
	return s.replicate(StateUpdate{
		Key:     key,
		Value:   value,
		NodeID:  s.nodeID,
		Deleted: false,
	})
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

	return s.replicate(StateUpdate{
		Key:     key,
		NodeID:  s.nodeID,
		Deleted: true,
	})
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

// KeyInfo is the metadata recorded for a wallet's key set.
//
// There is deliberately no field naming "the" curve of a wallet. A single
// keygen ceremony mints a secp256k1 key (EVM, Bitcoin, Lux, XRPL) AND an
// Ed25519 key (Solana, TON), so "what curve is this wallet" has no single
// answer and any scalar answer is a lie that the signer would then act on.
// Each curve gets its own field; an empty field means that curve was never
// minted for this wallet.
type KeyInfo struct {
	WalletID    string `json:"wallet_id"`
	Threshold   int    `json:"threshold"`
	ECDSAPubKey string `json:"public_key"` // secp256k1 (CGGMP21), hex
	EdDSAPubKey string `json:"eddsa_key"`  // ed25519 (FROST), hex
	KeyData     []byte `json:"key_data"`   // Additional data
	CreatedAt   int64  `json:"created_at"`
	NodeID      string `json:"node_id"` // Node that initiated keygen
}

// RecordsCurves reports whether this record names any curve at all.
//
// Records written before a wallet's key set was recorded carry no public keys.
// Such a record makes NO claim about which curves the wallet has, and must not
// be read as denying one — reading "no keys listed" as "no keys exist" would
// refuse every wallet minted before this field was populated. Callers gate the
// per-curve check on this, and let the missing share be the thing that fails
// closed for records that say nothing.
func (k KeyInfo) RecordsCurves() bool {
	return k.ECDSAPubKey != "" || k.EdDSAPubKey != ""
}

// PublicKeyFor returns the wallet's public key on the named curve, and whether
// a key on that curve exists at all.
//
// This is the only place curve identity is turned into a field, so a caller
// asking "can this wallet sign for Solana" never has to know which field
// answers it. Meaningful only when RecordsCurves is true.
func (k KeyInfo) PublicKeyFor(keyType types.KeyType) (string, bool) {
	switch keyType {
	case types.KeyTypeSecp256k1:
		return k.ECDSAPubKey, k.ECDSAPubKey != ""
	case types.KeyTypeEd25519:
		return k.EdDSAPubKey, k.EdDSAPubKey != ""
	default:
		// sr25519 and anything else: no keygen leg mints it, so no field
		// records it. Reporting "absent" is the truth, and fails closed.
		return "", false
	}
}

// RegisterKey upserts a wallet's key metadata.
//
// It merges rather than overwrites, because the record is written from two
// different moments of one keygen: the CGGMP21 ceremony knows the threshold
// but no public keys, and the keygen result knows the public keys but arrives
// later. Neither knows the other's fields, so a plain overwrite would have
// whichever ran last erase the other's contribution. Zero-valued arguments
// therefore mean "leave as recorded"; keys are only ever added to a wallet,
// never removed, so there is nothing a caller needs to clear.
//
// There is no keyType parameter. A wallet holds one key per curve, so there is
// nothing for a caller to name — and nothing for a caller to hardcode.
func (s *KeyInfoStore) RegisterKey(walletID string, threshold int, ecdsaKey, eddsaKey string, keyData []byte) error {
	info := KeyInfo{WalletID: walletID, NodeID: s.nodeID}
	if existing, err := s.Get(walletID); err == nil && existing != nil {
		info = *existing
		info.WalletID = walletID
		info.NodeID = s.nodeID
	}

	if threshold != 0 {
		info.Threshold = threshold
	}
	if ecdsaKey != "" {
		info.ECDSAPubKey = ecdsaKey
	}
	if eddsaKey != "" {
		info.EdDSAPubKey = eddsaKey
	}
	if len(keyData) != 0 {
		info.KeyData = keyData
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

// ListKeys returns all registered keys by scanning the underlying store for
// entries whose key begins with the KeyInfoStore prefix ("mpc/keys/").
// It leverages the kvstore.Store.Keys() method via a type assertion.
// If the store does not support key listing, only pending updates are searched.
func (s *KeyInfoStore) ListKeys() ([]KeyInfo, error) {
	type keyLister interface {
		Keys() ([]string, error)
	}

	lister, ok := s.state.local.(keyLister)
	if !ok {
		// Fallback: scan pending map only.
		s.state.pendingMu.RLock()
		defer s.state.pendingMu.RUnlock()

		var keys []KeyInfo
		for k, v := range s.state.pending {
			if len(k) > len(s.prefix) && k[:len(s.prefix)] == s.prefix {
				var ki KeyInfo
				if err := json.Unmarshal(v, &ki); err != nil {
					continue
				}
				keys = append(keys, ki)
			}
		}
		return keys, nil
	}

	allKeys, err := lister.Keys()
	if err != nil {
		return nil, err
	}

	var keys []KeyInfo
	for _, k := range allKeys {
		if len(k) <= len(s.prefix) || k[:len(s.prefix)] != s.prefix {
			continue
		}

		data, err := s.state.Get(k)
		if err != nil {
			logger.Warn("Failed to read key info during list", "key", k, "err", err)
			continue
		}

		var ki KeyInfo
		if err := json.Unmarshal(data, &ki); err != nil {
			logger.Warn("Failed to unmarshal key info during list", "key", k, "err", err)
			continue
		}
		keys = append(keys, ki)
	}

	return keys, nil
}
