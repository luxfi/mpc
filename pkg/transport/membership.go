// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"time"
)

var (
	ErrValidatorNotFound = errors.New("membership: validator not found")
	ErrInvalidEpoch      = errors.New("membership: invalid epoch")
)

// VoterID is a 32-byte validator identifier derived from Ed25519 public key
type VoterID [32]byte

// Validator represents an MPC node with Ed25519 identity
type Validator struct {
	ID        VoterID
	NodeID    string
	PublicKey ed25519.PublicKey
	Weight    uint64
}

// ValidatorSet is the set of active validators
type ValidatorSet struct {
	Epoch      uint64
	Validators []Validator
	TotalPower uint64
}

// Membership implements the consensus wire.Membership interface
// using MPC node Ed25519 keys as Proof-of-Authority validators
type Membership struct {
	mu         sync.RWMutex
	validators map[VoterID]*Validator
	nodeIndex  map[string]VoterID // nodeID -> VoterID

	currentEpoch uint64
	transport    *Transport
}

// NewMembership creates a PoA membership from MPC node identities
func NewMembership(transport *Transport) *Membership {
	return &Membership{
		validators: make(map[VoterID]*Validator),
		nodeIndex:  make(map[string]VoterID),
		transport:  transport,
	}
}

// AddValidator adds a validator from Ed25519 public key
func (m *Membership) AddValidator(nodeID string, pubKey ed25519.PublicKey) VoterID {
	voterID := DeriveVoterID("MPC/Ed25519", pubKey)

	validator := &Validator{
		ID:        voterID,
		NodeID:    nodeID,
		PublicKey: pubKey,
		Weight:    1, // Equal weight in PoA
	}

	m.mu.Lock()
	m.validators[voterID] = validator
	m.nodeIndex[nodeID] = voterID
	m.mu.Unlock()

	return voterID
}

// RemoveValidator removes a validator
func (m *Membership) RemoveValidator(nodeID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	voterID, ok := m.nodeIndex[nodeID]
	if !ok {
		return
	}

	delete(m.validators, voterID)
	delete(m.nodeIndex, nodeID)
}

// ValidatorSet returns the current validator set for an epoch
func (m *Membership) ValidatorSet(ctx context.Context, epoch uint64) (*ValidatorSet, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	validators := make([]Validator, 0, len(m.validators))
	var totalPower uint64

	for _, v := range m.validators {
		validators = append(validators, *v)
		totalPower += v.Weight
	}

	return &ValidatorSet{
		Epoch:      epoch,
		Validators: validators,
		TotalPower: totalPower,
	}, nil
}

// IsValidator checks if a VoterID is a validator
func (m *Membership) IsValidator(ctx context.Context, voterID VoterID) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, ok := m.validators[voterID]
	return ok, nil
}

// SampleCommittee samples k validators from the set for a round
// In PoA mode, this returns all validators if k >= total, otherwise random sample
func (m *Membership) SampleCommittee(ctx context.Context, epoch uint64, k int, seed []byte) ([]Validator, error) {
	m.mu.RLock()
	validators := make([]Validator, 0, len(m.validators))
	for _, v := range m.validators {
		validators = append(validators, *v)
	}
	m.mu.RUnlock()

	if k >= len(validators) {
		return validators, nil
	}

	// Deterministic random selection based on seed
	h := sha256.Sum256(seed)
	rng := rand.New(rand.NewSource(int64(h[0])<<56 | int64(h[1])<<48 | int64(h[2])<<40 | int64(h[3])<<32 |
		int64(h[4])<<24 | int64(h[5])<<16 | int64(h[6])<<8 | int64(h[7])))

	// Fisher-Yates shuffle
	for i := len(validators) - 1; i > 0; i-- {
		j := rng.Intn(i + 1)
		validators[i], validators[j] = validators[j], validators[i]
	}

	return validators[:k], nil
}

// GetValidatorByNodeID returns the validator for a node ID
func (m *Membership) GetValidatorByNodeID(nodeID string) (*Validator, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	voterID, ok := m.nodeIndex[nodeID]
	if !ok {
		return nil, ErrValidatorNotFound
	}

	validator, ok := m.validators[voterID]
	if !ok {
		return nil, ErrValidatorNotFound
	}

	return validator, nil
}

// GetVoterID returns the VoterID for a node ID
func (m *Membership) GetVoterID(nodeID string) (VoterID, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	voterID, ok := m.nodeIndex[nodeID]
	return voterID, ok
}

// GetNodeID returns the node ID for a VoterID
func (m *Membership) GetNodeID(voterID VoterID) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	validator, ok := m.validators[voterID]
	if !ok {
		return "", false
	}

	return validator.NodeID, true
}

// Count returns the number of validators
func (m *Membership) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.validators)
}

// DeriveVoterID creates a canonical VoterID from domain and data
func DeriveVoterID(domain string, data []byte) VoterID {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write(data)
	var v VoterID
	copy(v[:], h.Sum(nil))
	return v
}

// String returns hex representation
func (v VoterID) String() string {
	return fmt.Sprintf("%x", v[:8]) // First 8 bytes for readability
}

// ThresholdPolicy implements finality for MPC threshold signatures
// Finality is achieved when threshold+1 validators have signed
type ThresholdPolicy struct {
	threshold int
	votes     map[VoterID]bool
	mu        sync.Mutex
}

// NewThresholdPolicy creates a threshold-based finality policy
func NewThresholdPolicy(threshold int) *ThresholdPolicy {
	return &ThresholdPolicy{
		threshold: threshold,
		votes:     make(map[VoterID]bool),
	}
}

// AddVote records a vote from a validator
func (p *ThresholdPolicy) AddVote(voterID VoterID) int {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.votes[voterID] = true
	return len(p.votes)
}

// HasQuorum returns true if threshold is met
func (p *ThresholdPolicy) HasQuorum() bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	return len(p.votes) >= p.threshold+1
}

// VoteCount returns current vote count
func (p *ThresholdPolicy) VoteCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	return len(p.votes)
}

// Reset clears all votes
func (p *ThresholdPolicy) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.votes = make(map[VoterID]bool)
}

// ProposerElection selects leader for a round (round-robin in PoA)
type ProposerElection struct {
	membership *Membership
}

// NewProposerElection creates a round-robin proposer election
func NewProposerElection(membership *Membership) *ProposerElection {
	return &ProposerElection{membership: membership}
}

// Leader returns the leader for a round (round-robin by VoterID)
func (e *ProposerElection) Leader(ctx context.Context, round uint64, validators *ValidatorSet) (VoterID, error) {
	if len(validators.Validators) == 0 {
		return VoterID{}, errors.New("no validators")
	}

	// Round-robin selection
	idx := round % uint64(len(validators.Validators))
	return validators.Validators[idx].ID, nil
}

func init() {
	// Seed random with time for non-deterministic operations
	rand.Seed(time.Now().UnixNano())
}
