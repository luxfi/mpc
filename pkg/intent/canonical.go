// Package intent defines the CanonicalIntent — the deterministically-encoded
// description of a transaction that an MPC node signs over.
//
// The CanonicalIntent is the single source of truth for what was approved.
// Every MPC node must independently reconstruct the same digest from the
// same intent fields, so encoding is RFC 8949 §4.2 deterministic CBOR.
//
// The Approvals and NodeAttestations fields are excluded from the digest
// (they are signatures over the digest itself; including them would be
// circular).
package intent

import (
	"crypto/sha256"
	"errors"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// WalletTier classifies wallets by risk profile. Each tier carries a
// distinct approval threshold and policy bundle.
type WalletTier string

const (
	TierHot           WalletTier = "hot"
	TierWarm          WalletTier = "warm"
	TierCold          WalletTier = "cold"
	TierGas           WalletTier = "gas"
	TierBridge        WalletTier = "bridge"
	TierContractAdmin WalletTier = "contract_admin"
	TierValidator     WalletTier = "validator"
	TierQuarantine    WalletTier = "quarantine"
	TierDR            WalletTier = "disaster_recovery"
)

// IsValid reports whether t is a known tier.
func (t WalletTier) IsValid() bool {
	switch t {
	case TierHot, TierWarm, TierCold, TierGas, TierBridge,
		TierContractAdmin, TierValidator, TierQuarantine, TierDR:
		return true
	}
	return false
}

// IntentVersion is the schema version. Bump only on breaking changes.
const IntentVersion = "1"

// CanonicalIntent is the on-the-wire representation of a transaction
// pending threshold signing.
//
// The struct is deliberately frozen: all fields are required, none are
// optional, and the field tags use compact CBOR keys for stable encoding.
type CanonicalIntent struct {
	IntentVersion    string              `cbor:"intent_version"`
	SessionID        string              `cbor:"session_id"`
	WalletID         string              `cbor:"wallet_id"`
	WalletTier       WalletTier          `cbor:"wallet_tier"`
	Chain            string              `cbor:"chain"` // CAIP-2 e.g. "eip155:1"
	Asset            string              `cbor:"asset"`
	From             string              `cbor:"from"`
	To               string              `cbor:"to"`
	Amount           string              `cbor:"amount"` // arbitrary-precision decimal as string
	MaxFee           string              `cbor:"max_fee"`
	Nonce            string              `cbor:"nonce"`
	CalldataHash     [32]byte            `cbor:"calldata_hash"` // keccak256 / sha256 of contract calldata
	HumanSummary     string              `cbor:"human_summary"`
	PolicyID         string              `cbor:"policy_id"`
	PolicyHash       [32]byte            `cbor:"policy_hash"` // hash of the active policy bundle this intent was approved against
	RiskVerdictID    string              `cbor:"risk_verdict_id"`
	SimulationHash   [32]byte            `cbor:"simulation_hash"` // hash of the EVM simulation result
	ExpiresAt        time.Time           `cbor:"expires_at"`
	Approvals        []ApprovalSignature `cbor:"approvals"`         // executive sigs over the digest; excluded from digest
	NodeAttestations []NodeAttestation   `cbor:"node_attestations"` // per-node verifier decisions; excluded from digest
}

// ApprovalSignature is one executive's signature over the intent digest.
type ApprovalSignature struct {
	SignerID  string    `cbor:"signer_id"`
	PublicKey []byte    `cbor:"public_key"` // Ed25519 public key (32 bytes)
	Signature []byte    `cbor:"signature"`  // Ed25519(digest)
	SignedAt  time.Time `cbor:"signed_at"`
}

// NodeAttestation is one MPC node's verifier decision, signed with its
// identity key. Persisted to the audit log whether positive or negative.
type NodeAttestation struct {
	NodeID    string    `cbor:"node_id"`
	PublicKey []byte    `cbor:"public_key"` // node identity Ed25519 pubkey
	Verdict   string    `cbor:"verdict"`    // "approve" | "reject"
	Reason    string    `cbor:"reason,omitempty"`
	Signature []byte    `cbor:"signature"` // Ed25519(digest || verdict)
	SignedAt  time.Time `cbor:"signed_at"`
}

// detEnc is the singleton deterministic encoder used by Digest().
// We construct it once and reuse it; cbor.EncMode is goroutine-safe.
var detEnc cbor.EncMode

func init() {
	enc, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		// CoreDetEncOptions() is constant — this can never fail. Panic
		// at init time so the bug surfaces before any signing happens.
		panic("intent: cbor.CoreDetEncOptions().EncMode() failed: " + err.Error())
	}
	detEnc = enc
}

// digestBody is the subset of CanonicalIntent that participates in the
// digest. Approvals + NodeAttestations are excluded because they are
// signatures over the digest itself.
type digestBody struct {
	IntentVersion  string     `cbor:"intent_version"`
	SessionID      string     `cbor:"session_id"`
	WalletID       string     `cbor:"wallet_id"`
	WalletTier     WalletTier `cbor:"wallet_tier"`
	Chain          string     `cbor:"chain"`
	Asset          string     `cbor:"asset"`
	From           string     `cbor:"from"`
	To             string     `cbor:"to"`
	Amount         string     `cbor:"amount"`
	MaxFee         string     `cbor:"max_fee"`
	Nonce          string     `cbor:"nonce"`
	CalldataHash   [32]byte   `cbor:"calldata_hash"`
	HumanSummary   string     `cbor:"human_summary"`
	PolicyID       string     `cbor:"policy_id"`
	PolicyHash     [32]byte   `cbor:"policy_hash"`
	RiskVerdictID  string     `cbor:"risk_verdict_id"`
	SimulationHash [32]byte   `cbor:"simulation_hash"`
	ExpiresAt      time.Time  `cbor:"expires_at"`
}

// Digest returns the SHA-256 of the deterministic CBOR encoding of the
// intent body. The Approvals and NodeAttestations fields are excluded.
//
// The same intent produces the same digest on every node, every run.
func (ci *CanonicalIntent) Digest() ([32]byte, error) {
	body := digestBody{
		IntentVersion:  ci.IntentVersion,
		SessionID:      ci.SessionID,
		WalletID:       ci.WalletID,
		WalletTier:     ci.WalletTier,
		Chain:          ci.Chain,
		Asset:          ci.Asset,
		From:           ci.From,
		To:             ci.To,
		Amount:         ci.Amount,
		MaxFee:         ci.MaxFee,
		Nonce:          ci.Nonce,
		CalldataHash:   ci.CalldataHash,
		HumanSummary:   ci.HumanSummary,
		PolicyID:       ci.PolicyID,
		PolicyHash:     ci.PolicyHash,
		RiskVerdictID:  ci.RiskVerdictID,
		SimulationHash: ci.SimulationHash,
		ExpiresAt:      ci.ExpiresAt.UTC(),
	}
	enc, err := detEnc.Marshal(body)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(enc), nil
}

// Marshal serializes the full intent (body + approvals + attestations)
// using the same deterministic encoder. Used for transport between
// coordinator and nodes.
func (ci *CanonicalIntent) Marshal() ([]byte, error) {
	return detEnc.Marshal(ci)
}

// Unmarshal restores a CanonicalIntent from its CBOR bytes.
func Unmarshal(b []byte) (*CanonicalIntent, error) {
	var ci CanonicalIntent
	if err := cbor.Unmarshal(b, &ci); err != nil {
		return nil, err
	}
	return &ci, nil
}

// Validate performs cheap structural checks. Policy + risk + approval
// checks live in pkg/policy.LocalVerifier — this only catches malformed
// intents before they reach the verifier.
func (ci *CanonicalIntent) Validate() error {
	if ci.IntentVersion != IntentVersion {
		return errors.New("intent: unsupported version")
	}
	if ci.SessionID == "" {
		return errors.New("intent: session_id required")
	}
	if ci.WalletID == "" {
		return errors.New("intent: wallet_id required")
	}
	if !ci.WalletTier.IsValid() {
		return errors.New("intent: invalid wallet_tier")
	}
	if ci.Chain == "" {
		return errors.New("intent: chain required")
	}
	if ci.From == "" {
		return errors.New("intent: from required")
	}
	if ci.PolicyID == "" {
		return errors.New("intent: policy_id required")
	}
	if ci.ExpiresAt.IsZero() {
		return errors.New("intent: expires_at required")
	}
	return nil
}
