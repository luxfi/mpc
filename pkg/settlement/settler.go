package settlement

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// SettlementStatus tracks the settlement lifecycle.
type SettlementStatus string

const (
	SettlementPending     SettlementStatus = "pending"
	SettlementHSMSigning  SettlementStatus = "hsm_signing"
	SettlementBroadcast   SettlementStatus = "broadcast"
	SettlementConfirming  SettlementStatus = "confirming"
	SettlementFinalized   SettlementStatus = "finalized"
	SettlementVerified    SettlementStatus = "verified"
	SettlementFailed      SettlementStatus = "failed"
)

// HSMProvider abstracts hardware security module signing operations.
type HSMProvider interface {
	Sign(ctx context.Context, keyID string, message []byte) ([]byte, error)
	Verify(ctx context.Context, keyID string, message, signature []byte) (bool, error)
}

// HSMSignature is an attestation from a liquidity multisig signer backed by HSM.
type HSMSignature struct {
	SignerID  string    `json:"signerId"`
	KeyID     string    `json:"keyId"`
	Signature string    `json:"signature"` // hex-encoded
	Provider  string    `json:"provider"`  // aws, gcp, azure, zymbit, kms
	SignedAt  time.Time `json:"signedAt"`
}

// Settlement tracks the lifecycle from matched trade to finalized on-chain tx.
// It links an intent to its settlement transaction and records HSM multisig attestations.
type Settlement struct {
	ID       string `json:"id"`
	OrgID    string `json:"orgId"`
	IntentID string `json:"intentId"`
	MatchID  string `json:"matchId,omitempty"`

	// Settlement transaction
	SettlementTxHash string `json:"settlementTxHash,omitempty"`

	// Finalization
	FinalizeTxHash       string `json:"finalizeTxHash,omitempty"`
	FinalizedBlockNumber *int64 `json:"finalizedBlockNumber,omitempty"`

	// HSM multisig attestations
	HSMSignatures []HSMSignature `json:"hsmSignatures,omitempty"`
	RequiredSigs  int            `json:"requiredSigs"` // how many HSM sigs needed

	// Transfer agency verification
	TransferAgencyHash       string     `json:"transferAgencyHash,omitempty"`
	TransferAgencyVerified   bool       `json:"transferAgencyVerified"`
	TransferAgencyVerifiedAt *time.Time `json:"transferAgencyVerifiedAt,omitempty"`

	// Timestamps for every stage
	CreatedAt    time.Time  `json:"createdAt"`
	MatchedAt    *time.Time `json:"matchedAt,omitempty"`
	SignedAt     *time.Time `json:"signedAt,omitempty"` // when all HSM sigs collected
	BroadcastAt  *time.Time `json:"broadcastAt,omitempty"`
	FinalizedAt  *time.Time `json:"finalizedAt,omitempty"`
	VerifiedAt   *time.Time `json:"verifiedAt,omitempty"`

	Status  SettlementStatus `json:"status"`
	History []Transition     `json:"history,omitempty"`
}

// Settler manages the settlement lifecycle.
type Settler struct {
	requiredSigs int
}

// NewSettler creates a settler that requires the given number of HSM signatures.
func NewSettler(requiredSigs int) *Settler {
	if requiredSigs < 1 {
		requiredSigs = 1
	}
	return &Settler{requiredSigs: requiredSigs}
}

// CreateSettlement initializes a settlement record from a matched intent.
func (s *Settler) CreateSettlement(id, orgID string, intent *Intent, matchID string) (*Settlement, error) {
	if intent.Status != IntentMatched {
		return nil, fmt.Errorf("settler: intent must be in 'matched' status, got %s", intent.Status)
	}

	now := time.Now()
	return &Settlement{
		ID:           id,
		OrgID:        orgID,
		IntentID:     intent.ID,
		MatchID:      matchID,
		RequiredSigs: s.requiredSigs,
		CreatedAt:    now,
		MatchedAt:    &now,
		Status:       SettlementPending,
		History: []Transition{{
			From:      "",
			To:        string(SettlementPending),
			Timestamp: now,
			Detail:    fmt.Sprintf("settlement created from intent %s, match %s", intent.ID, matchID),
			Actor:     "system",
		}},
	}, nil
}

// AddHSMSignature adds an HSM attestation to the settlement.
// When enough signatures are collected, the settlement transitions to hsm_signing → broadcast-ready.
func (s *Settler) AddHSMSignature(ctx context.Context, settlement *Settlement, signerID, keyID string, hsmProvider HSMProvider, message []byte) error {
	if settlement.Status != SettlementPending && settlement.Status != SettlementHSMSigning {
		return fmt.Errorf("settler: cannot add HSM signature in status %s", settlement.Status)
	}

	// Check for duplicate signer
	for _, existing := range settlement.HSMSignatures {
		if existing.SignerID == signerID {
			return fmt.Errorf("settler: signer %s already signed", signerID)
		}
	}

	// Sign with HSM
	sig, err := hsmProvider.Sign(ctx, keyID, message)
	if err != nil {
		return fmt.Errorf("settler: HSM signing failed: %w", err)
	}

	// Verify the signature
	ok, err := hsmProvider.Verify(ctx, keyID, message, sig)
	if err != nil || !ok {
		return fmt.Errorf("settler: HSM signature verification failed")
	}

	now := time.Now()
	settlement.HSMSignatures = append(settlement.HSMSignatures, HSMSignature{
		SignerID:  signerID,
		KeyID:     keyID,
		Signature: fmt.Sprintf("%x", sig),
		Provider:  "hsm",
		SignedAt:  now,
	})

	if settlement.Status == SettlementPending {
		settlement.transition(string(SettlementHSMSigning), "first HSM signature collected", "system")
	}

	// Check if we have enough signatures
	if len(settlement.HSMSignatures) >= settlement.RequiredSigs {
		settlement.SignedAt = &now
		settlement.transition(string(SettlementBroadcast),
			fmt.Sprintf("collected %d/%d HSM signatures, ready for broadcast",
				len(settlement.HSMSignatures), settlement.RequiredSigs), "system")
	}

	return nil
}

// MarkBroadcast records that the settlement transaction has been broadcast.
func (s *Settler) MarkBroadcast(settlement *Settlement, txHash string) error {
	if settlement.Status != SettlementBroadcast {
		return fmt.Errorf("settler: cannot broadcast in status %s", settlement.Status)
	}

	now := time.Now()
	settlement.SettlementTxHash = txHash
	settlement.BroadcastAt = &now
	settlement.transition(string(SettlementConfirming),
		fmt.Sprintf("settlement tx broadcast: %s", txHash), "system")
	return nil
}

// MarkFinalized records that the settlement transaction has been finalized on-chain.
func (s *Settler) MarkFinalized(settlement *Settlement, finalizeTxHash string, blockNumber int64) error {
	if settlement.Status != SettlementConfirming {
		return fmt.Errorf("settler: cannot finalize in status %s", settlement.Status)
	}

	now := time.Now()
	settlement.FinalizeTxHash = finalizeTxHash
	settlement.FinalizedBlockNumber = &blockNumber
	settlement.FinalizedAt = &now
	settlement.transition(string(SettlementFinalized),
		fmt.Sprintf("finalized at block %d, tx %s", blockNumber, finalizeTxHash), "system")
	return nil
}

// MarkVerified records successful transfer agency verification.
func (s *Settler) MarkVerified(settlement *Settlement, agencyHash string) error {
	if settlement.Status != SettlementFinalized {
		return fmt.Errorf("settler: cannot verify in status %s", settlement.Status)
	}
	if agencyHash == "" {
		return errors.New("settler: transfer agency hash must not be empty")
	}

	now := time.Now()
	settlement.TransferAgencyHash = agencyHash
	settlement.TransferAgencyVerified = true
	settlement.TransferAgencyVerifiedAt = &now
	settlement.VerifiedAt = &now
	settlement.transition(string(SettlementVerified),
		fmt.Sprintf("verified by transfer agency, hash: %s", agencyHash), "transfer_agency")
	return nil
}

// MarkFailed records a settlement failure.
func (s *Settler) MarkFailed(settlement *Settlement, reason string) {
	settlement.transition(string(SettlementFailed), reason, "system")
}

func (settlement *Settlement) transition(to, detail, actor string) {
	settlement.History = append(settlement.History, Transition{
		From:      string(settlement.Status),
		To:        to,
		Timestamp: time.Now(),
		Detail:    detail,
		Actor:     actor,
	})
	settlement.Status = SettlementStatus(to)
}
