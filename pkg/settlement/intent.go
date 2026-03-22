// Package settlement implements the full settlement lifecycle from the
// architecture diagram:
//
//	Intent → Sign → Co-Sign (HSM) → Record on-chain → Match → Settle → Finalize → Verify
//
// It answers the two key questions:
//  1. "Did the tx land?" — via on-chain receipt tracking
//  2. "When did we record it?" — via timestamped state transitions
package settlement

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// IntentType describes what the user wants to do.
type IntentType string

const (
	IntentBuy      IntentType = "buy"
	IntentSell     IntentType = "sell"
	IntentTransfer IntentType = "transfer"
	IntentBridge   IntentType = "bridge"
)

// IntentStatus tracks the lifecycle of an intent.
type IntentStatus string

const (
	IntentPendingSign IntentStatus = "pending_sign"
	IntentSigned      IntentStatus = "signed"
	IntentCoSigned    IntentStatus = "co_signed"
	IntentRecorded    IntentStatus = "recorded"
	IntentMatched     IntentStatus = "matched"
	IntentSettling    IntentStatus = "settling"
	IntentSettled     IntentStatus = "settled"
	IntentVerified    IntentStatus = "verified"
	IntentExpired     IntentStatus = "expired"
	IntentFailed      IntentStatus = "failed"
)

// Intent represents a user's signed intention to execute a trade or transfer.
// The intent captures what the user wanted, when they signed it, and proof of
// authorization from both the user (MPC wallet) and the platform (HSM).
type Intent struct {
	ID        string     `json:"id"`
	OrgID     string     `json:"orgId"`
	WalletID  string     `json:"walletId"`
	Type      IntentType `json:"type"`
	Chain     string     `json:"chain"`
	ToAddress string     `json:"toAddress,omitempty"`
	Amount    string     `json:"amount"`
	Token     string     `json:"token,omitempty"`

	// Cryptographic proof
	IntentHash    string `json:"intentHash"`              // keccak256 of canonical data
	Signature     string `json:"signature,omitempty"`     // user MPC signature (first signer)
	CoSignature   string `json:"coSignature,omitempty"`   // platform HSM signature (second signer)
	CoSignerKeyID string `json:"coSignerKeyId,omitempty"` // HSM key used

	// On-chain recording
	OnChainTxHash string     `json:"onChainTxHash,omitempty"` // tx that recorded intent
	RecordedAt    *time.Time `json:"recordedAt,omitempty"`    // when confirmed on-chain
	RecordedBlock *int64     `json:"recordedBlock,omitempty"`

	// Matching
	MatchID   string     `json:"matchId,omitempty"`
	MatchedAt *time.Time `json:"matchedAt,omitempty"`

	Status    IntentStatus `json:"status"`
	ExpiresAt *time.Time   `json:"expiresAt,omitempty"`
	CreatedAt time.Time    `json:"createdAt"`

	History []Transition `json:"history,omitempty"`
}

// Transition records a single state change.
type Transition struct {
	From      string    `json:"from"`
	To        string    `json:"to"`
	Timestamp time.Time `json:"timestamp"`
	Detail    string    `json:"detail,omitempty"`
	Actor     string    `json:"actor,omitempty"` // userID, "hsm", or "system"
}

// NewIntent creates a new intent in pending_sign status.
func NewIntent(id, orgID, walletID string, intentType IntentType, chain, toAddr, amount, token string) *Intent {
	now := time.Now()
	expiry := now.Add(24 * time.Hour)
	i := &Intent{
		ID:        id,
		OrgID:     orgID,
		WalletID:  walletID,
		Type:      intentType,
		Chain:     chain,
		ToAddress: toAddr,
		Amount:    amount,
		Token:     token,
		Status:    IntentPendingSign,
		ExpiresAt: &expiry,
		CreatedAt: now,
	}
	i.IntentHash = i.Hash()
	return i
}

// Hash computes a domain-separated, versioned SHA-256 hash of the intent's
// canonical fields. The "lux-mpc-intent:v1|" prefix provides domain separation
// and prevents cross-version collision if the canonical format changes.
// This is the message that gets signed by both the user's MPC wallet and the platform HSM.
func (i *Intent) Hash() string {
	// Canonical representation: sorted key=value pairs, pipe-separated.
	// This ensures deterministic hashing regardless of field ordering.
	fields := []string{
		fmt.Sprintf("amount=%s", i.Amount),
		fmt.Sprintf("chain=%s", i.Chain),
		fmt.Sprintf("orgId=%s", i.OrgID),
		fmt.Sprintf("to=%s", i.ToAddress),
		fmt.Sprintf("token=%s", i.Token),
		fmt.Sprintf("type=%s", string(i.Type)),
		fmt.Sprintf("walletId=%s", i.WalletID),
	}
	sort.Strings(fields)
	canonical := "lux-mpc-intent:v1|" + strings.Join(fields, "|")

	h := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(h[:])
}

// SetSignature records the user's MPC wallet signature (first signer).
func (i *Intent) SetSignature(sig string, actor string) error {
	if i.Status != IntentPendingSign {
		return fmt.Errorf("intent: cannot sign in status %s", i.Status)
	}
	if sig == "" {
		return errors.New("intent: signature must not be empty")
	}
	i.Signature = sig
	i.transition(string(IntentSigned), "user signed via MPC wallet", actor)
	return nil
}

// SetCoSignature records the platform HSM signature (second signer).
func (i *Intent) SetCoSignature(sig, keyID, actor string) error {
	if i.Status != IntentSigned {
		return fmt.Errorf("intent: cannot co-sign in status %s (must be signed first)", i.Status)
	}
	if sig == "" {
		return errors.New("intent: co-signature must not be empty")
	}
	i.CoSignature = sig
	i.CoSignerKeyID = keyID
	i.transition(string(IntentCoSigned), fmt.Sprintf("HSM co-signed with key %s", keyID), actor)
	return nil
}

// RecordOnChain marks the intent as recorded on the blockchain.
func (i *Intent) RecordOnChain(txHash string, blockNumber int64) error {
	if i.Status != IntentCoSigned {
		return fmt.Errorf("intent: cannot record in status %s (must be co-signed first)", i.Status)
	}
	now := time.Now()
	i.OnChainTxHash = txHash
	i.RecordedAt = &now
	i.RecordedBlock = &blockNumber
	i.transition(string(IntentRecorded),
		fmt.Sprintf("recorded on-chain in tx %s at block %d", txHash, blockNumber), "system")
	return nil
}

// SetMatched marks the intent as matched by the order matching engine.
func (i *Intent) SetMatched(matchID string) error {
	if i.Status != IntentRecorded {
		return fmt.Errorf("intent: cannot match in status %s", i.Status)
	}
	now := time.Now()
	i.MatchID = matchID
	i.MatchedAt = &now
	i.transition(string(IntentMatched), fmt.Sprintf("matched as %s", matchID), "system")
	return nil
}

// IsExpired returns true if the intent has passed its expiry time.
func (i *Intent) IsExpired() bool {
	if i.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*i.ExpiresAt)
}

// Verify checks that the intent hash is consistent with the current field values.
func (i *Intent) Verify() error {
	expected := i.Hash()
	if i.IntentHash != expected {
		return fmt.Errorf("intent: hash mismatch (stored=%s, computed=%s)", i.IntentHash, expected)
	}
	return nil
}

func (i *Intent) transition(to, detail, actor string) {
	i.History = append(i.History, Transition{
		From:      string(i.Status),
		To:        to,
		Timestamp: time.Now(),
		Detail:    detail,
		Actor:     actor,
	})
	i.Status = IntentStatus(to)
}
