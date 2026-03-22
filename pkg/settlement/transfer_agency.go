package settlement

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// TransferRecord is the data registered with the transfer agency for verification.
type TransferRecord struct {
	TxHash         string    `json:"txHash"`
	IntentHash     string    `json:"intentHash"`
	SettlementHash string    `json:"settlementHash"`
	Chain          string    `json:"chain"`
	FromAddress    string    `json:"fromAddress"`
	ToAddress      string    `json:"toAddress"`
	Amount         string    `json:"amount"`
	Token          string    `json:"token,omitempty"`
	Timestamp      time.Time `json:"timestamp"`
}

// VerificationResult is the outcome of a transfer agency hash verification.
type VerificationResult struct {
	Verified      bool      `json:"verified"`
	MatchedAt     time.Time `json:"matchedAt"`
	RecordHash    string    `json:"recordHash"`   // the hash stored at the agency
	ComputedHash  string    `json:"computedHash"` // the hash we computed
	Discrepancies []string  `json:"discrepancies,omitempty"`
}

// ComputeTransferHash computes a deterministic hash of a transfer record.
// This is the hash that gets registered with the transfer agency and later
// verified against the on-chain transaction data.
func ComputeTransferHash(r *TransferRecord) string {
	canonical := fmt.Sprintf(
		"amount=%s|chain=%s|from=%s|intent=%s|settlement=%s|timestamp=%d|to=%s|token=%s|tx=%s",
		r.Amount,
		r.Chain,
		r.FromAddress,
		r.IntentHash,
		r.SettlementHash,
		r.Timestamp.Unix(),
		r.ToAddress,
		r.Token,
		r.TxHash,
	)
	h := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(h[:])
}

// VerifyTransferRecord checks that a transfer record's hash matches the expected value.
// This is the "verify hashes on Transfer Agency" step from the architecture diagram.
func VerifyTransferRecord(record *TransferRecord, expectedHash string) *VerificationResult {
	computed := ComputeTransferHash(record)
	result := &VerificationResult{
		Verified:     computed == expectedHash,
		MatchedAt:    time.Now(),
		RecordHash:   expectedHash,
		ComputedHash: computed,
	}

	if !result.Verified {
		result.Discrepancies = append(result.Discrepancies,
			fmt.Sprintf("hash mismatch: expected %s, got %s", expectedHash, computed))
	}

	return result
}

// TransferAgency verifies that settlement hashes match between the intent,
// the on-chain transaction, and the agency's records.
type TransferAgency struct {
	// In production, this would be backed by an external service endpoint.
	// For now, it maintains an in-process registry for hash verification.
	records map[string]*TransferRecord // txHash → record
}

// NewTransferAgency creates a new transfer agency verifier.
func NewTransferAgency() *TransferAgency {
	return &TransferAgency{
		records: make(map[string]*TransferRecord),
	}
}

// Register stores a transfer record for later verification.
func (ta *TransferAgency) Register(record *TransferRecord) (string, error) {
	if record.TxHash == "" {
		return "", fmt.Errorf("transfer_agency: tx hash required")
	}
	hash := ComputeTransferHash(record)
	ta.records[record.TxHash] = record
	return hash, nil
}

// Verify checks that a transaction's recorded data matches what the agency has.
func (ta *TransferAgency) Verify(txHash string, record *TransferRecord) *VerificationResult {
	stored, ok := ta.records[txHash]
	if !ok {
		return &VerificationResult{
			Verified:      false,
			MatchedAt:     time.Now(),
			Discrepancies: []string{"no record found for tx " + txHash},
		}
	}

	storedHash := ComputeTransferHash(stored)
	incomingHash := ComputeTransferHash(record)

	result := &VerificationResult{
		Verified:     storedHash == incomingHash,
		MatchedAt:    time.Now(),
		RecordHash:   storedHash,
		ComputedHash: incomingHash,
	}

	if !result.Verified {
		// Detail which fields differ
		if stored.Amount != record.Amount {
			result.Discrepancies = append(result.Discrepancies,
				fmt.Sprintf("amount: stored=%s, incoming=%s", stored.Amount, record.Amount))
		}
		if stored.ToAddress != record.ToAddress {
			result.Discrepancies = append(result.Discrepancies,
				fmt.Sprintf("toAddress: stored=%s, incoming=%s", stored.ToAddress, record.ToAddress))
		}
		if stored.IntentHash != record.IntentHash {
			result.Discrepancies = append(result.Discrepancies,
				fmt.Sprintf("intentHash: stored=%s, incoming=%s", stored.IntentHash, record.IntentHash))
		}
		if stored.Chain != record.Chain {
			result.Discrepancies = append(result.Discrepancies,
				fmt.Sprintf("chain: stored=%s, incoming=%s", stored.Chain, record.Chain))
		}
	}

	return result
}
