package settlement

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Mock HSM provider ---

type mockHSM struct {
	signResult []byte
	signErr    error
	verifyOK   bool
}

func (m *mockHSM) Sign(_ context.Context, _ string, _ []byte) ([]byte, error) {
	if m.signErr != nil {
		return nil, m.signErr
	}
	return m.signResult, nil
}

func (m *mockHSM) Verify(_ context.Context, _ string, _, _ []byte) (bool, error) {
	return m.verifyOK, nil
}

func makeMatchedIntent(t *testing.T) *Intent {
	t.Helper()
	i := NewIntent("intent-1", "org-1", "wallet-1", IntentBuy, "lux", "0xabc", "100", "LUX")
	require.NoError(t, i.SetSignature("sig", "user"))
	require.NoError(t, i.SetCoSignature("cosig", "key", "hsm"))
	require.NoError(t, i.RecordOnChain("0xtx", 100))
	require.NoError(t, i.SetMatched("match-1"))
	return i
}

func TestSettlementLifecycle(t *testing.T) {
	settler := NewSettler(2) // require 2 HSM sigs

	intent := makeMatchedIntent(t)

	// Create settlement
	s, err := settler.CreateSettlement("settle-1", "org-1", intent, "match-1")
	require.NoError(t, err)
	assert.Equal(t, SettlementPending, s.Status)
	assert.Equal(t, "intent-1", s.IntentID)
	assert.NotNil(t, s.MatchedAt)

	// First HSM signature
	hsm := &mockHSM{signResult: []byte("sig1"), verifyOK: true}
	err = settler.AddHSMSignature(context.Background(), s, "signer-1", "key-1", hsm, []byte("msg"))
	require.NoError(t, err)
	assert.Equal(t, SettlementHSMSigning, s.Status)
	assert.Len(t, s.HSMSignatures, 1)

	// Duplicate signer rejected
	err = settler.AddHSMSignature(context.Background(), s, "signer-1", "key-1", hsm, []byte("msg"))
	assert.Error(t, err)

	// Second HSM signature → transitions to broadcast
	hsm2 := &mockHSM{signResult: []byte("sig2"), verifyOK: true}
	err = settler.AddHSMSignature(context.Background(), s, "signer-2", "key-2", hsm2, []byte("msg"))
	require.NoError(t, err)
	assert.Equal(t, SettlementBroadcast, s.Status)
	assert.Len(t, s.HSMSignatures, 2)
	assert.NotNil(t, s.SignedAt)

	// Broadcast
	err = settler.MarkBroadcast(s, "0xsettle_tx")
	require.NoError(t, err)
	assert.Equal(t, SettlementConfirming, s.Status)
	assert.Equal(t, "0xsettle_tx", s.SettlementTxHash)
	assert.NotNil(t, s.BroadcastAt)

	// Finalize
	err = settler.MarkFinalized(s, "0xfinalize_tx", 200)
	require.NoError(t, err)
	assert.Equal(t, SettlementFinalized, s.Status)
	assert.Equal(t, int64(200), *s.FinalizedBlockNumber)
	assert.NotNil(t, s.FinalizedAt)

	// Verify with transfer agency
	err = settler.MarkVerified(s, "hash-abc-123")
	require.NoError(t, err)
	assert.Equal(t, SettlementVerified, s.Status)
	assert.True(t, s.TransferAgencyVerified)
	assert.NotNil(t, s.VerifiedAt)

	// Full history recorded
	assert.True(t, len(s.History) >= 5) // pending → hsm_signing → broadcast → confirming → finalized → verified
}

func TestSettlementFromUnmatchedIntent(t *testing.T) {
	settler := NewSettler(1)
	intent := NewIntent("i1", "o1", "w1", IntentBuy, "eth", "0x", "1", "ETH")

	_, err := settler.CreateSettlement("s1", "o1", intent, "m1")
	assert.Error(t, err, "should reject intent that isn't matched")
}

func TestSettlementSingleHSMSig(t *testing.T) {
	settler := NewSettler(1) // only 1 sig needed
	intent := makeMatchedIntent(t)

	s, err := settler.CreateSettlement("s1", "org-1", intent, "match-1")
	require.NoError(t, err)

	hsm := &mockHSM{signResult: []byte("sig"), verifyOK: true}
	err = settler.AddHSMSignature(context.Background(), s, "signer-1", "key-1", hsm, []byte("msg"))
	require.NoError(t, err)
	// With only 1 required, should go straight to broadcast status
	assert.Equal(t, SettlementBroadcast, s.Status)
}

func TestSettlementFailure(t *testing.T) {
	settler := NewSettler(1)
	intent := makeMatchedIntent(t)

	s, _ := settler.CreateSettlement("s1", "org-1", intent, "match-1")
	settler.MarkFailed(s, "network timeout")
	assert.Equal(t, SettlementFailed, s.Status)
}

func TestTransferAgencyVerification(t *testing.T) {
	ta := NewTransferAgency()

	record := &TransferRecord{
		TxHash:         "0xabc",
		IntentHash:     "intent-hash",
		SettlementHash: "settle-hash",
		Chain:          "lux",
		FromAddress:    "0x111",
		ToAddress:      "0x222",
		Amount:         "1000",
		Token:          "LUX",
	}

	// Register
	hash, err := ta.Register(record)
	require.NoError(t, err)
	assert.NotEmpty(t, hash)

	// Verify with matching record
	result := ta.Verify("0xabc", record)
	assert.True(t, result.Verified)
	assert.Empty(t, result.Discrepancies)

	// Verify with tampered record
	tampered := *record
	tampered.Amount = "9999"
	result = ta.Verify("0xabc", &tampered)
	assert.False(t, result.Verified)
	assert.NotEmpty(t, result.Discrepancies)

	// Verify unknown tx
	result = ta.Verify("0xunknown", record)
	assert.False(t, result.Verified)
}

func TestTransferHashDeterministic(t *testing.T) {
	r := &TransferRecord{
		TxHash:         "0xabc",
		IntentHash:     "ihash",
		SettlementHash: "shash",
		Chain:          "ethereum",
		FromAddress:    "0x1",
		ToAddress:      "0x2",
		Amount:         "100",
		Token:          "ETH",
	}

	h1 := ComputeTransferHash(r)
	h2 := ComputeTransferHash(r)
	assert.Equal(t, h1, h2)
	assert.Len(t, h1, 64) // hex-encoded SHA-256
}
