package settlement

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntentHashDeterministic(t *testing.T) {
	i1 := NewIntent("id1", "org1", "wallet1", IntentBuy, "ethereum", "0xabc", "1000", "USDC")
	i2 := NewIntent("id2", "org1", "wallet1", IntentBuy, "ethereum", "0xabc", "1000", "USDC")

	// Same fields → same hash, regardless of ID or creation time
	assert.Equal(t, i1.IntentHash, i2.IntentHash)
	assert.NotEmpty(t, i1.IntentHash)
}

func TestIntentHashChangesWithFields(t *testing.T) {
	i1 := NewIntent("id1", "org1", "wallet1", IntentBuy, "ethereum", "0xabc", "1000", "USDC")
	i2 := NewIntent("id2", "org1", "wallet1", IntentBuy, "ethereum", "0xabc", "2000", "USDC")

	// Different amount → different hash
	assert.NotEqual(t, i1.IntentHash, i2.IntentHash)
}

func TestIntentVerify(t *testing.T) {
	i := NewIntent("id1", "org1", "wallet1", IntentSell, "lux", "0xdef", "500", "LUX")
	require.NoError(t, i.Verify())

	// Tamper with a field
	i.Amount = "999"
	assert.Error(t, i.Verify())
}

func TestIntentSignAndCoSign(t *testing.T) {
	i := NewIntent("id1", "org1", "wallet1", IntentTransfer, "ethereum", "0xabc", "100", "ETH")

	// Can't co-sign before signing
	err := i.SetCoSignature("cosig", "key1", "hsm")
	assert.Error(t, err)

	// Sign
	err = i.SetSignature("sig123", "user1")
	require.NoError(t, err)
	assert.Equal(t, IntentSigned, i.Status)
	assert.Equal(t, "sig123", i.Signature)
	require.Len(t, i.History, 1)

	// Can't sign twice
	err = i.SetSignature("sig456", "user1")
	assert.Error(t, err)

	// Co-sign
	err = i.SetCoSignature("cosig456", "hsm-key-1", "hsm")
	require.NoError(t, err)
	assert.Equal(t, IntentCoSigned, i.Status)
	assert.Equal(t, "cosig456", i.CoSignature)
	assert.Equal(t, "hsm-key-1", i.CoSignerKeyID)
	require.Len(t, i.History, 2)
}

func TestIntentRecordOnChain(t *testing.T) {
	i := NewIntent("id1", "org1", "wallet1", IntentBuy, "lux", "0xabc", "50", "ZOO")

	// Can't record without co-signing
	err := i.RecordOnChain("0xtx1", 100)
	assert.Error(t, err)

	i.SetSignature("sig", "user")
	i.SetCoSignature("cosig", "key", "hsm")

	err = i.RecordOnChain("0xtx1", 100)
	require.NoError(t, err)
	assert.Equal(t, IntentRecorded, i.Status)
	assert.Equal(t, "0xtx1", i.OnChainTxHash)
	assert.NotNil(t, i.RecordedAt)
	assert.Equal(t, int64(100), *i.RecordedBlock)
}

func TestIntentMatching(t *testing.T) {
	i := NewIntent("id1", "org1", "wallet1", IntentSell, "ethereum", "0xabc", "1000", "USDC")
	i.SetSignature("sig", "user")
	i.SetCoSignature("cosig", "key", "hsm")
	i.RecordOnChain("0xtx1", 50)

	err := i.SetMatched("match-001")
	require.NoError(t, err)
	assert.Equal(t, IntentMatched, i.Status)
	assert.Equal(t, "match-001", i.MatchID)
	assert.NotNil(t, i.MatchedAt)
}

func TestIntentFullLifecycle(t *testing.T) {
	i := NewIntent("id1", "org1", "wallet1", IntentBuy, "lux", "0xabc", "100", "LUX")

	i.SetSignature("sig", "user-1")
	i.SetCoSignature("cosig", "hsm-key-1", "hsm-node-0")
	i.RecordOnChain("0xabc123", 1000)
	i.SetMatched("match-42")

	assert.Equal(t, IntentMatched, i.Status)
	require.Len(t, i.History, 4)

	// Verify full transition chain
	assert.Equal(t, "pending_sign", i.History[0].From)
	assert.Equal(t, "signed", i.History[0].To)
	assert.Equal(t, "signed", i.History[1].From)
	assert.Equal(t, "co_signed", i.History[1].To)
	assert.Equal(t, "co_signed", i.History[2].From)
	assert.Equal(t, "recorded", i.History[2].To)
	assert.Equal(t, "recorded", i.History[3].From)
	assert.Equal(t, "matched", i.History[3].To)
}

func TestIntentExpiry(t *testing.T) {
	i := NewIntent("id1", "org1", "wallet1", IntentBuy, "ethereum", "0xabc", "100", "ETH")
	assert.False(t, i.IsExpired()) // just created, 24h expiry

	i.ExpiresAt = nil
	assert.False(t, i.IsExpired()) // no expiry
}
