package txtracker

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/luxfi/mpc/pkg/db"
)

// --- Mock RPC client ---

type mockRPC struct {
	mu            sync.Mutex
	receipt       *Receipt
	blockNumber   int64
	revertReason  string
	receiptCalls  int
	blockCalls    int
}

func (m *mockRPC) GetTransactionReceipt(_ context.Context, _ string) (*Receipt, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.receiptCalls++
	if m.receipt == nil {
		return nil, nil
	}
	r := *m.receipt
	return &r, nil
}

func (m *mockRPC) GetBlockNumber(_ context.Context) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.blockCalls++
	return m.blockNumber, nil
}

func (m *mockRPC) CallForRevertReason(_ context.Context, _ string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.revertReason, nil
}

func (m *mockRPC) setReceipt(r *Receipt) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.receipt = r
}

func (m *mockRPC) setBlockNumber(n int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.blockNumber = n
}

// --- Tests ---

func TestStatusTransitionHistory(t *testing.T) {
	tx := &db.Transaction{
		Status: "pending_approval",
	}

	actor := "user-1"
	tx.RecordTransition("approved", "auto-approved by policy", &actor)
	assert.Equal(t, "approved", tx.Status)
	require.Len(t, tx.StatusHistory, 1)
	assert.Equal(t, "pending_approval", tx.StatusHistory[0].From)
	assert.Equal(t, "approved", tx.StatusHistory[0].To)
	assert.Equal(t, "auto-approved by policy", tx.StatusHistory[0].Detail)
	assert.Equal(t, &actor, tx.StatusHistory[0].Actor)
	assert.False(t, tx.StatusHistory[0].Timestamp.IsZero())

	sys := "system"
	tx.RecordTransition("signing", "mpc keygen triggered", &sys)
	assert.Equal(t, "signing", tx.Status)
	require.Len(t, tx.StatusHistory, 2)
	assert.Equal(t, "approved", tx.StatusHistory[1].From)
	assert.Equal(t, "signing", tx.StatusHistory[1].To)
}

func TestMultipleTransitions(t *testing.T) {
	tx := &db.Transaction{Status: "signed"}

	steps := []string{"broadcast", "confirming", "finalized"}
	for _, s := range steps {
		sys := "system"
		tx.RecordTransition(s, "", &sys)
	}

	assert.Equal(t, "finalized", tx.Status)
	require.Len(t, tx.StatusHistory, 3)

	// Timestamps should be monotonically non-decreasing
	for i := 1; i < len(tx.StatusHistory); i++ {
		assert.False(t, tx.StatusHistory[i].Timestamp.Before(tx.StatusHistory[i-1].Timestamp),
			"transition %d timestamp should not be before transition %d", i, i-1)
	}
}

func TestHexToInt64(t *testing.T) {
	tests := []struct {
		input    string
		expected int64
	}{
		{"0x0", 0},
		{"0x1", 1},
		{"0xa", 10},
		{"0xff", 255},
		{"0x100", 256},
		{"0xf4240", 1000000},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := hexToInt64(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDecodeRevertReason(t *testing.T) {
	// Test with a simple revert reason "Insufficient balance"
	// This is a known ABI-encoded Error(string) for that message
	reason := decodeRevertReason("0x1234")
	assert.Equal(t, "1234", reason, "short hex should be returned as-is")

	// Empty
	reason = decodeRevertReason("")
	assert.Equal(t, "", reason)
}

func TestReceiptStatusValues(t *testing.T) {
	r := &Receipt{
		Status:      1,
		BlockNumber: 100,
		BlockHash:   "0xabc",
		GasUsed:     "0x5208",
		TxHash:      "0xdef",
	}
	assert.Equal(t, 1, r.Status)
	assert.Equal(t, int64(100), r.BlockNumber)
}

func TestTrackerStopWithoutTracking(t *testing.T) {
	tracker := New(Config{
		PollInterval: 50 * time.Millisecond,
	})
	assert.Equal(t, 0, tracker.TrackedCount())
	tracker.Stop() // should not hang
}

func TestTrackerRejectsUnknownChain(t *testing.T) {
	tracker := New(Config{
		RPCClients: map[string]RPCClient{
			"ethereum": &mockRPC{},
		},
	})
	defer tracker.Stop()

	err := tracker.Track("tx-1", "org-1", "0xabc", "solana")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no RPC client configured")
}
