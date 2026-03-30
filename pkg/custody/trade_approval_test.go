package custody

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"

	"github.com/luxfi/mpc/pkg/db"
)

// testDB creates a temporary SQLite-backed ORM for testing.
func testDB(t *testing.T) orm.DB {
	t.Helper()
	o, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(t.TempDir(), "test.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { o.Close() })
	return o
}

// Ensure db package init() functions run (registers models).
var _ = db.PendingTrade{}

// mockNotifier records push notifications for assertions.
type mockNotifier struct {
	approvalCount     atomic.Int64
	confirmationCount atomic.Int64
	lastApproval      TradeApprovalNotification
	lastConfirmation  TradeConfirmationNotification
	shouldFail        bool
}

func (m *mockNotifier) SendTradeApproval(_ context.Context, req TradeApprovalNotification) error {
	m.approvalCount.Add(1)
	m.lastApproval = req
	if m.shouldFail {
		return errors.New("push failed")
	}
	return nil
}

func (m *mockNotifier) SendTradeConfirmation(_ context.Context, req TradeConfirmationNotification) error {
	m.confirmationCount.Add(1)
	m.lastConfirmation = req
	if m.shouldFail {
		return errors.New("push failed")
	}
	return nil
}

func TestSubmitForApproval_Success(t *testing.T) {
	o := testDB(t)
	notifier := &mockNotifier{}
	svc := NewTradeApprovalService(o, notifier)

	trade := db.PendingTrade{
		OrgID:       "org-1",
		UserID:      "user-1",
		WalletID:    "wallet-1",
		Symbol:      "AAPL",
		Side:        "buy",
		Quantity:    "10",
		Price:       "150.00",
		TotalValue:  "1500.00",
		MessageHash: "abcdef1234567890",
	}

	result, err := svc.SubmitForApproval(context.Background(), trade)
	if err != nil {
		t.Fatalf("SubmitForApproval failed: %v", err)
	}

	if result.Status != "pending_approval" {
		t.Errorf("expected status pending_approval, got %s", result.Status)
	}
	if result.Id() == "" {
		t.Error("expected non-empty trade ID")
	}
	if result.ExpiresAt.Before(time.Now()) {
		t.Error("expected expiry in the future")
	}
	if result.Symbol != "AAPL" {
		t.Errorf("expected symbol AAPL, got %s", result.Symbol)
	}
	if len(result.StatusHistory) == 0 {
		t.Error("expected status history entry")
	}
}

func TestSubmitForApproval_MissingFields(t *testing.T) {
	o := testDB(t)
	svc := NewTradeApprovalService(o, nil)

	tests := []struct {
		name  string
		trade db.PendingTrade
	}{
		{"missing org_id", db.PendingTrade{UserID: "u", WalletID: "w", Symbol: "X", Side: "buy", MessageHash: "h"}},
		{"missing user_id", db.PendingTrade{OrgID: "o", WalletID: "w", Symbol: "X", Side: "buy", MessageHash: "h"}},
		{"missing wallet_id", db.PendingTrade{OrgID: "o", UserID: "u", Symbol: "X", Side: "buy", MessageHash: "h"}},
		{"missing symbol", db.PendingTrade{OrgID: "o", UserID: "u", WalletID: "w", Side: "buy", MessageHash: "h"}},
		{"missing side", db.PendingTrade{OrgID: "o", UserID: "u", WalletID: "w", Symbol: "X", MessageHash: "h"}},
		{"missing message_hash", db.PendingTrade{OrgID: "o", UserID: "u", WalletID: "w", Symbol: "X", Side: "buy"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.SubmitForApproval(context.Background(), tc.trade)
			if err == nil {
				t.Error("expected error for missing fields")
			}
		})
	}
}

func TestApproveWithBiometric_Success(t *testing.T) {
	o := testDB(t)
	svc := NewTradeApprovalService(o, nil)

	trade := db.PendingTrade{
		OrgID:       "org-1",
		UserID:      "user-1",
		WalletID:    "wallet-1",
		Symbol:      "MSFT",
		Side:        "sell",
		Quantity:    "5",
		Price:       "400.00",
		TotalValue:  "2000.00",
		MessageHash: "deadbeef",
	}
	result, err := svc.SubmitForApproval(context.Background(), trade)
	if err != nil {
		t.Fatalf("SubmitForApproval failed: %v", err)
	}

	approved, err := svc.ApproveWithBiometric(context.Background(), result.Id(), "org-1", "user-1")
	if err != nil {
		t.Fatalf("ApproveWithBiometric failed: %v", err)
	}
	if approved.Status != "approved" {
		t.Errorf("expected status approved, got %s", approved.Status)
	}
	if approved.ApprovedAt == nil {
		t.Error("expected ApprovedAt to be set")
	}
}

func TestApproveWithBiometric_WrongUser(t *testing.T) {
	o := testDB(t)
	svc := NewTradeApprovalService(o, nil)

	trade := db.PendingTrade{
		OrgID: "org-1", UserID: "user-1", WalletID: "wallet-1",
		Symbol: "TSLA", Side: "buy", Quantity: "1", Price: "200.00",
		TotalValue: "200.00", MessageHash: "cafebabe",
	}
	result, _ := svc.SubmitForApproval(context.Background(), trade)

	_, err := svc.ApproveWithBiometric(context.Background(), result.Id(), "org-1", "user-2")
	if err == nil {
		t.Error("expected error when wrong user approves")
	}
}

func TestApproveWithBiometric_WrongOrg(t *testing.T) {
	o := testDB(t)
	svc := NewTradeApprovalService(o, nil)

	trade := db.PendingTrade{
		OrgID: "org-1", UserID: "user-1", WalletID: "wallet-1",
		Symbol: "NVDA", Side: "buy", Quantity: "3", Price: "800.00",
		TotalValue: "2400.00", MessageHash: "f00d",
	}
	result, _ := svc.SubmitForApproval(context.Background(), trade)

	_, err := svc.ApproveWithBiometric(context.Background(), result.Id(), "org-2", "user-1")
	if err == nil {
		t.Error("expected error when wrong org approves")
	}
}

func TestApproveWithBiometric_DoubleApprove(t *testing.T) {
	o := testDB(t)
	svc := NewTradeApprovalService(o, nil)

	trade := db.PendingTrade{
		OrgID: "org-1", UserID: "user-1", WalletID: "wallet-1",
		Symbol: "ETH", Side: "buy", Quantity: "1", Price: "3000.00",
		TotalValue: "3000.00", MessageHash: "aabb",
	}
	result, _ := svc.SubmitForApproval(context.Background(), trade)
	svc.ApproveWithBiometric(context.Background(), result.Id(), "org-1", "user-1")

	_, err := svc.ApproveWithBiometric(context.Background(), result.Id(), "org-1", "user-1")
	if err == nil {
		t.Error("expected error on double approve")
	}
}

func TestRejectTrade_Success(t *testing.T) {
	o := testDB(t)
	svc := NewTradeApprovalService(o, nil)

	trade := db.PendingTrade{
		OrgID: "org-1", UserID: "user-1", WalletID: "wallet-1",
		Symbol: "BTC", Side: "sell", Quantity: "0.5", Price: "60000.00",
		TotalValue: "30000.00", MessageHash: "ccdd",
	}
	result, _ := svc.SubmitForApproval(context.Background(), trade)

	err := svc.RejectTrade(context.Background(), result.Id(), "org-1", "user-1", "changed my mind")
	if err != nil {
		t.Fatalf("RejectTrade failed: %v", err)
	}

	rejected, _ := orm.Get[db.PendingTrade](o, result.Id())
	if rejected.Status != "rejected" {
		t.Errorf("expected status rejected, got %s", rejected.Status)
	}
	if rejected.Reason == nil || *rejected.Reason != "changed my mind" {
		t.Error("expected rejection reason")
	}
}

func TestRejectTrade_WrongUser(t *testing.T) {
	o := testDB(t)
	svc := NewTradeApprovalService(o, nil)

	trade := db.PendingTrade{
		OrgID: "org-1", UserID: "user-1", WalletID: "wallet-1",
		Symbol: "SOL", Side: "buy", Quantity: "10", Price: "100.00",
		TotalValue: "1000.00", MessageHash: "eeff",
	}
	result, _ := svc.SubmitForApproval(context.Background(), trade)

	err := svc.RejectTrade(context.Background(), result.Id(), "org-1", "user-2", "nope")
	if err == nil {
		t.Error("expected error when wrong user rejects")
	}
}

func TestGetPendingTrades(t *testing.T) {
	o := testDB(t)
	svc := NewTradeApprovalService(o, nil)

	for _, sym := range []string{"AAPL", "MSFT", "GOOG"} {
		svc.SubmitForApproval(context.Background(), db.PendingTrade{
			OrgID: "org-1", UserID: "user-1", WalletID: "wallet-1",
			Symbol: sym, Side: "buy", Quantity: "1", Price: "100.00",
			TotalValue: "100.00", MessageHash: "hash-" + sym,
		})
	}

	trades, err := svc.GetPendingTrades(context.Background(), "wallet-1", "org-1")
	if err != nil {
		t.Fatalf("GetPendingTrades failed: %v", err)
	}
	if len(trades) != 3 {
		t.Errorf("expected 3 pending trades, got %d", len(trades))
	}
}

func TestGetPendingTrades_EmptyWallet(t *testing.T) {
	o := testDB(t)
	svc := NewTradeApprovalService(o, nil)

	trades, err := svc.GetPendingTrades(context.Background(), "nonexistent", "org-1")
	if err != nil {
		t.Fatalf("GetPendingTrades failed: %v", err)
	}
	if len(trades) != 0 {
		t.Errorf("expected 0 trades, got %d", len(trades))
	}
}

func TestCleanupExpired(t *testing.T) {
	o := testDB(t)
	svc := NewTradeApprovalService(o, nil)

	result, _ := svc.SubmitForApproval(context.Background(), db.PendingTrade{
		OrgID: "org-1", UserID: "user-1", WalletID: "wallet-1",
		Symbol: "AAPL", Side: "buy", Quantity: "1", Price: "150.00",
		TotalValue: "150.00", MessageHash: "hash1",
	})

	// Backdate the expiry
	result.ExpiresAt = time.Now().Add(-1 * time.Minute)
	result.Update()

	count, err := svc.CleanupExpired(context.Background())
	if err != nil {
		t.Fatalf("CleanupExpired failed: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 expired trade, got %d", count)
	}

	trade, _ := orm.Get[db.PendingTrade](o, result.Id())
	if trade.Status != "expired" {
		t.Errorf("expected status expired, got %s", trade.Status)
	}
}

func TestMarkSigned(t *testing.T) {
	o := testDB(t)
	svc := NewTradeApprovalService(o, nil)

	trade := db.PendingTrade{
		OrgID: "org-1", UserID: "user-1", WalletID: "wallet-1",
		Symbol: "ETH", Side: "buy", Quantity: "2", Price: "3000.00",
		TotalValue: "6000.00", MessageHash: "hash-eth",
	}
	result, _ := svc.SubmitForApproval(context.Background(), trade)
	svc.ApproveWithBiometric(context.Background(), result.Id(), "org-1", "user-1")

	err := svc.MarkSigned(context.Background(), result.Id(), "intent-123")
	if err != nil {
		t.Fatalf("MarkSigned failed: %v", err)
	}

	signed, _ := orm.Get[db.PendingTrade](o, result.Id())
	if signed.Status != "signed" {
		t.Errorf("expected status signed, got %s", signed.Status)
	}
	if signed.IntentID == nil || *signed.IntentID != "intent-123" {
		t.Error("expected intent_id to be set")
	}
}

func TestMarkSigned_NotApproved(t *testing.T) {
	o := testDB(t)
	svc := NewTradeApprovalService(o, nil)

	result, _ := svc.SubmitForApproval(context.Background(), db.PendingTrade{
		OrgID: "org-1", UserID: "user-1", WalletID: "wallet-1",
		Symbol: "BTC", Side: "buy", Quantity: "1", Price: "60000.00",
		TotalValue: "60000.00", MessageHash: "h",
	})

	err := svc.MarkSigned(context.Background(), result.Id(), "intent-bad")
	if err == nil {
		t.Error("expected error when marking non-approved trade as signed")
	}
}

func TestMarkSettled(t *testing.T) {
	o := testDB(t)
	notifier := &mockNotifier{}
	svc := NewTradeApprovalService(o, notifier)

	trade := db.PendingTrade{
		OrgID: "org-1", UserID: "user-1", WalletID: "wallet-1",
		Symbol: "BTC", Side: "sell", Quantity: "1", Price: "60000.00",
		TotalValue: "60000.00", MessageHash: "hash-btc",
	}
	result, _ := svc.SubmitForApproval(context.Background(), trade)
	svc.ApproveWithBiometric(context.Background(), result.Id(), "org-1", "user-1")
	svc.MarkSigned(context.Background(), result.Id(), "intent-456")

	err := svc.MarkSettled(context.Background(), result.Id(), "0xdeadbeef")
	if err != nil {
		t.Fatalf("MarkSettled failed: %v", err)
	}

	settled, _ := orm.Get[db.PendingTrade](o, result.Id())
	if settled.Status != "settled" {
		t.Errorf("expected status settled, got %s", settled.Status)
	}
	if settled.TxHash == nil || *settled.TxHash != "0xdeadbeef" {
		t.Error("expected tx_hash to be set")
	}
}

func TestSubmitForApproval_PushFailure_NonFatal(t *testing.T) {
	o := testDB(t)
	notifier := &mockNotifier{shouldFail: true}
	svc := NewTradeApprovalService(o, notifier)

	trade := db.PendingTrade{
		OrgID: "org-1", UserID: "user-1", WalletID: "wallet-1",
		DeviceID: "device-1", Symbol: "AAPL", Side: "buy",
		Quantity: "1", Price: "150.00", TotalValue: "150.00",
		MessageHash: "hash-push-fail",
	}
	result, err := svc.SubmitForApproval(context.Background(), trade)
	if err != nil {
		t.Fatalf("SubmitForApproval should succeed even when push fails: %v", err)
	}
	if result.Status != "pending_approval" {
		t.Errorf("expected pending_approval, got %s", result.Status)
	}
}

func TestApproveWithBiometric_Expired(t *testing.T) {
	o := testDB(t)
	svc := NewTradeApprovalService(o, nil)

	result, _ := svc.SubmitForApproval(context.Background(), db.PendingTrade{
		OrgID: "org-1", UserID: "user-1", WalletID: "wallet-1",
		Symbol: "AAPL", Side: "buy", Quantity: "1", Price: "150.00",
		TotalValue: "150.00", MessageHash: "expired-hash",
	})

	// Backdate the expiry
	result.ExpiresAt = time.Now().Add(-1 * time.Second)
	result.Update()

	_, err := svc.ApproveWithBiometric(context.Background(), result.Id(), "org-1", "user-1")
	if err == nil {
		t.Error("expected error for expired trade")
	}

	// Verify it was marked as expired
	expired, _ := orm.Get[db.PendingTrade](o, result.Id())
	if expired.Status != "expired" {
		t.Errorf("expected status expired, got %s", expired.Status)
	}
}

func TestRejectTrade_AlreadyApproved(t *testing.T) {
	o := testDB(t)
	svc := NewTradeApprovalService(o, nil)

	result, _ := svc.SubmitForApproval(context.Background(), db.PendingTrade{
		OrgID: "org-1", UserID: "user-1", WalletID: "wallet-1",
		Symbol: "AAPL", Side: "buy", Quantity: "1", Price: "150.00",
		TotalValue: "150.00", MessageHash: "already-approved",
	})

	svc.ApproveWithBiometric(context.Background(), result.Id(), "org-1", "user-1")

	err := svc.RejectTrade(context.Background(), result.Id(), "org-1", "user-1", "too late")
	if err == nil {
		t.Error("expected error when rejecting already-approved trade")
	}
}
