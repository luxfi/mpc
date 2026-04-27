package approval

import (
	"context"
	"errors"
	"testing"
)

// TestLedgerDevice_NotImplemented documents the explicit NOTIMPL contract:
// every method must return a documented error, never silently succeed.
func TestLedgerDevice_NotImplemented(t *testing.T) {
	provider, err := NewLedgerDevice(map[string]string{"bip32_path": "m/44'/9000'/0'/0/0"})
	if err != nil {
		t.Fatalf("NewLedgerDevice: %v", err)
	}
	if provider.Provider() != "ledger-device" {
		t.Fatalf("Provider() = %q, want ledger-device", provider.Provider())
	}

	_, err = provider.GetPublicIdentity(context.Background(), "ceo@fund.com")
	if err == nil {
		t.Fatal("GetPublicIdentity: want NOTIMPL error, got nil")
	}
	if !errors.Is(err, ErrNotImplemented()) {
		t.Fatalf("GetPublicIdentity error %v, want ErrNotImplemented", err)
	}

	intent := newTestIntent("any")
	_, err = provider.ApproveIntent(context.Background(), "ceo@fund.com", intent)
	if err == nil {
		t.Fatal("ApproveIntent: want NOTIMPL error, got nil")
	}
	if !errors.Is(err, ErrNotImplemented()) {
		t.Fatalf("ApproveIntent error %v, want ErrNotImplemented", err)
	}

	// VerifyApproval refuses to accept anything (defense in depth).
	ok, err := provider.VerifyApproval(context.Background(), intent, ApprovalSignature{Provider: "ledger-device"})
	if err == nil {
		t.Fatal("VerifyApproval: want error, got nil")
	}
	if ok {
		t.Fatal("VerifyApproval returned ok=true while not implemented")
	}
}
