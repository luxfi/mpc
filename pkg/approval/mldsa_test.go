package approval

import (
	"context"
	"testing"
)

func TestMLDSA_ApproveAndVerify(t *testing.T) {
	provider, err := NewMLDSA(nil)
	if err != nil {
		t.Fatalf("NewMLDSA: %v", err)
	}
	mp := provider.(*MLDSAProvider)
	if err := mp.Enroll("ceo@fund.com", nil); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	id, err := mp.GetPublicIdentity(context.Background(), "ceo@fund.com")
	if err != nil {
		t.Fatalf("GetPublicIdentity: %v", err)
	}
	if id.Algorithm != AlgorithmMLDSA65 {
		t.Fatalf("Algorithm = %q, want %q", id.Algorithm, AlgorithmMLDSA65)
	}
	if len(id.PublicKey) == 0 {
		t.Fatal("empty PublicKey")
	}

	intent := newTestIntent("treasury allocation Q2-2026")
	sig, err := mp.ApproveIntent(context.Background(), "ceo@fund.com", intent)
	if err != nil {
		t.Fatalf("ApproveIntent: %v", err)
	}
	if sig.Algorithm != AlgorithmMLDSA65 {
		t.Fatalf("Algorithm = %q, want %q", sig.Algorithm, AlgorithmMLDSA65)
	}

	ok, err := mp.VerifyApproval(context.Background(), intent, sig)
	if err != nil {
		t.Fatalf("VerifyApproval: %v", err)
	}
	if !ok {
		t.Fatal("VerifyApproval = false, want true")
	}

	// Tampered intent → verification fails.
	other := newTestIntent("different intent")
	ok, _ = mp.VerifyApproval(context.Background(), other, sig)
	if ok {
		t.Fatal("VerifyApproval(tampered) = true, want false")
	}
}

func TestMLDSA_UnenrolledApprover(t *testing.T) {
	provider, err := NewMLDSA(nil)
	if err != nil {
		t.Fatalf("NewMLDSA: %v", err)
	}
	intent := newTestIntent("foo")
	if _, err := provider.ApproveIntent(context.Background(), "nobody", intent); err == nil {
		t.Fatal("ApproveIntent for unenrolled approver: want error")
	}
}
