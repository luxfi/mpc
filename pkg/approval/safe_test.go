package approval

import (
	"context"
	"testing"
)

func TestSafe_RoundTrip(t *testing.T) {
	provider, err := NewSafeMultisig(map[string]string{
		"chain_id":     "1",
		"safe_address": "0x1234567890abcdef1234567890abcdef12345678",
	})
	if err != nil {
		t.Fatalf("NewSafeMultisig: %v", err)
	}
	sp := provider.(*SafeMultisigProvider)
	if err := sp.Enroll("treasury-3of5", 1, "0x1234567890abcdef1234567890abcdef12345678"); err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	intent := newTestIntent("send 100 ETH to grant recipient")
	sessionID, err := sp.IssueChallenge(context.Background(), "treasury-3of5", intent)
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}

	// Simulate the on-chain execution producing safeTxHash + execTxHash.
	var safeTxHash, execTxHash [32]byte
	for i := range safeTxHash {
		safeTxHash[i] = byte(i)
		execTxHash[i] = byte(0xff - i)
	}
	sig, err := sp.SubmitExecution(context.Background(), sessionID, safeTxHash, execTxHash)
	if err != nil {
		t.Fatalf("SubmitExecution: %v", err)
	}

	if sig.Algorithm != AlgorithmSafeContract {
		t.Fatalf("Algorithm = %q, want %q", sig.Algorithm, AlgorithmSafeContract)
	}
	if len(sig.Signature) != 92 {
		t.Fatalf("Signature length = %d, want 92", len(sig.Signature))
	}

	ok, err := sp.VerifyApproval(context.Background(), intent, sig)
	if err != nil {
		t.Fatalf("VerifyApproval: %v", err)
	}
	if !ok {
		t.Fatal("VerifyApproval = false, want true")
	}

	// Tampered intent → verification fails (digest mismatch).
	other := newTestIntent("different")
	ok, _ = sp.VerifyApproval(context.Background(), other, sig)
	if ok {
		t.Fatal("VerifyApproval(tampered) = true, want false")
	}

	// Bundle with wrong chain → fail.
	tamperedSig := sig
	tamperedSig.Signature = make([]byte, 92)
	copy(tamperedSig.Signature, sig.Signature)
	tamperedSig.Signature[7] = 0xff // chainID byte
	ok, _ = sp.VerifyApproval(context.Background(), intent, tamperedSig)
	if ok {
		t.Fatal("VerifyApproval(wrong chain) = true, want false")
	}
}

func TestSafe_BadConfig(t *testing.T) {
	if _, err := NewSafeMultisig(nil); err == nil {
		t.Fatal("NewSafeMultisig(nil): want error")
	}
	if _, err := NewSafeMultisig(map[string]string{"chain_id": "1"}); err == nil {
		t.Fatal("NewSafeMultisig without safe_address: want error")
	}
	if _, err := NewSafeMultisig(map[string]string{"safe_address": "0x12"}); err == nil {
		t.Fatal("NewSafeMultisig with short address: want error")
	}
}

func TestSafe_BundleEncoding(t *testing.T) {
	addr := [20]byte{1, 2, 3, 4, 5}
	var safeTxHash, execTxHash [32]byte
	safeTxHash[0] = 0xab
	execTxHash[31] = 0xcd
	bundle := encodeSafeBundle(42, addr, safeTxHash, execTxHash)

	chainID, gotAddr, gotSafe, gotExec, err := decodeSafeBundle(bundle)
	if err != nil {
		t.Fatalf("decodeSafeBundle: %v", err)
	}
	if chainID != 42 {
		t.Fatalf("chainID = %d, want 42", chainID)
	}
	if gotAddr != addr {
		t.Fatal("addr mismatch")
	}
	if gotSafe != safeTxHash {
		t.Fatal("safeTxHash mismatch")
	}
	if gotExec != execTxHash {
		t.Fatal("execTxHash mismatch")
	}
}
