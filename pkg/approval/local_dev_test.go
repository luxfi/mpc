package approval

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"strings"
	"testing"
)

// withDevEnv ensures local-dev provider is permitted during this test.
// Restores prior env on cleanup.
func withDevEnv(t *testing.T) {
	t.Helper()
	prevEnv := os.Getenv("MPC_ENV")
	prevFlag := os.Getenv("MPC_LOCAL_APPROVAL")
	t.Cleanup(func() {
		os.Setenv("MPC_ENV", prevEnv)
		os.Setenv("MPC_LOCAL_APPROVAL", prevFlag)
	})
	os.Setenv("MPC_ENV", "test")
	os.Setenv("MPC_LOCAL_APPROVAL", "true")
}

func TestLocalDev_ProviderName(t *testing.T) {
	withDevEnv(t)
	p, err := NewLocalDev(nil)
	if err != nil {
		t.Fatalf("NewLocalDev: %v", err)
	}
	if got, want := p.Provider(), "local-dev"; got != want {
		t.Fatalf("Provider() = %q, want %q", got, want)
	}
}

func TestLocalDev_Identity_Roundtrip(t *testing.T) {
	withDevEnv(t)
	p, err := NewLocalDev(nil)
	if err != nil {
		t.Fatalf("NewLocalDev: %v", err)
	}
	id, err := p.GetPublicIdentity(context.Background(), "alice")
	if err != nil {
		t.Fatalf("GetPublicIdentity: %v", err)
	}
	if id.ApproverID != "alice" {
		t.Fatalf("ApproverID = %q, want alice", id.ApproverID)
	}
	if id.Algorithm != AlgorithmEd25519 {
		t.Fatalf("Algorithm = %q, want %q", id.Algorithm, AlgorithmEd25519)
	}
	if len(id.PublicKey) != ed25519.PublicKeySize {
		t.Fatalf("public key size = %d, want %d", len(id.PublicKey), ed25519.PublicKeySize)
	}
}

func TestLocalDev_ApproveAndVerify(t *testing.T) {
	withDevEnv(t)
	p, err := NewLocalDev(nil)
	if err != nil {
		t.Fatalf("NewLocalDev: %v", err)
	}
	intent := newTestIntent("transfer 10 LUX to alice")
	sig, err := p.ApproveIntent(context.Background(), "alice", intent)
	if err != nil {
		t.Fatalf("ApproveIntent: %v", err)
	}
	if sig.ApproverID != "alice" {
		t.Fatalf("ApproverID = %q, want alice", sig.ApproverID)
	}
	if sig.IntentDigest != intent.Digest() {
		t.Fatal("IntentDigest mismatch")
	}
	if sig.Provider != "local-dev" {
		t.Fatalf("Provider = %q, want local-dev", sig.Provider)
	}
	if sig.Algorithm != AlgorithmEd25519 {
		t.Fatalf("Algorithm = %q, want %q", sig.Algorithm, AlgorithmEd25519)
	}

	ok, err := p.VerifyApproval(context.Background(), intent, sig)
	if err != nil {
		t.Fatalf("VerifyApproval: %v", err)
	}
	if !ok {
		t.Fatal("VerifyApproval = false, want true")
	}

	// Tamper with the intent — verification must fail.
	tampered := newTestIntent("transfer 1000000 LUX to attacker")
	ok, err = p.VerifyApproval(context.Background(), tampered, sig)
	if err != nil {
		t.Fatalf("VerifyApproval (tampered): %v", err)
	}
	if ok {
		t.Fatal("VerifyApproval(tampered) = true, want false")
	}
}

func TestLocalDev_RefusesProduction(t *testing.T) {
	prevEnv := os.Getenv("MPC_ENV")
	prevFlag := os.Getenv("MPC_LOCAL_APPROVAL")
	t.Cleanup(func() {
		os.Setenv("MPC_ENV", prevEnv)
		os.Setenv("MPC_LOCAL_APPROVAL", prevFlag)
	})
	os.Setenv("MPC_ENV", "production")
	os.Setenv("MPC_LOCAL_APPROVAL", "")

	if _, err := NewProvider("local-dev", nil); err == nil {
		t.Fatal("NewProvider(local-dev) in production: want error, got nil")
	} else if !strings.Contains(err.Error(), "forbidden in production") {
		t.Fatalf("error %q does not mention forbidden in production", err)
	}
}

func TestLocalDev_Enroll_DeterministicKey(t *testing.T) {
	withDevEnv(t)
	provider, err := NewLocalDev(nil)
	if err != nil {
		t.Fatalf("NewLocalDev: %v", err)
	}
	dev := provider.(*LocalDevProvider)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dev.Enroll("alice", priv)
	id, err := dev.GetPublicIdentity(context.Background(), "alice")
	if err != nil {
		t.Fatalf("GetPublicIdentity: %v", err)
	}
	if string(id.PublicKey) != string(pub) {
		t.Fatal("enrolled public key did not round-trip")
	}
}

func TestLocalDev_CrossProviderIsolation(t *testing.T) {
	// A signature claiming provider=mldsa must NOT verify against local-dev.
	withDevEnv(t)
	p, err := NewLocalDev(nil)
	if err != nil {
		t.Fatalf("NewLocalDev: %v", err)
	}
	intent := newTestIntent("cross-provider check")
	sig, err := p.ApproveIntent(context.Background(), "alice", intent)
	if err != nil {
		t.Fatal(err)
	}
	// Mutate provider claim
	sig.Provider = "mldsa"
	ok, err := p.VerifyApproval(context.Background(), intent, sig)
	if err != nil {
		t.Fatalf("VerifyApproval: %v", err)
	}
	if ok {
		t.Fatal("VerifyApproval accepted signature with wrong provider claim")
	}
}
