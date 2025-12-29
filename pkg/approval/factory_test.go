package approval

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"strings"
	"testing"
)

func TestFactory_AllProviders(t *testing.T) {
	prevEnv := os.Getenv("MPC_ENV")
	prevFlag := os.Getenv("MPC_LOCAL_APPROVAL")
	t.Cleanup(func() {
		os.Setenv("MPC_ENV", prevEnv)
		os.Setenv("MPC_LOCAL_APPROVAL", prevFlag)
	})
	os.Setenv("MPC_ENV", "test")
	os.Setenv("MPC_LOCAL_APPROVAL", "true")

	cases := []struct {
		name      string
		ptype     string
		config    map[string]string
		wantError bool
	}{
		{"local-dev", "local-dev", nil, false},
		{"mldsa", "mldsa", nil, false},
		{"safe", "safe-multisig", map[string]string{
			"chain_id": "1", "safe_address": "0x1234567890abcdef1234567890abcdef12345678",
		}, false},
		{"webauthn", "webauthn", map[string]string{
			"rpid":    "lux.network",
			"origins": "https://approvals.lux.network",
		}, false},
		{"ledger-enterprise", "ledger-enterprise", map[string]string{
			"endpoint": "https://vault.example.com", "api_key": "k", "workspace": "w",
		}, false},
		{"ledger-device", "ledger-device", nil, false},
		{"aws-kms", "aws-kms", map[string]string{"region": "us-east-1"}, false},
		{"gcp-kms", "gcp-kms", nil, false},
		{"azure-keyvault", "azure-keyvault", map[string]string{"vault_url": "https://x.vault.azure.net"}, false},
		{"zymbit", "zymbit", map[string]string{"api_addr": "http://localhost:6789"}, false},
		// yubihsm is supported in luxfi/hsm head but not yet in v1.1.2 — the
		// factory wraps the published version's NewSigner which rejects it.
		// Once luxfi/hsm publishes a yubihsm-capable v1.x tag, flip wantError
		// back to false and the existing provider code starts working.
		{"yubihsm", "yubihsm", map[string]string{}, true},
		{"unknown", "fake", nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := NewProvider(tc.ptype, tc.config)
			if tc.wantError {
				if err == nil {
					t.Fatal("want error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("NewProvider(%q): %v", tc.ptype, err)
			}
			if p == nil {
				t.Fatal("NewProvider returned nil provider with no error")
			}
			if p.Provider() == "" {
				t.Fatal("provider name is empty")
			}
		})
	}
}

func TestFactory_LocalDevForbiddenInProduction(t *testing.T) {
	prevEnv := os.Getenv("MPC_ENV")
	t.Cleanup(func() { os.Setenv("MPC_ENV", prevEnv) })
	os.Setenv("MPC_ENV", "production")

	if _, err := NewProvider("local-dev", nil); err == nil {
		t.Fatal("NewProvider(local-dev) in production: want error")
	} else if !strings.Contains(err.Error(), "forbidden in production") {
		t.Fatalf("error %q does not contain 'forbidden in production'", err)
	}
}

func TestCrossProvider_ApprovalDoesNotVerify(t *testing.T) {
	prevEnv := os.Getenv("MPC_ENV")
	prevFlag := os.Getenv("MPC_LOCAL_APPROVAL")
	t.Cleanup(func() {
		os.Setenv("MPC_ENV", prevEnv)
		os.Setenv("MPC_LOCAL_APPROVAL", prevFlag)
	})
	os.Setenv("MPC_ENV", "test")
	os.Setenv("MPC_LOCAL_APPROVAL", "true")

	dev, err := NewLocalDev(nil)
	if err != nil {
		t.Fatal(err)
	}
	mldsa, err := NewMLDSA(nil)
	if err != nil {
		t.Fatal(err)
	}
	pq := mldsa.(*MLDSAProvider)
	if err := pq.Enroll("alice", nil); err != nil {
		t.Fatal(err)
	}

	// Pre-seed local-dev with its own key for alice.
	_, sk, _ := ed25519.GenerateKey(rand.Reader)
	dev.(*LocalDevProvider).Enroll("alice", sk)

	intent := newTestIntent("cross-provider attack")
	devSig, err := dev.ApproveIntent(context.Background(), "alice", intent)
	if err != nil {
		t.Fatal(err)
	}

	// dev-signed approval must NOT verify against mldsa provider.
	ok, _ := mldsa.VerifyApproval(context.Background(), intent, devSig)
	if ok {
		t.Fatal("MLDSA verified a local-dev signature — provider boundary leak")
	}

	// Provider-name spoofing: claim the signature is from mldsa.
	spoofed := devSig
	spoofed.Provider = "mldsa"
	spoofed.Algorithm = AlgorithmMLDSA65
	ok, _ = mldsa.VerifyApproval(context.Background(), intent, spoofed)
	if ok {
		t.Fatal("MLDSA verified a spoofed local-dev signature — algorithm/key not checked")
	}
}
