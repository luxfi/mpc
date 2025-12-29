package approval

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeLedgerVault simulates a Ledger Enterprise REST endpoint.
type fakeLedgerVault struct {
	priv *ecdsa.PrivateKey

	mu      sync.Mutex
	digests map[string]string // accountID -> base64 digest from create call
}

func (v *fakeLedgerVault) handler(t *testing.T) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/accounts/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/accounts/")
		segments := strings.Split(path, "/")
		switch {
		case len(segments) == 2 && segments[1] == "transactions" && r.Method == http.MethodPost:
			var req leTransactionRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			r.Body.Close()
			v.mu.Lock()
			v.digests[segments[0]] = req.Digest
			v.mu.Unlock()
			writeFakeJSON(w, leTransactionResponse{TxID: "tx-1", Status: "pending"})
		case len(segments) == 4 && segments[1] == "transactions" && segments[3] == "approve" && r.Method == http.MethodPost:
			writeFakeJSON(w, leTransactionResponse{TxID: segments[2], Status: "pending"})
		case len(segments) == 3 && segments[1] == "transactions" && r.Method == http.MethodGet:
			v.mu.Lock()
			digestB64 := v.digests[segments[0]]
			v.mu.Unlock()
			rawDigest, _ := base64.StdEncoding.DecodeString(digestB64)
			h := sha256.Sum256(rawDigest)
			r2, s2, err := ecdsa.Sign(rand.Reader, v.priv, h[:])
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			rb := r2.Bytes()
			sb := s2.Bytes()
			raw := make([]byte, 64)
			copy(raw[32-len(rb):32], rb)
			copy(raw[64-len(sb):], sb)
			der, _ := ecdsaRawToASN1(raw)
			writeFakeJSON(w, leTransactionResponse{TxID: segments[2], Status: "approved", Sig: base64.StdEncoding.EncodeToString(der)})
		default:
			http.Error(w, "not found: "+r.Method+" "+r.URL.Path, http.StatusNotFound)
		}
	})
	return mux
}

func writeFakeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func TestLedgerEnterprise_ApproveAndVerify(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	v := &fakeLedgerVault{priv: priv, digests: map[string]string{}}
	srv := httptest.NewServer(v.handler(t))
	defer srv.Close()

	provider, err := NewLedgerEnterprise(map[string]string{
		"endpoint":         srv.URL,
		"api_key":          "test-key",
		"workspace":        "ws-1",
		"approval_timeout": "5s",
	})
	if err != nil {
		t.Fatalf("NewLedgerEnterprise: %v", err)
	}
	le := provider.(*LedgerEnterpriseProvider)
	le.pollEvery = 50 * time.Millisecond

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := le.Enroll("ceo@fund.com", "acct-1", AlgorithmECDSAP256, pubDER); err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	intent := newTestIntent("transfer cold custody to warm")
	sig, err := le.ApproveIntent(context.Background(), "ceo@fund.com", intent)
	if err != nil {
		t.Fatalf("ApproveIntent: %v", err)
	}
	if sig.Algorithm != AlgorithmECDSAP256 {
		t.Fatalf("Algorithm = %q, want %q", sig.Algorithm, AlgorithmECDSAP256)
	}

	ok, err := le.VerifyApproval(context.Background(), intent, sig)
	if err != nil {
		t.Fatalf("VerifyApproval: %v", err)
	}
	if !ok {
		t.Fatal("VerifyApproval = false, want true")
	}
}

func TestLedgerEnterprise_BadConfig(t *testing.T) {
	if _, err := NewLedgerEnterprise(nil); err == nil {
		t.Fatal("NewLedgerEnterprise(nil): want error")
	}
	if _, err := NewLedgerEnterprise(map[string]string{
		"endpoint": "https://example.com",
	}); err == nil {
		t.Fatal("missing api_key + workspace: want error")
	}
}
