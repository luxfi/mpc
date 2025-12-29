package risk

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/luxfi/mpc/pkg/intent"
)

func ci(to string) *intent.CanonicalIntent {
	return &intent.CanonicalIntent{
		IntentVersion: intent.IntentVersion,
		SessionID:     "s1",
		WalletID:      "w1",
		WalletTier:    intent.TierWarm,
		Chain:         "eip155:1",
		To:            to,
		ExpiresAt:     time.Now().Add(time.Hour),
		PolicyID:      "p1",
	}
}

func TestInternalAllowlist_Allow(t *testing.T) {
	p := NewInternalAllowlistProvider()
	p.Allow("eip155:1", "0xabc")
	v, err := p.ScreenAddress(context.Background(), "eip155:1", "0xABC")
	if err != nil {
		t.Fatalf("screen: %v", err)
	}
	if !v.Approved {
		t.Fatalf("expected approved, got %+v", v)
	}
}

func TestInternalAllowlist_NotListed(t *testing.T) {
	p := NewInternalAllowlistProvider()
	v, _ := p.ScreenAddress(context.Background(), "eip155:1", "0xnope")
	if v.Approved {
		t.Fatalf("expected reject for unlisted addr, got %+v", v)
	}
}

func TestInternalAllowlist_DenyOverridesAllow(t *testing.T) {
	p := NewInternalAllowlistProvider()
	p.Allow("eip155:1", "0xabc")
	p.Deny("eip155:1", "0xabc")
	v, _ := p.ScreenAddress(context.Background(), "eip155:1", "0xabc")
	if v.Approved {
		t.Fatalf("deny should override allow, got %+v", v)
	}
}

func TestInternalAllowlist_ScreenTransaction(t *testing.T) {
	p := NewInternalAllowlistProvider()
	p.Allow("eip155:1", "0xrecip")
	v, _ := p.ScreenTransaction(context.Background(), ci("0xrecip"))
	if !v.Approved {
		t.Fatalf("expected approve, got %+v", v)
	}
}

func TestComposite_ModeAll_AllApprove(t *testing.T) {
	a := NewInternalAllowlistProvider()
	a.Allow("eip155:1", "0xabc")
	b := NewInternalAllowlistProvider()
	b.Allow("eip155:1", "0xabc")
	c := NewCompositeProvider(ModeAll, a, b)
	v, _ := c.ScreenAddress(context.Background(), "eip155:1", "0xabc")
	if !v.Approved {
		t.Fatalf("ModeAll: expected approve when all approve, got %+v", v)
	}
}

func TestComposite_ModeAll_OneRejects(t *testing.T) {
	a := NewInternalAllowlistProvider()
	a.Allow("eip155:1", "0xabc")
	b := NewInternalAllowlistProvider() // empty -> rejects
	c := NewCompositeProvider(ModeAll, a, b)
	v, _ := c.ScreenAddress(context.Background(), "eip155:1", "0xabc")
	if v.Approved {
		t.Fatalf("ModeAll: expected reject when one rejects, got %+v", v)
	}
}

func TestComposite_ModeAny_OneApproves(t *testing.T) {
	a := NewInternalAllowlistProvider() // empty -> rejects
	b := NewInternalAllowlistProvider()
	b.Allow("eip155:1", "0xabc")
	c := NewCompositeProvider(ModeAny, a, b)
	v, _ := c.ScreenAddress(context.Background(), "eip155:1", "0xabc")
	if !v.Approved {
		t.Fatalf("ModeAny: expected approve when any approves, got %+v", v)
	}
}

func TestComposite_ModeAny_AllReject(t *testing.T) {
	a := NewInternalAllowlistProvider()
	b := NewInternalAllowlistProvider()
	c := NewCompositeProvider(ModeAny, a, b)
	v, _ := c.ScreenAddress(context.Background(), "eip155:1", "0xabc")
	if v.Approved {
		t.Fatalf("ModeAny: expected reject when all reject, got %+v", v)
	}
}

// TestChainalysis_LowRisk — exercise the HTTP path against an httptest
// server returning a Low-risk verdict.
func TestChainalysis_LowRisk(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Token") != "test-key" {
			http.Error(w, "missing token", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"risk":"Low","riskCategory":"none","address":"0xabc"}`))
	}))
	defer srv.Close()

	p := NewChainalysisProvider(srv.URL, "test-key")
	v, err := p.ScreenAddress(context.Background(), "eip155:1", "0xabc")
	if err != nil {
		t.Fatalf("screen: %v", err)
	}
	if !v.Approved {
		t.Fatalf("Low risk should approve: %+v", v)
	}
}

func TestChainalysis_HighRisk(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"risk":"Severe","riskCategory":"sanctions","address":"0xevil"}`))
	}))
	defer srv.Close()

	p := NewChainalysisProvider(srv.URL, "test-key")
	v, err := p.ScreenAddress(context.Background(), "eip155:1", "0xevil")
	if err != nil {
		t.Fatalf("screen: %v", err)
	}
	if v.Approved {
		t.Fatalf("Severe risk must reject: %+v", v)
	}
	if v.RiskScore != 1.0 {
		t.Fatalf("expected RiskScore=1.0 for Severe, got %v", v.RiskScore)
	}
}

func TestChainalysis_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	p := NewChainalysisProvider(srv.URL, "test-key")
	if _, err := p.ScreenAddress(context.Background(), "eip155:1", "0xabc"); err == nil {
		t.Fatal("expected error on HTTP 500")
	}
}

func TestChainalysis_NoAPIKey(t *testing.T) {
	p := NewChainalysisProvider("https://example.invalid", "")
	if _, err := p.ScreenAddress(context.Background(), "eip155:1", "0xabc"); err == nil {
		t.Fatal("expected error when api key empty")
	}
}

func TestTRMElliptic_NotImplemented(t *testing.T) {
	trm := NewTRMProvider("https://api.trm.com", "k")
	if _, err := trm.ScreenAddress(context.Background(), "eip155:1", "0xabc"); err != ErrNotImplemented {
		t.Fatalf("expected ErrNotImplemented, got %v", err)
	}
	ell := NewEllipticProvider("https://api.elliptic.co", "k", "s")
	if _, err := ell.ScreenAddress(context.Background(), "eip155:1", "0xabc"); err != ErrNotImplemented {
		t.Fatalf("expected ErrNotImplemented, got %v", err)
	}
}
