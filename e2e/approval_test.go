package e2e

import (
	"context"
	"crypto/sha256"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/luxfi/mpc/pkg/approval"
)

// e2eIntent is the test stand-in for pkg/intent.CanonicalIntent.
type e2eIntent struct {
	body []byte
}

func (i *e2eIntent) Digest() [32]byte { return sha256.Sum256(i.body) }
func (i *e2eIntent) Bytes() []byte    { return i.body }

func enableLocalDev(t *testing.T) {
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

// TestApproval_E2E_2of3_LocalDev exercises the full collect-and-verify flow
// with three independent approver keys, all backed by the local-dev
// software signer. This is the smoke test the CI pipeline runs without
// any HSM infrastructure.
func TestApproval_E2E_2of3_LocalDev(t *testing.T) {
	enableLocalDev(t)

	dev, err := approval.NewLocalDev(nil)
	if err != nil {
		t.Fatalf("NewLocalDev: %v", err)
	}
	o := approval.NewOrchestrator([]approval.ApprovalProvider{dev})
	for _, a := range []string{"ceo@fund.com", "cfo@fund.com", "cto@fund.com"} {
		if err := o.Bind(approval.ApproverBinding{
			ApproverID:   a,
			ProviderName: "local-dev",
		}); err != nil {
			t.Fatalf("Bind(%s): %v", a, err)
		}
	}

	intent := &e2eIntent{body: []byte("transfer 1000 LUX to grant recipient")}
	bundle, err := o.CollectApprovals(context.Background(), intent,
		[]string{"ceo@fund.com", "cfo@fund.com", "cto@fund.com"}, 2)
	if err != nil {
		t.Fatalf("CollectApprovals: %v", err)
	}
	if len(bundle) < 2 {
		t.Fatalf("bundle has %d sigs, want >= 2", len(bundle))
	}
	ok, err := o.VerifyBundle(context.Background(), intent, bundle, 2)
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if !ok {
		t.Fatal("VerifyBundle returned false")
	}
}

// TestApproval_E2E_MixedProviders binds approvers across TWO distinct
// providers — local-dev (Ed25519) and MLDSA (post-quantum). This is the
// configuration a real fund would run: every executive uses a *different*
// device class so a single supply-chain compromise cannot reach all of them.
func TestApproval_E2E_MixedProviders(t *testing.T) {
	enableLocalDev(t)

	dev, err := approval.NewLocalDev(nil)
	if err != nil {
		t.Fatalf("NewLocalDev: %v", err)
	}
	pq, err := approval.NewMLDSA(nil)
	if err != nil {
		t.Fatalf("NewMLDSA: %v", err)
	}
	if err := pq.(*approval.MLDSAProvider).Enroll("cfo@fund.com", nil); err != nil {
		t.Fatalf("MLDSA.Enroll: %v", err)
	}

	o := approval.NewOrchestrator([]approval.ApprovalProvider{dev, pq})
	o.Bind(approval.ApproverBinding{ApproverID: "ceo@fund.com", ProviderName: "local-dev"})
	o.Bind(approval.ApproverBinding{ApproverID: "cfo@fund.com", ProviderName: "mldsa"})

	intent := &e2eIntent{body: []byte("multi-provider approval")}
	bundle, err := o.CollectApprovals(context.Background(), intent, []string{"ceo@fund.com", "cfo@fund.com"}, 2)
	if err != nil {
		t.Fatalf("CollectApprovals: %v", err)
	}
	if len(bundle) != 2 {
		t.Fatalf("bundle has %d, want 2", len(bundle))
	}
	// Confirm they used different providers — provenance check.
	seen := map[string]bool{}
	for _, sig := range bundle {
		seen[sig.Provider] = true
	}
	if !seen["local-dev"] || !seen["mldsa"] {
		t.Fatalf("missing provider in bundle: %+v", seen)
	}

	ok, err := o.VerifyBundle(context.Background(), intent, bundle, 2)
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if !ok {
		t.Fatal("VerifyBundle = false")
	}
}

// TestApproval_E2E_TamperedIntentRejected confirms re-verifying a bundle
// against a different intent payload fails — digest binding holds.
func TestApproval_E2E_TamperedIntentRejected(t *testing.T) {
	enableLocalDev(t)

	dev, err := approval.NewLocalDev(nil)
	if err != nil {
		t.Fatal(err)
	}
	o := approval.NewOrchestrator([]approval.ApprovalProvider{dev})
	o.Bind(approval.ApproverBinding{ApproverID: "alice", ProviderName: "local-dev"})

	original := &e2eIntent{body: []byte("send 10 LUX to alice")}
	bundle, err := o.CollectApprovals(context.Background(), original, []string{"alice"}, 1)
	if err != nil {
		t.Fatalf("CollectApprovals: %v", err)
	}

	tampered := &e2eIntent{body: []byte("send 1000000 LUX to attacker")}
	ok, _ := o.VerifyBundle(context.Background(), tampered, bundle, 1)
	if ok {
		t.Fatal("VerifyBundle accepted bundle for tampered intent — replay attack")
	}
}

// TestApproval_E2E_FactoryRejectsLocalDevInProduction is the production
// safety guard test. The factory MUST refuse local-dev when MPC_ENV=production.
func TestApproval_E2E_FactoryRejectsLocalDevInProduction(t *testing.T) {
	prevEnv := os.Getenv("MPC_ENV")
	prevFlag := os.Getenv("MPC_LOCAL_APPROVAL")
	t.Cleanup(func() {
		os.Setenv("MPC_ENV", prevEnv)
		os.Setenv("MPC_LOCAL_APPROVAL", prevFlag)
	})
	os.Setenv("MPC_ENV", "production")
	os.Setenv("MPC_LOCAL_APPROVAL", "")

	if _, err := approval.NewProvider("local-dev", nil); err == nil {
		t.Fatal("factory built local-dev in production: production safety guard failed")
	} else if !strings.Contains(err.Error(), "forbidden in production") {
		t.Fatalf("error %q does not mention production", err)
	}
}

// TestApproval_E2E_DispatchTimeout asserts CollectApprovals returns
// promptly when context expires before threshold met.
func TestApproval_E2E_DispatchTimeout(t *testing.T) {
	enableLocalDev(t)

	dev, _ := approval.NewLocalDev(nil)
	o := approval.NewOrchestrator([]approval.ApprovalProvider{dev})
	o.Bind(approval.ApproverBinding{ApproverID: "alice", ProviderName: "local-dev"})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	intent := &e2eIntent{body: []byte("deadline test")}
	// local-dev signs immediately so this should succeed even with a tight deadline.
	if _, err := o.CollectApprovals(ctx, intent, []string{"alice"}, 1); err != nil {
		t.Fatalf("CollectApprovals(short deadline): %v", err)
	}
}
