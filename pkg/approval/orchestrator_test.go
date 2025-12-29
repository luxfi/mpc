package approval

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func devEnv(t *testing.T) {
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

func makeBoundOrchestrator(t *testing.T, approvers []string) *Orchestrator {
	t.Helper()
	dev, err := NewLocalDev(nil)
	if err != nil {
		t.Fatal(err)
	}
	o := NewOrchestrator([]ApprovalProvider{dev})
	for _, a := range approvers {
		if err := o.Bind(ApproverBinding{ApproverID: a, ProviderName: "local-dev"}); err != nil {
			t.Fatalf("Bind(%s): %v", a, err)
		}
	}
	return o
}

func TestOrchestrator_2of3_Succeeds(t *testing.T) {
	devEnv(t)
	o := makeBoundOrchestrator(t, []string{"alice", "bob", "carol"})
	intent := newTestIntent("2-of-3 approval")
	bundle, err := o.CollectApprovals(context.Background(), intent, []string{"alice", "bob", "carol"}, 2)
	if err != nil {
		t.Fatalf("CollectApprovals: %v", err)
	}
	if len(bundle) < 2 {
		t.Fatalf("bundle has %d signatures, want >= 2", len(bundle))
	}
	ok, err := o.VerifyBundle(context.Background(), intent, bundle, 2)
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if !ok {
		t.Fatal("VerifyBundle = false")
	}
}

func TestOrchestrator_AllSucceed(t *testing.T) {
	devEnv(t)
	o := makeBoundOrchestrator(t, []string{"alice", "bob", "carol"})
	intent := newTestIntent("all-three approval")
	bundle, err := o.CollectApprovals(context.Background(), intent, []string{"alice", "bob", "carol"}, 3)
	if err != nil {
		t.Fatalf("CollectApprovals: %v", err)
	}
	if len(bundle) != 3 {
		t.Fatalf("bundle has %d signatures, want 3", len(bundle))
	}
}

func TestOrchestrator_ThresholdTooHigh(t *testing.T) {
	devEnv(t)
	o := makeBoundOrchestrator(t, []string{"alice"})
	intent := newTestIntent("impossible threshold")
	if _, err := o.CollectApprovals(context.Background(), intent, []string{"alice"}, 5); err == nil {
		t.Fatal("CollectApprovals with threshold > approvers: want error")
	}
}

func TestOrchestrator_UnboundApprover(t *testing.T) {
	devEnv(t)
	dev, _ := NewLocalDev(nil)
	o := NewOrchestrator([]ApprovalProvider{dev})
	o.Bind(ApproverBinding{ApproverID: "alice", ProviderName: "local-dev"})
	// "bob" is intentionally unbound.

	intent := newTestIntent("missing binding")
	if _, err := o.CollectApprovals(context.Background(), intent, []string{"alice", "bob"}, 2); err == nil {
		t.Fatal("CollectApprovals with unbound approver: want error")
	} else if !strings.Contains(err.Error(), "not bound") {
		t.Fatalf("error %q does not mention 'not bound'", err)
	}
}

func TestOrchestrator_DedupesApprovers(t *testing.T) {
	devEnv(t)
	o := makeBoundOrchestrator(t, []string{"alice"})
	intent := newTestIntent("dedupe test")
	bundle, err := o.CollectApprovals(context.Background(), intent, []string{"alice", "alice", "alice"}, 1)
	if err != nil {
		t.Fatalf("CollectApprovals: %v", err)
	}
	// dedupe shrinks to 1 unique approver, threshold 1 satisfied
	if len(bundle) != 1 {
		t.Fatalf("bundle has %d, want 1", len(bundle))
	}
}

// slowProvider delays Approve for the configured duration so we can test
// context cancellation.
type slowProvider struct {
	delay time.Duration
}

func (p *slowProvider) Provider() string { return "slow" }
func (p *slowProvider) GetPublicIdentity(_ context.Context, approverID string) (PublicIdentity, error) {
	return PublicIdentity{ApproverID: approverID, Provider: "slow"}, nil
}
func (p *slowProvider) ApproveIntent(ctx context.Context, approverID string, _ CanonicalIntent) (ApprovalSignature, error) {
	select {
	case <-time.After(p.delay):
		return ApprovalSignature{ApproverID: approverID, Provider: "slow"}, nil
	case <-ctx.Done():
		return ApprovalSignature{}, ctx.Err()
	}
}
func (p *slowProvider) VerifyApproval(_ context.Context, _ CanonicalIntent, _ ApprovalSignature) (bool, error) {
	return true, nil
}

func TestOrchestrator_ContextTimeout(t *testing.T) {
	slow := &slowProvider{delay: 5 * time.Second}
	o := NewOrchestrator([]ApprovalProvider{slow})
	o.Bind(ApproverBinding{ApproverID: "alice", ProviderName: "slow"})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	intent := newTestIntent("timeout test")
	_, err := o.CollectApprovals(ctx, intent, []string{"alice"}, 1)
	if err == nil {
		t.Fatal("CollectApprovals on cancelled context: want error")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !strings.Contains(err.Error(), "threshold 1 not met") {
		t.Fatalf("unexpected error %v", err)
	}
}

func TestOrchestrator_VerifyBundle_RejectsWrongCount(t *testing.T) {
	devEnv(t)
	o := makeBoundOrchestrator(t, []string{"alice"})
	intent := newTestIntent("verify count")
	bundle, err := o.CollectApprovals(context.Background(), intent, []string{"alice"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	// Threshold 2 but only 1 signature → false.
	ok, err := o.VerifyBundle(context.Background(), intent, bundle, 2)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("VerifyBundle accepted insufficient signatures")
	}
}
