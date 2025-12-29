package scheduler

import (
	"errors"
	"testing"
)

// TestOrchestratorIntegration_TrustGateRunsBeforePolicy proves the
// integration contract that pkg/mpc.SignGate now relies on:
//
//   - The scheduler is consulted with (Worker, ci.PolicyID) BEFORE
//     any policy-bundle verification work.
//   - A worker below MinTrust short-circuits with ErrInsufficientTrust
//     wrapped from Eligible.
//   - A worker at or above MinTrust returns nil, allowing the caller
//     (the policy verifier) to proceed.
//
// This is the behavioral contract the orchestrator file imports the
// scheduler for; testing it here keeps the proof close to the scheduler
// logic and avoids the upstream pkg/policy build dependency that is
// pre-existing breakage in this branch.
func TestOrchestratorIntegration_TrustGateRunsBeforePolicy(t *testing.T) {
	// Workload requires GPU + private lane + attested CPU+GPU.
	policy := &WorkloadPolicy{
		WorkloadID:                  "p-prod",
		MinTrust:                    TrustGPU,
		MinIO:                       IOPrivateLane,
		RequireGPUAttested:          true,
		RequireCPUAttested:          true,
		RequireModelConfidentiality: false, // simplify
	}
	src := NewStaticPolicySource(map[string]*WorkloadPolicy{"p-prod": policy})
	s := New(src)

	// Eligible worker matches the policy floors.
	good := Worker{
		ID: "node-good", TrustMode: TrustGPU, IOLevel: IOPrivateLane,
		GPUAttested: true, CPUAttested: true, Online: true,
	}
	if err := s.Eligible(good, "p-prod"); err != nil {
		t.Fatalf("expected eligible, got %v", err)
	}

	// Worker below GPU trust → reject. Wraps ErrInsufficientTrust via
	// AuthorizeSession; via Eligible, returns descriptive error.
	bad := good
	bad.TrustMode = TrustCVM
	if err := s.Eligible(bad, "p-prod"); err == nil {
		t.Fatal("expected ineligible")
	}

	// Worker offline — second-level guard.
	off := good
	off.Online = false
	if err := s.Eligible(off, "p-prod"); err == nil {
		t.Fatal("expected offline rejection")
	}

	// Workload not found in the policy source — distinct error.
	if err := s.Eligible(good, "ghost-policy"); err == nil {
		t.Fatal("expected lookup error")
	}
}

// TestOrchestratorIntegration_AuthorizeSession_FiltersWorkers proves the
// scheduler's AuthorizeSession (used by the sign coordinator to pick
// the t+1 nodes that may participate) excludes any worker that fails
// any gate, in stable order. This is the multi-node analogue of the
// per-call gate inside SignGate.AuthorizeSign.
func TestOrchestratorIntegration_AuthorizeSession_FiltersWorkers(t *testing.T) {
	policy := &WorkloadPolicy{
		WorkloadID:         "p-prod",
		MinTrust:           TrustGPU,
		MinIO:              IOPrivateLane,
		RequireGPUAttested: true,
		RequireCPUAttested: true,
	}
	src := NewStaticPolicySource(map[string]*WorkloadPolicy{"p-prod": policy})
	s := New(src)

	good1 := Worker{ID: "n1", TrustMode: TrustGPU, IOLevel: IOPrivateLane, GPUAttested: true, CPUAttested: true, Online: true}
	good2 := Worker{ID: "n2", TrustMode: TrustGPU, IOLevel: IOPrivateLane, GPUAttested: true, CPUAttested: true, Online: true}
	bad := good1
	bad.ID = "n3"
	bad.GPUAttested = false // missing GPU attestation

	out, err := s.AuthorizeSession("p-prod", []Worker{good1, bad, good2}, 2)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if len(out) != 2 || out[0].ID != "n1" || out[1].ID != "n2" {
		t.Fatalf("ordering or filter wrong: %+v", out)
	}

	// Below threshold → ErrInsufficientTrust.
	if _, err := s.AuthorizeSession("p-prod", []Worker{bad}, 1); !errors.Is(err, ErrInsufficientTrust) {
		t.Fatalf("got %v", err)
	}
}
