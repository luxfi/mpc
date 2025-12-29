// Sign-orchestrator scheduler integration. Proves that wiring a
// scheduler.Scheduler into a SignGate causes the gate to refuse
// signing for a worker whose trust posture falls below the workload
// floor — and that the refusal lands in the audit sink as a reject
// attestation, identically to a policy-verifier refusal.
//
// This file lives in package mpc_test alongside the existing
// per-node policy-gate tests so it runs under the same `go test
// ./pkg/mpc/...` invocation. There is a pre-existing breakage in
// pkg/policy (luxfi/fhe import path resolution) that blocks pkg/mpc
// from compiling at HEAD; once that is resolved, this test passes
// without further changes — see the truth-table in
// pkg/scheduler/orchestrator_integration_test.go for the same
// invariants tested standalone.

package mpc_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/luxfi/mpc/pkg/intent"
	"github.com/luxfi/mpc/pkg/mpc"
	"github.com/luxfi/mpc/pkg/policy"
	"github.com/luxfi/mpc/pkg/risk"
	"github.com/luxfi/mpc/pkg/scheduler"
)

// buildVerifier returns a LocalVerifier that approves the canonical
// happy-path intent built by buildIntent below.
func buildVerifier(t *testing.T) (*policy.LocalVerifier, []signerKeySched, *policy.PolicyBundle) {
	t.Helper()
	signers := []signerKeySched{
		mkSignerSched(t, "exec-cfo"),
		mkSignerSched(t, "exec-cto"),
	}
	bundle := &policy.PolicyBundle{
		PolicyID: "p-prod",
		Version:  "v1",
		Tiers: map[intent.WalletTier]policy.TierPolicy{
			intent.TierWarm: {
				MinApprovals:     2,
				MaxAmount:        big.NewInt(1_000_000_000_000),
				EnforceAllowlist: true,
			},
		},
		Allowlist: map[string]map[string]bool{"eip155:1": {"0xrecip": true}},
	}
	wr := policy.NewMemWalletRegistry()
	wr.Put(policy.Wallet{WalletID: "wallet-treasury", Tier: intent.TierWarm, Chain: "eip155:1", Address: "0xfrom"})
	ks := policy.NewMemApprovalKeyset()
	for _, s := range signers {
		ks.Add(policy.ApprovalSigner{SignerID: s.id, PublicKey: s.pub})
	}
	ps := policy.NewMemPolicyStore()
	ps.Put(bundle)
	rp := risk.NewInternalAllowlistProvider()
	rp.Allow("eip155:1", "0xrecip")
	v := policy.NewLocalVerifier(wr, ks, rp, ps)
	v.Now = func() time.Time { return time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC) }
	return v, signers, bundle
}

type signerKeySched struct {
	id   string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func mkSignerSched(t *testing.T, id string) signerKeySched {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	return signerKeySched{id: id, pub: pub, priv: priv}
}

func buildIntent(t *testing.T, signers []signerKeySched, bundle *policy.PolicyBundle) *intent.CanonicalIntent {
	t.Helper()
	ci := &intent.CanonicalIntent{
		IntentVersion:  intent.IntentVersion,
		SessionID:      "sess",
		WalletID:       "wallet-treasury",
		WalletTier:     intent.TierWarm,
		Chain:          "eip155:1",
		Asset:          "USDC",
		From:           "0xfrom",
		To:             "0xrecip",
		Amount:         "100",
		MaxFee:         "21000",
		Nonce:          "1",
		CalldataHash:   [32]byte{1},
		HumanSummary:   "test",
		PolicyID:       bundle.PolicyID,
		PolicyHash:     bundle.Hash(),
		RiskVerdictID:  "rv",
		SimulationHash: [32]byte{2},
		ExpiresAt:      time.Date(2026, 4, 27, 13, 0, 0, 0, time.UTC),
	}
	digest, err := ci.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	for _, s := range signers {
		ci.Approvals = append(ci.Approvals, intent.ApprovalSignature{
			SignerID:  s.id,
			PublicKey: s.pub,
			Signature: ed25519.Sign(s.priv, digest[:]),
			SignedAt:  time.Date(2026, 4, 27, 11, 0, 0, 0, time.UTC),
		})
	}
	return ci
}

// strictWorkloadPolicy mirrors the workload's trust requirements at
// the same PolicyID the intent references — wiring is by ci.PolicyID.
func strictWorkloadPolicy() *scheduler.WorkloadPolicy {
	return &scheduler.WorkloadPolicy{
		WorkloadID:         "p-prod",
		MinTrust:           scheduler.TrustGPU,
		MinIO:              scheduler.IOPrivateLane,
		RequireGPUAttested: true,
		RequireCPUAttested: true,
	}
}

// TestSignGate_NilSchedulerKeepsLegacyBehavior — without a scheduler
// wired in, AuthorizeSign behaves exactly as before (only the policy
// verifier runs).
func TestSignGate_NilSchedulerKeepsLegacyBehavior(t *testing.T) {
	v, signers, bundle := buildVerifier(t)
	ci := buildIntent(t, signers, bundle)

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	sink := mpc.NewMemAttestationSink()
	g := mpc.NewSignGate("node0", priv, v, sink)

	att, err := g.AuthorizeSign(context.Background(), ci)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if att.Verdict != "approve" {
		t.Fatalf("verdict: %s", att.Verdict)
	}
}

// TestSignGate_SchedulerEligibleAllowsPolicyVerifier — when the worker
// passes the trust posture floor, the policy verifier runs and the
// happy path approves.
func TestSignGate_SchedulerEligibleAllowsPolicyVerifier(t *testing.T) {
	v, signers, bundle := buildVerifier(t)
	ci := buildIntent(t, signers, bundle)

	src := scheduler.NewStaticPolicySource(map[string]*scheduler.WorkloadPolicy{
		"p-prod": strictWorkloadPolicy(),
	})
	s := scheduler.New(src)
	worker := scheduler.Worker{
		ID:          "node-good",
		TrustMode:   scheduler.TrustGPU,
		IOLevel:     scheduler.IOPrivateLane,
		GPUAttested: true,
		CPUAttested: true,
		Online:      true,
	}

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	sink := mpc.NewMemAttestationSink()
	g := mpc.NewSignGate("node0", priv, v, sink).WithScheduler(s, worker)

	att, err := g.AuthorizeSign(context.Background(), ci)
	if err != nil {
		t.Fatalf("expected authorize, got %v", err)
	}
	if att.Verdict != "approve" {
		t.Fatalf("verdict: %s", att.Verdict)
	}
}

// TestSignGate_SchedulerInsufficientTrustShortCircuits — a worker
// below the workload's trust floor causes AuthorizeSign to reject
// without consulting the policy verifier. The reject attestation
// reason names "scheduler:" so audit consumers can categorize.
func TestSignGate_SchedulerInsufficientTrustShortCircuits(t *testing.T) {
	v, signers, bundle := buildVerifier(t)
	ci := buildIntent(t, signers, bundle)

	src := scheduler.NewStaticPolicySource(map[string]*scheduler.WorkloadPolicy{
		"p-prod": strictWorkloadPolicy(),
	})
	s := scheduler.New(src)

	// CVM tier is below the required GPU trust.
	worker := scheduler.Worker{
		ID:          "node-cvm",
		TrustMode:   scheduler.TrustCVM,
		IOLevel:     scheduler.IOPrivateLane,
		GPUAttested: false, // no GPU
		CPUAttested: true,
		Online:      true,
	}

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	sink := mpc.NewMemAttestationSink()
	g := mpc.NewSignGate("node0", priv, v, sink).WithScheduler(s, worker)

	att, err := g.AuthorizeSign(context.Background(), ci)
	if !errors.Is(err, mpc.ErrSignBlocked) {
		t.Fatalf("expected ErrSignBlocked, got %v", err)
	}
	if att.Verdict != "reject" {
		t.Fatalf("verdict: %s", att.Verdict)
	}
	// Reason must indicate scheduler — not a policy-verifier reason.
	if !contains(att.Reason, "scheduler:") {
		t.Fatalf("expected reason to start with scheduler: got %q", att.Reason)
	}
	if got := sink.All(); len(got) != 1 {
		t.Fatalf("audit count: %d", len(got))
	}
}

// TestSignGate_SchedulerWorkloadLookupFails — when ci.PolicyID does
// not exist in the scheduler's source, AuthorizeSign rejects with the
// scheduler error wrapped in ErrSignBlocked.
func TestSignGate_SchedulerWorkloadLookupFails(t *testing.T) {
	v, signers, bundle := buildVerifier(t)
	ci := buildIntent(t, signers, bundle)
	ci.PolicyID = "ghost-workload"
	// re-sign approvals against the new digest so the policy verifier
	// would otherwise pass — proving the scheduler check ran first.
	digest, _ := ci.Digest()
	ci.Approvals = nil
	for _, s := range signers {
		ci.Approvals = append(ci.Approvals, intent.ApprovalSignature{
			SignerID:  s.id,
			PublicKey: s.pub,
			Signature: ed25519.Sign(s.priv, digest[:]),
		})
	}

	src := scheduler.NewStaticPolicySource(map[string]*scheduler.WorkloadPolicy{
		"p-prod": strictWorkloadPolicy(),
	})
	s := scheduler.New(src)
	worker := scheduler.Worker{
		ID: "node0", TrustMode: scheduler.TrustGPU, IOLevel: scheduler.IOPrivateLane,
		GPUAttested: true, CPUAttested: true, Online: true,
	}

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	sink := mpc.NewMemAttestationSink()
	g := mpc.NewSignGate("node0", priv, v, sink).WithScheduler(s, worker)

	_, err := g.AuthorizeSign(context.Background(), ci)
	if !errors.Is(err, mpc.ErrSignBlocked) {
		t.Fatalf("expected ErrSignBlocked, got %v", err)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
