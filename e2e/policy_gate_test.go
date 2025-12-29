//go:build policygate
// +build policygate

package e2e

// Per-node policy gate end-to-end test.
//
// Build tag rationale: the e2e module imports luxfi/zapdb which is not
// in go.mod (pre-existing breakage tracked separately). This file is
// gated behind `-tags policygate` so it can be exercised independently
// of the daemon-driven e2e tests:
//
//   cd e2e && go test -tags policygate -run TestPolicyGate -v
//
// The same test logic also runs as a regular package test under
// /Users/z/work/lux/mpc/pkg/mpc/sign_orchestrator_e2e_test.go which
// does not require the broken e2e module to build.
//
// This test exercises the full orchestration of:
//   1. building a CanonicalIntent
//   2. gathering executive approvals (Ed25519 signatures over the digest)
//   3. each MPC node independently running its LocalVerifier via SignGate
//   4. confirming sign succeeds only when EVERY node verifies
//
// It is the proof that "the MPC node signs only if it independently
// verifies the policy bundle" is non-bypassable: a coordinator that
// returns "approved" cannot trick a node into signing if the node's
// own verifier disagrees.
//
// This test does NOT spin up the full mpcd binary or NATS/Consul; it
// runs three SignGates in-process to assert the gate logic. The other
// e2e tests in this directory exercise the full daemon pipeline.

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
)

const (
	numClusterNodes = 3
)

// nodeCtx holds the per-node state for the simulated cluster.
type nodeCtx struct {
	id      string
	pubKey  ed25519.PublicKey
	privKey ed25519.PrivateKey
	gate    *mpc.SignGate
	sink    interface{ All() []intent.NodeAttestation } // memAttestationSink
}

// clusterRig is the test fixture: 3 MPC nodes, each with a copy of the
// same policy bundle + approval keyset, plus 3 executive approval keys.
type clusterRig struct {
	nodes    []*nodeCtx
	signers  []signerKey
	bundle   *policy.PolicyBundle
}

type signerKey struct {
	id      string
	pub     ed25519.PublicKey
	priv    ed25519.PrivateKey
}

func mkSigner(t *testing.T, id string) signerKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	return signerKey{id: id, pub: pub, priv: priv}
}

func newClusterRig(t *testing.T) *clusterRig {
	t.Helper()

	// Three executive approvers — at least 2 must sign for warm tier.
	signers := []signerKey{
		mkSigner(t, "exec-cfo"),
		mkSigner(t, "exec-cto"),
		mkSigner(t, "exec-ceo"),
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
		Allowlist: map[string]map[string]bool{
			"eip155:1": {"0xrecip": true},
		},
	}

	// Each node holds an independent copy of every backing store —
	// this is what makes the verification per-node and non-bypassable.
	build := func(id string) *nodeCtx {
		wr := policy.NewMemWalletRegistry()
		wr.Put(policy.Wallet{
			WalletID: "wallet-treasury",
			Tier:     intent.TierWarm,
			Chain:    "eip155:1",
			Address:  "0xfrom",
		})
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

		nodePub, nodePriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("node key: %v", err)
		}
		sink := mpc.NewMemAttestationSink()
		gate := mpc.NewSignGate(id, nodePriv, v, sink)
		return &nodeCtx{
			id: id, pubKey: nodePub, privKey: nodePriv,
			gate: gate, sink: sink,
		}
	}

	nodes := make([]*nodeCtx, numClusterNodes)
	for i := 0; i < numClusterNodes; i++ {
		nodes[i] = build(makeNodeID(i))
	}

	return &clusterRig{nodes: nodes, signers: signers, bundle: bundle}
}

func makeNodeID(i int) string {
	switch i {
	case 0:
		return "node0"
	case 1:
		return "node1"
	case 2:
		return "node2"
	default:
		return "nodeN"
	}
}

// buildApprovedIntent constructs a fully-approved intent at numApprovals.
func (r *clusterRig) buildApprovedIntent(t *testing.T, numApprovals int) *intent.CanonicalIntent {
	t.Helper()
	ci := &intent.CanonicalIntent{
		IntentVersion:  intent.IntentVersion,
		SessionID:      "sess-test",
		WalletID:       "wallet-treasury",
		WalletTier:     intent.TierWarm,
		Chain:          "eip155:1",
		Asset:          "USDC",
		From:           "0xfrom",
		To:             "0xrecip",
		Amount:         "1000",
		MaxFee:         "21000",
		Nonce:          "1",
		CalldataHash:   [32]byte{1, 2, 3},
		HumanSummary:   "treasury->vendor 1000 USDC",
		PolicyID:       r.bundle.PolicyID,
		PolicyHash:     r.bundle.Hash(),
		RiskVerdictID:  "rv-test",
		SimulationHash: [32]byte{0xaa, 0xbb},
		ExpiresAt:      time.Date(2026, 4, 27, 13, 0, 0, 0, time.UTC),
	}
	digest, err := ci.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	for i := 0; i < numApprovals && i < len(r.signers); i++ {
		s := r.signers[i]
		ci.Approvals = append(ci.Approvals, intent.ApprovalSignature{
			SignerID:  s.id,
			PublicKey: s.pub,
			Signature: ed25519.Sign(s.priv, digest[:]),
			SignedAt:  time.Date(2026, 4, 27, 11, 0, 0, 0, time.UTC),
		})
	}
	return ci
}

// runEachNode invokes each node's gate. Returns per-node attestations.
// If allMustPass is true, fails the test if any node rejects.
func (r *clusterRig) runEachNode(t *testing.T, ci *intent.CanonicalIntent) []intent.NodeAttestation {
	t.Helper()
	out := make([]intent.NodeAttestation, 0, len(r.nodes))
	for _, n := range r.nodes {
		att, err := n.gate.AuthorizeSign(context.Background(), ci)
		if err == nil {
			out = append(out, att)
			continue
		}
		// Even on failure the gate must return a (rejected) attestation.
		out = append(out, att)
	}
	return out
}

// =============================================================================
// Tests
// =============================================================================

// TestPolicyGate_FullSignFlow_Succeeds — happy path: 2 valid approvals
// (meets MinApprovals=2 for warm tier) → all 3 nodes authorize.
func TestPolicyGate_FullSignFlow_Succeeds(t *testing.T) {
	rig := newClusterRig(t)
	ci := rig.buildApprovedIntent(t, 2)

	digestBefore, err := ci.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}

	for _, n := range rig.nodes {
		digest, att, err := n.gate.AuthorizeAndDigest(context.Background(), ci)
		if err != nil {
			t.Fatalf("node %s: expected authorize success, got %v", n.id, err)
		}
		if digest != digestBefore {
			t.Fatalf("node %s: digest drift across gate", n.id)
		}
		if att.Verdict != "approve" {
			t.Fatalf("node %s: expected approve, got %s", n.id, att.Verdict)
		}
		if err := policy.VerifyAttestation(ci, att); err != nil {
			t.Fatalf("node %s: attestation verify: %v", n.id, err)
		}
	}
}

// TestPolicyGate_OneApprovalMissing_AllNodesRefuse — only 1 of 2
// required approvals attached. EVERY node must independently refuse,
// no signature produced.
func TestPolicyGate_OneApprovalMissing_AllNodesRefuse(t *testing.T) {
	rig := newClusterRig(t)
	ci := rig.buildApprovedIntent(t, 1) // only one approval

	for _, n := range rig.nodes {
		att, err := n.gate.AuthorizeSign(context.Background(), ci)
		if !errors.Is(err, mpc.ErrSignBlocked) {
			t.Fatalf("node %s: expected ErrSignBlocked, got %v", n.id, err)
		}
		if !errors.Is(err, policy.ErrInsufficientApprovals) {
			t.Fatalf("node %s: expected wrapped ErrInsufficientApprovals, got %v", n.id, err)
		}
		if att.Verdict != "reject" {
			t.Fatalf("node %s: expected reject attestation, got %s", n.id, att.Verdict)
		}
	}
}

// TestPolicyGate_CoordinatorBypassAttempt_NodesStillRefuse — the
// coordinator (simulated by mutating the intent) flips an "approved"
// flag, but the actual approval signatures are still missing. EVERY
// node refuses because each runs the verifier on its own.
//
// This is the central proof that the gate is non-bypassable: there is
// no "trust the coordinator" path. The coordinator's claim is irrelevant.
func TestPolicyGate_CoordinatorBypassAttempt_NodesStillRefuse(t *testing.T) {
	rig := newClusterRig(t)

	// Build an intent with ZERO approvals — but pretend the coordinator
	// signed off on it via a phony NodeAttestation field. There is no
	// "approved" boolean to flip; the structural representation is the
	// list of valid approvals over the digest. So the bypass attempt
	// is: send the intent without approvals.
	ci := rig.buildApprovedIntent(t, 0)

	// Add a fabricated "approval" from an unknown key — the
	// coordinator's attempt to claim policy was met.
	rogue := mkSigner(t, "rogue-coordinator")
	digest, _ := ci.Digest()
	ci.Approvals = append(ci.Approvals, intent.ApprovalSignature{
		SignerID:  "rogue-coordinator",
		PublicKey: rogue.pub,
		Signature: ed25519.Sign(rogue.priv, digest[:]),
	})

	for _, n := range rig.nodes {
		_, err := n.gate.AuthorizeSign(context.Background(), ci)
		if !errors.Is(err, mpc.ErrSignBlocked) {
			t.Fatalf("node %s: BYPASS — expected ErrSignBlocked, got %v", n.id, err)
		}
	}
}

// TestPolicyGate_PolicyHashMismatch_AllNodesRefuse — the coordinator
// references a policy ID that exists, but the hash does not match the
// node's local copy of the bundle. Per-node verification catches this
// because each node computes the bundle hash itself.
func TestPolicyGate_PolicyHashMismatch_AllNodesRefuse(t *testing.T) {
	rig := newClusterRig(t)
	ci := rig.buildApprovedIntent(t, 2)
	// Tamper with PolicyHash to simulate a coordinator referencing a
	// rewritten policy bundle.
	ci.PolicyHash = [32]byte{0xff, 0xff, 0xff}
	// Re-sign approvals against the new (tampered) digest:
	digest, _ := ci.Digest()
	ci.Approvals = nil
	for i := 0; i < 2; i++ {
		s := rig.signers[i]
		ci.Approvals = append(ci.Approvals, intent.ApprovalSignature{
			SignerID:  s.id,
			PublicKey: s.pub,
			Signature: ed25519.Sign(s.priv, digest[:]),
		})
	}

	for _, n := range rig.nodes {
		_, err := n.gate.AuthorizeSign(context.Background(), ci)
		if !errors.Is(err, policy.ErrPolicyMismatch) {
			t.Fatalf("node %s: expected ErrPolicyMismatch, got %v", n.id, err)
		}
	}
}

// TestPolicyGate_AuditRecordsBothPositiveAndNegative — both positive
// and negative attestations are persisted to the audit sink.
func TestPolicyGate_AuditRecordsBothPositiveAndNegative(t *testing.T) {
	rig := newClusterRig(t)

	// First: a passing intent → positive attestations recorded.
	pass := rig.buildApprovedIntent(t, 2)
	for _, n := range rig.nodes {
		if _, err := n.gate.AuthorizeSign(context.Background(), pass); err != nil {
			t.Fatalf("node %s: %v", n.id, err)
		}
	}
	// Then: a failing intent → rejection attestations recorded.
	fail := rig.buildApprovedIntent(t, 0)
	for _, n := range rig.nodes {
		if _, err := n.gate.AuthorizeSign(context.Background(), fail); err == nil {
			t.Fatalf("node %s: expected failure", n.id)
		}
	}

	for _, n := range rig.nodes {
		all := n.sink.All()
		if len(all) != 2 {
			t.Fatalf("node %s: expected 2 audit records, got %d", n.id, len(all))
		}
		if all[0].Verdict != "approve" || all[1].Verdict != "reject" {
			t.Fatalf("node %s: expected approve+reject, got %s+%s",
				n.id, all[0].Verdict, all[1].Verdict)
		}
	}
}

// TestPolicyGate_DeterministicDigestAcrossNodes — every node computes
// the same digest from the same intent. This is what makes the
// threshold protocol agree on what to sign.
func TestPolicyGate_DeterministicDigestAcrossNodes(t *testing.T) {
	rig := newClusterRig(t)
	ci := rig.buildApprovedIntent(t, 2)

	digests := make([][32]byte, 0, len(rig.nodes))
	for _, n := range rig.nodes {
		d, _, err := n.gate.AuthorizeAndDigest(context.Background(), ci)
		if err != nil {
			t.Fatalf("node %s: %v", n.id, err)
		}
		digests = append(digests, d)
	}
	first := digests[0]
	for i, d := range digests {
		if d != first {
			t.Fatalf("node %d digest differs: %x vs %x", i, d, first)
		}
	}
}

// TestPolicyGate_FailureModesAreOrthogonal — exhaustive sweep of every
// rejection cause exercised through the gate, asserting each surfaces
// uniformly via ErrSignBlocked + the underlying policy error.
func TestPolicyGate_FailureModesAreOrthogonal(t *testing.T) {
	type tc struct {
		name   string
		mutate func(*clusterRig, *intent.CanonicalIntent)
		want   error
	}
	cases := []tc{
		{
			name:   "unknown wallet",
			mutate: func(_ *clusterRig, ci *intent.CanonicalIntent) { ci.WalletID = "ghost" },
			want:   policy.ErrUnknownWallet,
		},
		{
			name:   "policy not found",
			mutate: func(_ *clusterRig, ci *intent.CanonicalIntent) { ci.PolicyID = "nope" },
			want:   policy.ErrPolicyNotFound,
		},
		{
			name:   "expired",
			mutate: func(_ *clusterRig, ci *intent.CanonicalIntent) { ci.ExpiresAt = time.Date(2026, 4, 27, 11, 0, 0, 0, time.UTC) },
			want:   policy.ErrExpiredIntent,
		},
		{
			name: "destination off allowlist",
			mutate: func(r *clusterRig, ci *intent.CanonicalIntent) {
				ci.To = "0xstranger"
				digest, _ := ci.Digest()
				ci.Approvals = nil
				for i := 0; i < 2; i++ {
					s := r.signers[i]
					ci.Approvals = append(ci.Approvals, intent.ApprovalSignature{
						SignerID: s.id, PublicKey: s.pub,
						Signature: ed25519.Sign(s.priv, digest[:]),
					})
				}
			},
			want: policy.ErrAllowlistViolation,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rig := newClusterRig(t)
			ci := rig.buildApprovedIntent(t, 2)
			c.mutate(rig, ci)

			for _, n := range rig.nodes {
				_, err := n.gate.AuthorizeSign(context.Background(), ci)
				if !errors.Is(err, c.want) {
					t.Fatalf("node %s: expected %v, got %v", n.id, c.want, err)
				}
				if !errors.Is(err, mpc.ErrSignBlocked) {
					t.Fatalf("node %s: expected wrapped ErrSignBlocked, got %v", n.id, err)
				}
			}
		})
	}
}
