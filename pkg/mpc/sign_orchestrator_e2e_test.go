package mpc_test

// In-process e2e for the per-node sign gate.
//
// Mirrors e2e/policy_gate_test.go, but lives in pkg/mpc so it runs
// under the normal `go test ./pkg/mpc/...` flow. The e2e module has
// a pre-existing build break (missing luxfi/zapdb dep) so the
// equivalent test there is gated behind -tags policygate.

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

const numClusterNodes = 3

type nodeCtxE2E struct {
	id      string
	pubKey  ed25519.PublicKey
	privKey ed25519.PrivateKey
	gate    *mpc.SignGate
	sink    interface {
		All() []intent.NodeAttestation
	}
}

type signerKeyE2E struct {
	id   string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func mkSignerE2E(t *testing.T, id string) signerKeyE2E {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	return signerKeyE2E{id: id, pub: pub, priv: priv}
}

type clusterRigE2E struct {
	nodes   []*nodeCtxE2E
	signers []signerKeyE2E
	bundle  *policy.PolicyBundle
}

func newClusterRigE2E(t *testing.T) *clusterRigE2E {
	t.Helper()
	signers := []signerKeyE2E{
		mkSignerE2E(t, "exec-cfo"),
		mkSignerE2E(t, "exec-cto"),
		mkSignerE2E(t, "exec-ceo"),
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

	build := func(id string) *nodeCtxE2E {
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
		return &nodeCtxE2E{id: id, pubKey: nodePub, privKey: nodePriv, gate: gate, sink: sink}
	}

	nodes := make([]*nodeCtxE2E, numClusterNodes)
	for i := 0; i < numClusterNodes; i++ {
		nodes[i] = build(nodeIDE2E(i))
	}
	return &clusterRigE2E{nodes: nodes, signers: signers, bundle: bundle}
}

func nodeIDE2E(i int) string {
	return [...]string{"node0", "node1", "node2"}[i]
}

func (r *clusterRigE2E) buildIntent(t *testing.T, numApprovals int) *intent.CanonicalIntent {
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

func TestPolicyGateE2E_FullSignFlow_Succeeds(t *testing.T) {
	rig := newClusterRigE2E(t)
	ci := rig.buildIntent(t, 2)
	digestBefore, _ := ci.Digest()

	for _, n := range rig.nodes {
		digest, att, err := n.gate.AuthorizeAndDigest(context.Background(), ci)
		if err != nil {
			t.Fatalf("node %s: expected success, got %v", n.id, err)
		}
		if digest != digestBefore {
			t.Fatalf("node %s: digest drift", n.id)
		}
		if att.Verdict != "approve" {
			t.Fatalf("node %s: expected approve, got %s", n.id, att.Verdict)
		}
		if err := policy.VerifyAttestation(ci, att); err != nil {
			t.Fatalf("node %s: verify attestation: %v", n.id, err)
		}
	}
}

func TestPolicyGateE2E_OneApprovalMissing_AllNodesRefuse(t *testing.T) {
	rig := newClusterRigE2E(t)
	ci := rig.buildIntent(t, 1)
	for _, n := range rig.nodes {
		att, err := n.gate.AuthorizeSign(context.Background(), ci)
		if !errors.Is(err, mpc.ErrSignBlocked) {
			t.Fatalf("node %s: expected ErrSignBlocked, got %v", n.id, err)
		}
		if !errors.Is(err, policy.ErrInsufficientApprovals) {
			t.Fatalf("node %s: expected ErrInsufficientApprovals, got %v", n.id, err)
		}
		if att.Verdict != "reject" {
			t.Fatalf("node %s: expected reject attestation, got %s", n.id, att.Verdict)
		}
	}
}

// TestPolicyGateE2E_CoordinatorBypassAttempt_NodesStillRefuse — even if
// a malicious coordinator forges an "approval" with an unknown key,
// per-node verification rejects it.
func TestPolicyGateE2E_CoordinatorBypassAttempt_NodesStillRefuse(t *testing.T) {
	rig := newClusterRigE2E(t)
	ci := rig.buildIntent(t, 0)
	rogue := mkSignerE2E(t, "rogue-coordinator")
	digest, _ := ci.Digest()
	ci.Approvals = append(ci.Approvals, intent.ApprovalSignature{
		SignerID:  "rogue-coordinator",
		PublicKey: rogue.pub,
		Signature: ed25519.Sign(rogue.priv, digest[:]),
	})
	for _, n := range rig.nodes {
		_, err := n.gate.AuthorizeSign(context.Background(), ci)
		if !errors.Is(err, mpc.ErrSignBlocked) {
			t.Fatalf("node %s: BYPASS — expected block, got %v", n.id, err)
		}
	}
}

func TestPolicyGateE2E_PolicyHashMismatch_AllNodesRefuse(t *testing.T) {
	rig := newClusterRigE2E(t)
	ci := rig.buildIntent(t, 2)
	ci.PolicyHash = [32]byte{0xff, 0xff, 0xff}
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

func TestPolicyGateE2E_AuditRecordsBothPositiveAndNegative(t *testing.T) {
	rig := newClusterRigE2E(t)
	pass := rig.buildIntent(t, 2)
	for _, n := range rig.nodes {
		if _, err := n.gate.AuthorizeSign(context.Background(), pass); err != nil {
			t.Fatalf("node %s: %v", n.id, err)
		}
	}
	fail := rig.buildIntent(t, 0)
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

func TestPolicyGateE2E_DeterministicDigestAcrossNodes(t *testing.T) {
	rig := newClusterRigE2E(t)
	ci := rig.buildIntent(t, 2)

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

func TestPolicyGateE2E_FailureModesAreOrthogonal(t *testing.T) {
	type tc struct {
		name   string
		mutate func(*clusterRigE2E, *intent.CanonicalIntent)
		want   error
	}
	cases := []tc{
		{
			name:   "unknown wallet",
			mutate: func(_ *clusterRigE2E, ci *intent.CanonicalIntent) { ci.WalletID = "ghost" },
			want:   policy.ErrUnknownWallet,
		},
		{
			name:   "policy not found",
			mutate: func(_ *clusterRigE2E, ci *intent.CanonicalIntent) { ci.PolicyID = "nope" },
			want:   policy.ErrPolicyNotFound,
		},
		{
			name: "expired",
			mutate: func(_ *clusterRigE2E, ci *intent.CanonicalIntent) {
				ci.ExpiresAt = time.Date(2026, 4, 27, 11, 0, 0, 0, time.UTC)
			},
			want: policy.ErrExpiredIntent,
		},
		{
			name: "destination off allowlist",
			mutate: func(r *clusterRigE2E, ci *intent.CanonicalIntent) {
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
			rig := newClusterRigE2E(t)
			ci := rig.buildIntent(t, 2)
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
