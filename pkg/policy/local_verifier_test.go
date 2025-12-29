package policy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/luxfi/mpc/pkg/intent"
	"github.com/luxfi/mpc/pkg/risk"
)

// signerKey is a generated keypair for an approval signer in tests.
type signerKey struct {
	id  string
	pub ed25519.PublicKey
	sec ed25519.PrivateKey
}

func mkSigner(t *testing.T, id string) signerKey {
	t.Helper()
	pub, sec, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	return signerKey{id: id, pub: pub, sec: sec}
}

// rig builds a fully-wired verifier + a base intent and returns both.
type rig struct {
	v       *LocalVerifier
	wr      *MemWalletRegistry
	ks      *MemApprovalKeyset
	ps      *MemPolicyStore
	risk    *risk.InternalAllowlistProvider
	bundle  *PolicyBundle
	signers []signerKey
}

func newRig(t *testing.T) *rig {
	t.Helper()
	wr := NewMemWalletRegistry()
	wr.Put(Wallet{
		WalletID: "w1",
		Tier:     intent.TierWarm,
		Chain:    "eip155:1",
		Address:  "0xfrom",
	})

	signers := []signerKey{mkSigner(t, "exec-cfo"), mkSigner(t, "exec-cto"), mkSigner(t, "exec-ceo")}
	ks := NewMemApprovalKeyset()
	for _, s := range signers {
		ks.Add(ApprovalSigner{SignerID: s.id, PublicKey: s.pub})
	}

	bundle := &PolicyBundle{
		PolicyID: "p1",
		Version:  "v1",
		Tiers: map[intent.WalletTier]TierPolicy{
			intent.TierWarm: {
				MinApprovals:     2,
				MaxAmount:        big.NewInt(1_000_000_000),
				EnforceAllowlist: true,
				AmountThresholds: []AmountThreshold{
					{Amount: big.NewInt(500_000_000), Required: 3},
				},
			},
		},
		Allowlist: map[string]map[string]bool{
			"eip155:1": {"0xrecip": true},
		},
	}
	ps := NewMemPolicyStore()
	ps.Put(bundle)

	rp := risk.NewInternalAllowlistProvider()
	rp.Allow("eip155:1", "0xrecip")

	v := NewLocalVerifier(wr, ks, rp, ps)
	v.Now = func() time.Time { return time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC) }

	return &rig{v: v, wr: wr, ks: ks, ps: ps, risk: rp, bundle: bundle, signers: signers}
}

// validIntent returns a fully-approved intent at the rig's "now".
func (r *rig) validIntent(t *testing.T) *intent.CanonicalIntent {
	t.Helper()
	ci := &intent.CanonicalIntent{
		IntentVersion:  intent.IntentVersion,
		SessionID:      "s1",
		WalletID:       "w1",
		WalletTier:     intent.TierWarm,
		Chain:          "eip155:1",
		Asset:          "USDC",
		From:           "0xfrom",
		To:             "0xrecip",
		Amount:         "1000",
		MaxFee:         "21000",
		Nonce:          "1",
		CalldataHash:   [32]byte{1},
		HumanSummary:   "test send",
		PolicyID:       r.bundle.PolicyID,
		PolicyHash:     r.bundle.Hash(),
		RiskVerdictID:  "rv1",
		SimulationHash: [32]byte{2},
		ExpiresAt:      time.Date(2026, 4, 27, 13, 0, 0, 0, time.UTC),
	}
	digest, err := ci.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	// Two valid approvals — meets the MinApprovals=2 floor.
	for _, s := range r.signers[:2] {
		ci.Approvals = append(ci.Approvals, intent.ApprovalSignature{
			SignerID:  s.id,
			PublicKey: s.pub,
			Signature: ed25519.Sign(s.sec, digest[:]),
			SignedAt:  time.Date(2026, 4, 27, 11, 0, 0, 0, time.UTC),
		})
	}
	return ci
}

func TestVerify_HappyPath(t *testing.T) {
	r := newRig(t)
	if err := r.v.Verify(context.Background(), r.validIntent(t)); err != nil {
		t.Fatalf("expected pass, got %v", err)
	}
}

func TestVerify_UnknownWallet(t *testing.T) {
	r := newRig(t)
	ci := r.validIntent(t)
	ci.WalletID = "ghost"
	if err := r.v.Verify(context.Background(), ci); !errors.Is(err, ErrUnknownWallet) {
		t.Fatalf("expected ErrUnknownWallet, got %v", err)
	}
}

func TestVerify_TierMismatch(t *testing.T) {
	r := newRig(t)
	ci := r.validIntent(t)
	// rebuild approvals against a new digest after mutating the tier
	ci.WalletTier = intent.TierCold
	ci.Approvals = nil
	digest, _ := ci.Digest()
	for _, s := range r.signers[:2] {
		ci.Approvals = append(ci.Approvals, intent.ApprovalSignature{
			SignerID: s.id, PublicKey: s.pub,
			Signature: ed25519.Sign(s.sec, digest[:]),
		})
	}
	if err := r.v.Verify(context.Background(), ci); !errors.Is(err, ErrTierMismatch) {
		t.Fatalf("expected ErrTierMismatch, got %v", err)
	}
}

func TestVerify_Expired(t *testing.T) {
	r := newRig(t)
	ci := r.validIntent(t)
	ci.ExpiresAt = time.Date(2026, 4, 27, 11, 0, 0, 0, time.UTC)
	// Re-sign approvals against the new digest:
	digest, _ := ci.Digest()
	ci.Approvals = nil
	for _, s := range r.signers[:2] {
		ci.Approvals = append(ci.Approvals, intent.ApprovalSignature{
			SignerID: s.id, PublicKey: s.pub,
			Signature: ed25519.Sign(s.sec, digest[:]),
		})
	}
	if err := r.v.Verify(context.Background(), ci); !errors.Is(err, ErrExpiredIntent) {
		t.Fatalf("expected ErrExpiredIntent, got %v", err)
	}
}

func TestVerify_PolicyMismatch(t *testing.T) {
	r := newRig(t)
	ci := r.validIntent(t)
	ci.PolicyHash = [32]byte{0xff} // wrong hash
	digest, _ := ci.Digest()
	ci.Approvals = nil
	for _, s := range r.signers[:2] {
		ci.Approvals = append(ci.Approvals, intent.ApprovalSignature{
			SignerID: s.id, PublicKey: s.pub,
			Signature: ed25519.Sign(s.sec, digest[:]),
		})
	}
	if err := r.v.Verify(context.Background(), ci); !errors.Is(err, ErrPolicyMismatch) {
		t.Fatalf("expected ErrPolicyMismatch, got %v", err)
	}
}

func TestVerify_PolicyNotFound(t *testing.T) {
	r := newRig(t)
	ci := r.validIntent(t)
	ci.PolicyID = "nope"
	if err := r.v.Verify(context.Background(), ci); !errors.Is(err, ErrPolicyNotFound) {
		t.Fatalf("expected ErrPolicyNotFound, got %v", err)
	}
}

func TestVerify_InsufficientApprovals(t *testing.T) {
	r := newRig(t)
	ci := r.validIntent(t)
	ci.Approvals = ci.Approvals[:1] // only one of two required
	if err := r.v.Verify(context.Background(), ci); !errors.Is(err, ErrInsufficientApprovals) {
		t.Fatalf("expected ErrInsufficientApprovals, got %v", err)
	}
}

func TestVerify_UnknownApprovalKey_DoesNotCount(t *testing.T) {
	r := newRig(t)
	ci := r.validIntent(t)
	// Replace one valid approval with a signature from an unknown key.
	rogue := mkSigner(t, "rogue")
	digest, _ := ci.Digest()
	ci.Approvals[0] = intent.ApprovalSignature{
		SignerID:  "rogue",
		PublicKey: rogue.pub,
		Signature: ed25519.Sign(rogue.sec, digest[:]),
	}
	if err := r.v.Verify(context.Background(), ci); !errors.Is(err, ErrInsufficientApprovals) {
		t.Fatalf("expected unknown-key approval to not count: got %v", err)
	}
}

func TestVerify_TamperedSignature_DoesNotCount(t *testing.T) {
	r := newRig(t)
	ci := r.validIntent(t)
	// Flip a byte in the signature — verification must fail and the
	// approval count drops below threshold.
	ci.Approvals[0].Signature[0] ^= 0xff
	if err := r.v.Verify(context.Background(), ci); !errors.Is(err, ErrInsufficientApprovals) {
		t.Fatalf("expected tampered sig to not count: got %v", err)
	}
}

func TestVerify_DuplicateSignerNotDoubleCounted(t *testing.T) {
	r := newRig(t)
	ci := r.validIntent(t)
	// Replace second approval with the same signer as the first.
	digest, _ := ci.Digest()
	ci.Approvals[1] = intent.ApprovalSignature{
		SignerID:  r.signers[0].id,
		PublicKey: r.signers[0].pub,
		Signature: ed25519.Sign(r.signers[0].sec, digest[:]),
	}
	if err := r.v.Verify(context.Background(), ci); !errors.Is(err, ErrInsufficientApprovals) {
		t.Fatalf("expected duplicate signer to not double-count: got %v", err)
	}
}

func TestVerify_LargerAmountEscalates(t *testing.T) {
	r := newRig(t)
	ci := r.validIntent(t)
	// Bump amount above the escalation threshold (500_000_000 -> 3 required).
	ci.Amount = "600000000"
	// Re-sign with two approvers — should still fail (need 3).
	digest, _ := ci.Digest()
	ci.Approvals = nil
	for _, s := range r.signers[:2] {
		ci.Approvals = append(ci.Approvals, intent.ApprovalSignature{
			SignerID: s.id, PublicKey: s.pub,
			Signature: ed25519.Sign(s.sec, digest[:]),
		})
	}
	if err := r.v.Verify(context.Background(), ci); !errors.Is(err, ErrInsufficientApprovals) {
		t.Fatalf("expected escalation to require 3 approvals, got %v", err)
	}
	// Add a third approval — should pass.
	ci.Approvals = append(ci.Approvals, intent.ApprovalSignature{
		SignerID:  r.signers[2].id,
		PublicKey: r.signers[2].pub,
		Signature: ed25519.Sign(r.signers[2].sec, digest[:]),
	})
	if err := r.v.Verify(context.Background(), ci); err != nil {
		t.Fatalf("expected pass with 3 approvals, got %v", err)
	}
}

func TestVerify_AllowlistViolation(t *testing.T) {
	r := newRig(t)
	ci := r.validIntent(t)
	ci.To = "0xstranger"
	digest, _ := ci.Digest()
	ci.Approvals = nil
	for _, s := range r.signers[:2] {
		ci.Approvals = append(ci.Approvals, intent.ApprovalSignature{
			SignerID: s.id, PublicKey: s.pub,
			Signature: ed25519.Sign(s.sec, digest[:]),
		})
	}
	if err := r.v.Verify(context.Background(), ci); !errors.Is(err, ErrAllowlistViolation) {
		t.Fatalf("expected ErrAllowlistViolation, got %v", err)
	}
}

func TestVerify_LimitViolation(t *testing.T) {
	r := newRig(t)
	ci := r.validIntent(t)
	// MaxAmount = 1_000_000_000; bump above to trigger limit.
	ci.Amount = "10000000000" // 10x ceiling
	digest, _ := ci.Digest()
	ci.Approvals = nil
	for _, s := range r.signers {
		ci.Approvals = append(ci.Approvals, intent.ApprovalSignature{
			SignerID: s.id, PublicKey: s.pub,
			Signature: ed25519.Sign(s.sec, digest[:]),
		})
	}
	if err := r.v.Verify(context.Background(), ci); !errors.Is(err, ErrLimitViolation) {
		t.Fatalf("expected ErrLimitViolation, got %v", err)
	}
}

func TestVerify_RiskRejected(t *testing.T) {
	r := newRig(t)
	ci := r.validIntent(t)
	// Move the destination off the risk allowlist.
	r.risk.Deny("eip155:1", "0xrecip")
	if err := r.v.Verify(context.Background(), ci); !errors.Is(err, ErrRiskRejected) {
		t.Fatalf("expected ErrRiskRejected, got %v", err)
	}
}

func TestVerify_InvalidIntent(t *testing.T) {
	r := newRig(t)
	ci := r.validIntent(t)
	ci.WalletID = ""
	if err := r.v.Verify(context.Background(), ci); !errors.Is(err, ErrInvalidIntent) {
		t.Fatalf("expected ErrInvalidIntent, got %v", err)
	}
}

func TestPolicyBundle_HashStable(t *testing.T) {
	a := &PolicyBundle{
		PolicyID: "p", Version: "v",
		Tiers: map[intent.WalletTier]TierPolicy{
			intent.TierHot: {MinApprovals: 1},
		},
		Allowlist: map[string]map[string]bool{
			"eip155:1": {"0xa": true, "0xb": true},
		},
	}
	b := &PolicyBundle{
		PolicyID: "p", Version: "v",
		Tiers: map[intent.WalletTier]TierPolicy{
			intent.TierHot: {MinApprovals: 1},
		},
		Allowlist: map[string]map[string]bool{
			"eip155:1": {"0xb": true, "0xa": true},
		},
	}
	if a.Hash() != b.Hash() {
		t.Fatal("policy hash must be stable across map insertion order")
	}
}

func TestAttestation_Roundtrip(t *testing.T) {
	r := newRig(t)
	ci := r.validIntent(t)
	pub, sec, _ := ed25519.GenerateKey(rand.Reader)
	_ = pub
	att, err := r.v.AttestationFor(ci, "node0", sec, nil)
	if err != nil {
		t.Fatalf("attest: %v", err)
	}
	if att.Verdict != "approve" {
		t.Fatalf("expected approve, got %s", att.Verdict)
	}
	if err := VerifyAttestation(ci, att); err != nil {
		t.Fatalf("verify attestation: %v", err)
	}
}

func TestAttestation_RejectionEncoded(t *testing.T) {
	r := newRig(t)
	ci := r.validIntent(t)
	_, sec, _ := ed25519.GenerateKey(rand.Reader)
	att, err := r.v.AttestationFor(ci, "node0", sec, ErrAllowlistViolation)
	if err != nil {
		t.Fatalf("attest: %v", err)
	}
	if att.Verdict != "reject" {
		t.Fatalf("expected reject, got %s", att.Verdict)
	}
	if att.Reason == "" {
		t.Fatal("reject attestation must include reason")
	}
	if err := VerifyAttestation(ci, att); err != nil {
		t.Fatalf("verify attestation: %v", err)
	}
}

func TestAttestation_TamperedRejected(t *testing.T) {
	r := newRig(t)
	ci := r.validIntent(t)
	_, sec, _ := ed25519.GenerateKey(rand.Reader)
	att, _ := r.v.AttestationFor(ci, "node0", sec, nil)
	att.Verdict = "reject" // changes signed payload, sig no longer valid
	if err := VerifyAttestation(ci, att); err == nil {
		t.Fatal("expected verify failure on tampered verdict")
	}
}
