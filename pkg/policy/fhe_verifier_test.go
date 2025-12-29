package policy

import (
	"context"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/luxfi/mpc/pkg/intent"
)

// fakeFChain returns a fixed encrypted result regardless of input. The
// test pairs it with a fakeDecryptor that maps the bytes to a bool.
type fakeFChain struct {
	encResult []byte
	err       error
	calls     int
	gotWallet string
	gotAmount *big.Int
	gotVel    *big.Int
}

func (f *fakeFChain) EvaluateLatest(ctx context.Context, walletID string, amount *big.Int, _ [32]byte, vel *big.Int) ([]byte, error) {
	f.calls++
	f.gotWallet = walletID
	f.gotAmount = amount
	f.gotVel = vel
	return f.encResult, f.err
}

type fakeDecryptor struct {
	allowed bool
	err     error
	calls   int
	got     []byte
}

func (d *fakeDecryptor) Decrypt(ctx context.Context, ct []byte) (bool, error) {
	d.calls++
	d.got = ct
	return d.allowed, d.err
}

type fakeVelocity struct {
	total *big.Int
	err   error
}

func (v *fakeVelocity) WindowSpend(ctx context.Context, _ string, _ string) (*big.Int, error) {
	return v.total, v.err
}

type fakeRegistry struct {
	wallets map[string]Wallet
}

func (r *fakeRegistry) Get(id string) (Wallet, bool) {
	w, ok := r.wallets[id]
	return w, ok
}

func validIntent() *intent.CanonicalIntent {
	return &intent.CanonicalIntent{
		IntentVersion: intent.IntentVersion,
		SessionID:     "sess-1",
		WalletID:      "w-1",
		WalletTier:    intent.TierHot,
		Chain:         "eip155:1",
		Asset:         "ETH",
		From:          "0xfrom",
		To:            "0xto",
		Amount:        "1000",
		MaxFee:        "100",
		Nonce:         "1",
		HumanSummary:  "test",
		PolicyID:      "p-1",
		RiskVerdictID: "r-1",
		ExpiresAt:     time.Now().Add(1 * time.Hour),
	}
}

// TestFHEVerifier_AllowPath verifies the happy path: F-Chain returns
// encrypted "true", decryptor returns true, verifier returns nil.
func TestFHEVerifier_AllowPath(t *testing.T) {
	fc := &fakeFChain{encResult: []byte("ENC_TRUE")}
	dec := &fakeDecryptor{allowed: true}
	vel := &fakeVelocity{total: big.NewInt(0)}
	reg := &fakeRegistry{wallets: map[string]Wallet{
		"w-1": {WalletID: "w-1", Tier: intent.TierHot, Chain: "eip155:1"},
	}}

	v := NewFHEVerifier(reg, fc, dec, vel)
	if err := v.Verify(context.Background(), validIntent()); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if fc.calls != 1 {
		t.Errorf("FChain calls: got %d, want 1", fc.calls)
	}
	if dec.calls != 1 {
		t.Errorf("Decryptor calls: got %d, want 1", dec.calls)
	}
	if string(dec.got) != "ENC_TRUE" {
		t.Errorf("Decryptor got %q, want ENC_TRUE", dec.got)
	}
}

// TestFHEVerifier_DenyPath verifies that an encrypted-deny verdict produces
// ErrFHEVerdictDeny.
func TestFHEVerifier_DenyPath(t *testing.T) {
	fc := &fakeFChain{encResult: []byte("ENC_FALSE")}
	dec := &fakeDecryptor{allowed: false}
	vel := &fakeVelocity{total: big.NewInt(0)}
	reg := &fakeRegistry{wallets: map[string]Wallet{
		"w-1": {WalletID: "w-1", Tier: intent.TierHot, Chain: "eip155:1"},
	}}

	v := NewFHEVerifier(reg, fc, dec, vel)
	err := v.Verify(context.Background(), validIntent())
	if !errors.Is(err, ErrFHEVerdictDeny) {
		t.Fatalf("expected ErrFHEVerdictDeny, got %v", err)
	}
}

// TestFHEVerifier_FailsClosedOnDecryptError ensures the verifier denies
// rather than allowing when the threshold-decrypt round errors.
func TestFHEVerifier_FailsClosedOnDecryptError(t *testing.T) {
	fc := &fakeFChain{encResult: []byte("ENC")}
	dec := &fakeDecryptor{allowed: true, err: errors.New("decrypt unavailable")}
	vel := &fakeVelocity{total: big.NewInt(0)}
	reg := &fakeRegistry{wallets: map[string]Wallet{
		"w-1": {WalletID: "w-1", Tier: intent.TierHot, Chain: "eip155:1"},
	}}

	v := NewFHEVerifier(reg, fc, dec, vel)
	err := v.Verify(context.Background(), validIntent())
	if !errors.Is(err, ErrFHEThresholdDec) {
		t.Fatalf("expected ErrFHEThresholdDec, got %v", err)
	}
}

// TestFHEVerifier_FailsClosedOnEvalError ensures F-Chain eval errors
// produce ErrFHEPolicyEval (not a leaky generic error).
func TestFHEVerifier_FailsClosedOnEvalError(t *testing.T) {
	fc := &fakeFChain{err: errors.New("F-Chain unreachable")}
	dec := &fakeDecryptor{}
	vel := &fakeVelocity{total: big.NewInt(0)}
	reg := &fakeRegistry{wallets: map[string]Wallet{
		"w-1": {WalletID: "w-1", Tier: intent.TierHot, Chain: "eip155:1"},
	}}

	v := NewFHEVerifier(reg, fc, dec, vel)
	err := v.Verify(context.Background(), validIntent())
	if !errors.Is(err, ErrFHEPolicyEval) {
		t.Fatalf("expected ErrFHEPolicyEval, got %v", err)
	}
	if dec.calls != 0 {
		t.Errorf("Decryptor must not be called when eval fails; got %d calls", dec.calls)
	}
}

// TestFHEVerifier_RejectsExpiredIntent verifies expiry is checked before
// the (expensive) FHE round.
func TestFHEVerifier_RejectsExpiredIntent(t *testing.T) {
	fc := &fakeFChain{encResult: []byte("ENC")}
	dec := &fakeDecryptor{allowed: true}
	vel := &fakeVelocity{total: big.NewInt(0)}
	reg := &fakeRegistry{wallets: map[string]Wallet{
		"w-1": {WalletID: "w-1", Tier: intent.TierHot, Chain: "eip155:1"},
	}}

	ci := validIntent()
	ci.ExpiresAt = time.Now().Add(-1 * time.Hour)

	v := NewFHEVerifier(reg, fc, dec, vel)
	err := v.Verify(context.Background(), ci)
	if !errors.Is(err, ErrExpiredIntent) {
		t.Fatalf("expected ErrExpiredIntent, got %v", err)
	}
	if fc.calls != 0 {
		t.Errorf("FChain must not be called for expired intent; got %d calls", fc.calls)
	}
}

// TestFHEVerifier_RejectsUnknownWallet verifies the registry check.
func TestFHEVerifier_RejectsUnknownWallet(t *testing.T) {
	fc := &fakeFChain{encResult: []byte("ENC")}
	dec := &fakeDecryptor{allowed: true}
	vel := &fakeVelocity{total: big.NewInt(0)}
	reg := &fakeRegistry{wallets: map[string]Wallet{}}

	v := NewFHEVerifier(reg, fc, dec, vel)
	err := v.Verify(context.Background(), validIntent())
	if !errors.Is(err, ErrUnknownWallet) {
		t.Fatalf("expected ErrUnknownWallet, got %v", err)
	}
}

// TestFHEVerifier_RejectsTierMismatch verifies the tier-bind check.
func TestFHEVerifier_RejectsTierMismatch(t *testing.T) {
	fc := &fakeFChain{encResult: []byte("ENC")}
	dec := &fakeDecryptor{allowed: true}
	vel := &fakeVelocity{total: big.NewInt(0)}
	reg := &fakeRegistry{wallets: map[string]Wallet{
		"w-1": {WalletID: "w-1", Tier: intent.TierCold, Chain: "eip155:1"},
	}}

	v := NewFHEVerifier(reg, fc, dec, vel)
	err := v.Verify(context.Background(), validIntent())
	if !errors.Is(err, ErrTierMismatch) {
		t.Fatalf("expected ErrTierMismatch, got %v", err)
	}
}

// TestFHEVerifier_RejectsMissingDeps verifies that misconfigured verifiers
// fail closed at the first call rather than at random later runtime.
func TestFHEVerifier_RejectsMissingDeps(t *testing.T) {
	v := &FHEVerifier{}
	err := v.Verify(context.Background(), validIntent())
	if !errors.Is(err, ErrFHEClientRequired) {
		t.Fatalf("expected ErrFHEClientRequired, got %v", err)
	}

	v = &FHEVerifier{FChain: &fakeFChain{}}
	err = v.Verify(context.Background(), validIntent())
	if !errors.Is(err, ErrFHEDecRequired) {
		t.Fatalf("expected ErrFHEDecRequired, got %v", err)
	}
}

// fakePlan is the rule-engine path counterpart to fakeFChain. It records
// the (policyID, policyHash) plus the encrypted-equivalent intent fields
// the verifier hands to the plan, and returns a fixed verdict.
type fakePlan struct {
	encResult     []byte
	err           error
	calls         int
	gotPolicyID   string
	gotPolicyHash [32]byte
	gotWallet     string
	gotAmount     *big.Int
	gotVel        *big.Int
}

func (p *fakePlan) EvaluatePlan(
	_ context.Context,
	policyID string,
	policyHash [32]byte,
	walletID string,
	amount *big.Int,
	_ [32]byte,
	vel *big.Int,
) ([]byte, error) {
	p.calls++
	p.gotPolicyID = policyID
	p.gotPolicyHash = policyHash
	p.gotWallet = walletID
	p.gotAmount = amount
	p.gotVel = vel
	return p.encResult, p.err
}

// TestFHEVerifier_PlanPathPrefersPlan asserts that when both Plan and
// FChain are wired, Verify uses Plan and never touches FChain. This
// is what shipping the rule engine in production will look like.
func TestFHEVerifier_PlanPathPrefersPlan(t *testing.T) {
	pp := &fakePlan{encResult: []byte("ENC_TRUE_PLAN")}
	fc := &fakeFChain{encResult: []byte("ENC_TRUE_FCHAIN")}
	dec := &fakeDecryptor{allowed: true}
	vel := &fakeVelocity{total: big.NewInt(0)}
	reg := &fakeRegistry{wallets: map[string]Wallet{
		"w-1": {WalletID: "w-1", Tier: intent.TierHot, Chain: "eip155:1"},
	}}

	v := NewFHEVerifierWithPlan(reg, pp, dec, vel)
	v.FChain = fc // both wired

	if err := v.Verify(context.Background(), validIntent()); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if pp.calls != 1 {
		t.Errorf("Plan calls: got %d, want 1", pp.calls)
	}
	if fc.calls != 0 {
		t.Errorf("FChain must not be called when Plan is set; got %d", fc.calls)
	}
	if dec.calls != 1 {
		t.Errorf("Decryptor calls: got %d, want 1", dec.calls)
	}
	if string(dec.got) != "ENC_TRUE_PLAN" {
		t.Errorf("Decryptor got %q, want ENC_TRUE_PLAN", dec.got)
	}
	if pp.gotPolicyID != "p-1" {
		t.Errorf("Plan policyID: got %q, want p-1", pp.gotPolicyID)
	}
}

// TestFHEVerifier_PlanPathDeny exercises the deny path through the plan
// provider — encrypted-false from the plan, threshold-decryptor returns
// false, verifier returns ErrFHEVerdictDeny.
func TestFHEVerifier_PlanPathDeny(t *testing.T) {
	pp := &fakePlan{encResult: []byte("ENC_FALSE")}
	dec := &fakeDecryptor{allowed: false}
	vel := &fakeVelocity{total: big.NewInt(0)}
	reg := &fakeRegistry{wallets: map[string]Wallet{
		"w-1": {WalletID: "w-1", Tier: intent.TierHot, Chain: "eip155:1"},
	}}

	v := NewFHEVerifierWithPlan(reg, pp, dec, vel)
	err := v.Verify(context.Background(), validIntent())
	if !errors.Is(err, ErrFHEVerdictDeny) {
		t.Fatalf("expected ErrFHEVerdictDeny, got %v", err)
	}
}

// TestFHEVerifier_PlanPathFailClosed verifies that plan-eval errors map
// to ErrFHEPolicyEval — same posture as the FChain path.
func TestFHEVerifier_PlanPathFailClosed(t *testing.T) {
	pp := &fakePlan{err: errors.New("plan: cache miss + load failed")}
	dec := &fakeDecryptor{}
	vel := &fakeVelocity{total: big.NewInt(0)}
	reg := &fakeRegistry{wallets: map[string]Wallet{
		"w-1": {WalletID: "w-1", Tier: intent.TierHot, Chain: "eip155:1"},
	}}

	v := NewFHEVerifierWithPlan(reg, pp, dec, vel)
	err := v.Verify(context.Background(), validIntent())
	if !errors.Is(err, ErrFHEPolicyEval) {
		t.Fatalf("expected ErrFHEPolicyEval, got %v", err)
	}
	if dec.calls != 0 {
		t.Errorf("Decryptor must not be called when eval fails; got %d", dec.calls)
	}
}
