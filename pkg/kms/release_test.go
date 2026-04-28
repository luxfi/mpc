package kms

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/luxfi/mpc/cc/attest"
)

// x25519Basepoint multiplies priv by the curve25519 basepoint.
func x25519Basepoint(priv []byte) ([]byte, error) {
	return curve25519.X25519(priv, curve25519.Basepoint)
}

// fakeAttestation is a deterministic stub. Verify() succeeds iff
// expectedNonce equals the nonce captured at construction. RIM and
// hardware are caller-supplied so the test exercises Permits().
//
// VerifyEvidence simulates the cc/attest chain dispatch. Default is
// success. Set failChain=true to force a chain-verify failure — used
// by TestRelease_RefusesOnChainFailure.
//
// issuers is the set of canonical evidence-issuer strings the
// attestation envelope claims to carry. Permits() inspects this when
// ReleasePolicy.Require* flags are set. nil / empty issuers ⇒ Require*
// gates refuse.
type fakeAttestation struct {
	expectNonce [32]byte
	rim         [32]byte
	hw          [32]byte
	teePub      [32]byte
	failVerify  bool
	failChain   bool
	issuers     []string
}

func (f *fakeAttestation) Verify(expectedNonce [32]byte) (bool, error) {
	if f.failVerify {
		return false, nil
	}
	return f.expectNonce == expectedNonce, nil
}

func (f *fakeAttestation) VerifyEvidence(ctx context.Context, opts ...attest.Option) ([]*attest.VerifiedReport, error) {
	if f.failChain {
		return nil, attest.ErrChainInvalid
	}
	return []*attest.VerifiedReport{{Kind: attest.KindSEVSNP, Vendor: "amd.sev.snp"}}, nil
}
func (f *fakeAttestation) RIMDigest() [32]byte           { return f.rim }
func (f *fakeAttestation) HardwareFingerprint() [32]byte { return f.hw }
func (f *fakeAttestation) TEEPublicKey() [32]byte        { return f.teePub }
func (f *fakeAttestation) EvidenceIssuers() []string     { return f.issuers }

func mustRand(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}

func newTestGate(t *testing.T) (*LocalReleaseGate, *MemoryNonceStore, [32]byte, [32]byte, [32]byte) {
	t.Helper()
	var rim, hw [32]byte
	copy(rim[:], mustRand(t, 32))
	copy(hw[:], mustRand(t, 32))
	policy := NewReleasePolicy([][32]byte{rim}, [][32]byte{hw})

	var rootKey [32]byte
	copy(rootKey[:], mustRand(t, 32))
	store := NewMemoryNonceStore()
	gate, err := NewLocalReleaseGate(policy, store, rootKey)
	if err != nil {
		t.Fatalf("NewLocalReleaseGate: %v", err)
	}
	var teePub [32]byte
	priv := mustRand(t, 32)
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pub, err := curve25519X25519Basepoint(priv)
	if err != nil {
		t.Fatalf("curve25519: %v", err)
	}
	copy(teePub[:], pub)
	return gate, store, rim, hw, teePub
}

func curve25519X25519Basepoint(priv []byte) ([]byte, error) {
	return x25519Basepoint(priv)
}

// Test 1: Issue → Release with matching nonce → success.
func TestRelease_HappyPath(t *testing.T) {
	gate, _, rim, hw, teePub := newTestGate(t)
	var jobID [32]byte
	copy(jobID[:], mustRand(t, 32))

	nonce, epoch, err := gate.Issue(jobID)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if epoch != 1 {
		t.Fatalf("epoch: got %d want 1", epoch)
	}

	att := &fakeAttestation{expectNonce: nonce, rim: rim, hw: hw, teePub: teePub}
	sealed, err := gate.Release(ReleaseRequest{
		JobID: jobID, Epoch: epoch, Nonce: nonce, Attestation: att,
	})
	if err != nil {
		t.Fatalf("Release: %v", err)
	}
	if sealed.IssuedNonce != nonce {
		t.Fatalf("IssuedNonce mismatch in sealed output")
	}
	if sealed.Epoch != epoch || sealed.JobID != jobID {
		t.Fatalf("sealed metadata mismatch")
	}
}

// Test 2: Issue → Release with wrong nonce → ErrNonceMismatch.
func TestRelease_WrongNonce(t *testing.T) {
	gate, _, rim, hw, teePub := newTestGate(t)
	var jobID [32]byte
	copy(jobID[:], mustRand(t, 32))

	nonce, epoch, err := gate.Issue(jobID)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	var forged [32]byte
	copy(forged[:], mustRand(t, 32))
	if forged == nonce {
		t.Fatalf("test setup: forged equals issued (re-roll)")
	}
	att := &fakeAttestation{expectNonce: forged, rim: rim, hw: hw, teePub: teePub}
	_, err = gate.Release(ReleaseRequest{
		JobID: jobID, Epoch: epoch, Nonce: forged, Attestation: att,
	})
	if err == nil {
		t.Fatalf("Release: expected error, got nil")
	}
	if !errors.Is(err, ErrPolicyRefused) {
		t.Fatalf("Release: expected ErrPolicyRefused, got %v", err)
	}
	if !errors.Is(err, ErrNonceMismatch) {
		t.Fatalf("Release: expected ErrNonceMismatch wrapped, got %v", err)
	}
}

// Test 3: Issue → KMS restart → Release still works.
func TestRelease_SurvivesRestart(t *testing.T) {
	policy := NewReleasePolicy(
		[][32]byte{[32]byte(mustRand(t, 32))},
		[][32]byte{[32]byte(mustRand(t, 32))},
	)
	for k := range policy.RequiredRIM {
		_ = k
	}
	var rootKey [32]byte
	copy(rootKey[:], mustRand(t, 32))
	store := NewMemoryNonceStore()

	g1, err := NewLocalReleaseGate(policy, store, rootKey)
	if err != nil {
		t.Fatalf("NewLocalReleaseGate: %v", err)
	}
	var jobID [32]byte
	copy(jobID[:], mustRand(t, 32))
	nonce, epoch, err := g1.Issue(jobID)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	g2, err := NewLocalReleaseGate(policy, store, rootKey)
	if err != nil {
		t.Fatalf("NewLocalReleaseGate (restart): %v", err)
	}

	var rim, hw [32]byte
	for k := range policy.RequiredRIM {
		rim = k
		break
	}
	for k := range policy.AllowedHardware {
		hw = k
		break
	}

	priv := mustRand(t, 32)
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pub, err := x25519Basepoint(priv)
	if err != nil {
		t.Fatalf("curve25519: %v", err)
	}
	var teePub [32]byte
	copy(teePub[:], pub)
	att := &fakeAttestation{expectNonce: nonce, rim: rim, hw: hw, teePub: teePub}
	if _, err := g2.Release(ReleaseRequest{
		JobID: jobID, Epoch: epoch, Nonce: nonce, Attestation: att,
	}); err != nil {
		t.Fatalf("Release after restart: %v", err)
	}
}

// Test 4: Issue → Release → second Release with same JobID/Nonce →
// ErrAlreadyConsumed.
func TestRelease_AlreadyConsumed(t *testing.T) {
	gate, _, rim, hw, teePub := newTestGate(t)
	var jobID [32]byte
	copy(jobID[:], mustRand(t, 32))

	nonce, epoch, err := gate.Issue(jobID)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	att := &fakeAttestation{expectNonce: nonce, rim: rim, hw: hw, teePub: teePub}
	if _, err := gate.Release(ReleaseRequest{
		JobID: jobID, Epoch: epoch, Nonce: nonce, Attestation: att,
	}); err != nil {
		t.Fatalf("Release #1: %v", err)
	}

	_, err = gate.Release(ReleaseRequest{
		JobID: jobID, Epoch: epoch, Nonce: nonce, Attestation: att,
	})
	if err == nil {
		t.Fatalf("Release #2: expected error, got nil")
	}
	if !errors.Is(err, ErrPolicyRefused) {
		t.Fatalf("Release #2: expected ErrPolicyRefused, got %v", err)
	}
	if !errors.Is(err, ErrAlreadyConsumed) {
		t.Fatalf("Release #2: expected ErrAlreadyConsumed wrapped, got %v", err)
	}
}

// Test 5: Time-expired nonce → GC removes → Release → ErrExpired.
func TestRelease_Expired(t *testing.T) {
	gate, _, rim, hw, teePub := newTestGate(t)
	gate.SetIssueTTL(10 * time.Millisecond)

	var jobID [32]byte
	copy(jobID[:], mustRand(t, 32))
	nonce, epoch, err := gate.Issue(jobID)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	att := &fakeAttestation{expectNonce: nonce, rim: rim, hw: hw, teePub: teePub}
	_, err = gate.Release(ReleaseRequest{
		JobID: jobID, Epoch: epoch, Nonce: nonce, Attestation: att,
	})
	if err == nil {
		t.Fatalf("Release: expected expiry error, got nil")
	}
	if !errors.Is(err, ErrPolicyRefused) {
		t.Fatalf("Release: expected ErrPolicyRefused, got %v", err)
	}
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("Release: expected ErrExpired wrapped, got %v", err)
	}

	if err := gate.GC(); err != nil {
		t.Fatalf("GC: %v", err)
	}
	_, err = gate.Release(ReleaseRequest{
		JobID: jobID, Epoch: epoch, Nonce: nonce, Attestation: att,
	})
	if !errors.Is(err, ErrPolicyRefused) {
		t.Fatalf("Release post-GC: expected ErrPolicyRefused, got %v", err)
	}
}

func TestNonce_BoundToJobID(t *testing.T) {
	gate, _, _, _, _ := newTestGate(t)

	var jobA, jobB [32]byte
	copy(jobA[:], mustRand(t, 32))
	copy(jobB[:], mustRand(t, 32))

	nA, _, err := gate.Issue(jobA)
	if err != nil {
		t.Fatalf("Issue A: %v", err)
	}
	nB, _, err := gate.Issue(jobB)
	if err != nil {
		t.Fatalf("Issue B: %v", err)
	}
	if nA == nB {
		t.Fatalf("nonces collided across jobIDs (HMAC binding broken)")
	}
}

func TestAAD_BindsIssuedNonce(t *testing.T) {
	var jobID, n1, n2, teePub [32]byte
	copy(jobID[:], mustRand(t, 32))
	copy(n1[:], mustRand(t, 32))
	copy(n2[:], mustRand(t, 32))
	copy(teePub[:], mustRand(t, 32))

	a := SealedSessionKey{Epoch: 1, JobID: jobID, IssuedNonce: n1}
	b := SealedSessionKey{Epoch: 1, JobID: jobID, IssuedNonce: n2}
	aadA := a.AAD(teePub)
	aadB := b.AAD(teePub)
	if string(aadA) == string(aadB) {
		t.Fatalf("AAD did not bind IssuedNonce (collision)")
	}
}

// Test (Red Final N1): an attestation that passes the cheap nonce
// Verify() but FAILS the cc/attest chain verifier (AMD KDS / VCEK,
// NRAS, TDX) MUST be refused. Without the chain step a worker can
// craft a forged envelope whose Verify(nonce) returns true but whose
// evidence blobs do not chain to the pinned vendor root, harvesting a
// session key.
func TestRelease_RefusesOnChainFailure(t *testing.T) {
	gate, _, rim, hw, teePub := newTestGate(t)
	var jobID [32]byte
	copy(jobID[:], mustRand(t, 32))

	nonce, epoch, err := gate.Issue(jobID)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// nonce binding passes (failVerify=false) but the chain check
	// fails — the forged-evidence path the audit flagged.
	att := &fakeAttestation{
		expectNonce: nonce,
		rim:         rim,
		hw:          hw,
		teePub:      teePub,
		failVerify:  false,
		failChain:   true,
	}
	_, err = gate.Release(ReleaseRequest{
		JobID:       jobID,
		Epoch:       epoch,
		Nonce:       nonce,
		Attestation: att,
	})
	if err == nil {
		t.Fatalf("Release: expected chain-verify refusal, got nil")
	}
	if !errors.Is(err, ErrPolicyRefused) {
		t.Fatalf("Release: expected ErrPolicyRefused wrapped, got %v", err)
	}
	if !errors.Is(err, ErrAttestationChain) {
		t.Fatalf("Release: expected ErrAttestationChain wrapped, got %v", err)
	}
}

// Test (Red Final N1, paired): the SAME attestation with chain check
// passing must succeed.
func TestRelease_AcceptsOnChainPass(t *testing.T) {
	gate, _, rim, hw, teePub := newTestGate(t)
	var jobID [32]byte
	copy(jobID[:], mustRand(t, 32))

	nonce, epoch, err := gate.Issue(jobID)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	att := &fakeAttestation{
		expectNonce: nonce,
		rim:         rim,
		hw:          hw,
		teePub:      teePub,
		failChain:   false,
	}
	if _, err := gate.Release(ReleaseRequest{
		JobID:       jobID,
		Epoch:       epoch,
		Nonce:       nonce,
		Attestation: att,
	}); err != nil {
		t.Fatalf("Release: expected success, got %v", err)
	}
}

// newRequireFlagPolicy builds a policy with all three Require* flags set
// to true (production posture per #203 O5 fix). Any test that asserts
// strict default-deny behavior calls this.
func newRequireFlagPolicy(rim, hw [32]byte) ReleasePolicy {
	return NewReleasePolicyStrict([][32]byte{rim}, [][32]byte{hw})
}

// Test: happy path — SEV-SNP + TDX + NVNRAS all present + valid →
// Permits returns true. Asserts the strict policy posture accepts a
// fully attested envelope.
func TestPermits_RequireFlags_AllPresent(t *testing.T) {
	var rim, hw, teePub [32]byte
	copy(rim[:], mustRand(t, 32))
	copy(hw[:], mustRand(t, 32))
	copy(teePub[:], mustRand(t, 32))

	policy := newRequireFlagPolicy(rim, hw)
	att := &fakeAttestation{
		rim:    rim,
		hw:     hw,
		teePub: teePub,
		issuers: []string{
			IssuerSEVSNP,
			IssuerTDX,
			IssuerNVNRAS,
		},
	}
	if !policy.Permits(att) {
		t.Fatalf("Permits: strict policy rejected envelope with all required issuers present")
	}
}

// Test: missing SEV-SNP when RequireSEVSNP=true → Permits refuses.
// Default-deny: a strict policy MUST refuse if the SEV-SNP CPU TEE
// quote is absent, even when TDX and NVNRAS are present.
func TestPermits_RequireFlags_MissingSEVSNP(t *testing.T) {
	var rim, hw, teePub [32]byte
	copy(rim[:], mustRand(t, 32))
	copy(hw[:], mustRand(t, 32))
	copy(teePub[:], mustRand(t, 32))

	policy := newRequireFlagPolicy(rim, hw)
	att := &fakeAttestation{
		rim:     rim,
		hw:      hw,
		teePub:  teePub,
		issuers: []string{IssuerTDX, IssuerNVNRAS}, // no SEV-SNP
	}
	if policy.Permits(att) {
		t.Fatalf("Permits: strict policy accepted envelope missing SEV-SNP")
	}
}

// Test: missing TDX when RequireTDX=true → Permits refuses.
func TestPermits_RequireFlags_MissingTDX(t *testing.T) {
	var rim, hw, teePub [32]byte
	copy(rim[:], mustRand(t, 32))
	copy(hw[:], mustRand(t, 32))
	copy(teePub[:], mustRand(t, 32))

	policy := newRequireFlagPolicy(rim, hw)
	att := &fakeAttestation{
		rim:     rim,
		hw:      hw,
		teePub:  teePub,
		issuers: []string{IssuerSEVSNP, IssuerNVNRAS}, // no TDX
	}
	if policy.Permits(att) {
		t.Fatalf("Permits: strict policy accepted envelope missing TDX")
	}
}

// Test: missing NVNRAS when RequireNVNRAS=true → Permits refuses.
// Empty issuer list also tests the nil-slice path: Permits MUST treat
// an attestation that publishes no evidence issuers as a hard refusal
// under any Require* flag.
func TestPermits_RequireFlags_MissingNVNRAS(t *testing.T) {
	var rim, hw, teePub [32]byte
	copy(rim[:], mustRand(t, 32))
	copy(hw[:], mustRand(t, 32))
	copy(teePub[:], mustRand(t, 32))

	policy := newRequireFlagPolicy(rim, hw)
	att := &fakeAttestation{
		rim:     rim,
		hw:      hw,
		teePub:  teePub,
		issuers: []string{IssuerSEVSNP, IssuerTDX}, // no NVNRAS
	}
	if policy.Permits(att) {
		t.Fatalf("Permits: strict policy accepted envelope missing NVNRAS")
	}

	// Belt-and-suspenders: empty issuer list ⇒ refuse.
	att2 := &fakeAttestation{rim: rim, hw: hw, teePub: teePub, issuers: nil}
	if policy.Permits(att2) {
		t.Fatalf("Permits: strict policy accepted envelope with no issuers at all")
	}
}
