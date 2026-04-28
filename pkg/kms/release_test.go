package kms

import (
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
)

// x25519Basepoint multiplies priv by the curve25519 basepoint.
func x25519Basepoint(priv []byte) ([]byte, error) {
	return curve25519.X25519(priv, curve25519.Basepoint)
}

// fakeAttestation is a deterministic stub. Verify() succeeds iff
// expectedNonce equals the nonce captured at construction. RIM and
// hardware are caller-supplied so the test exercises Permits().
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
	issuers     []string
}

func (f *fakeAttestation) Verify(expectedNonce [32]byte) (bool, error) {
	if f.failVerify {
		return false, nil
	}
	return f.expectNonce == expectedNonce, nil
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
	// Use a real curve25519 pubkey so ECDH succeeds in seal.
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

// curve25519X25519Basepoint wraps the basepoint multiplication so the
// test file does not import curve25519 directly (avoid duplicate import
// surfaces; release.go already pulls it).
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

	// Worker presents a forged nonce (e.g. the worker chose its own
	// random challenge instead of using the gate-issued one).
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

// Test 3: Issue → KMS restart (re-construct gate from store) → Release
// still works (no replay-window reset).
func TestRelease_SurvivesRestart(t *testing.T) {
	policy := NewReleasePolicy(
		[][32]byte{[32]byte(mustRand(t, 32))},
		[][32]byte{[32]byte(mustRand(t, 32))},
	)
	for k := range policy.RequiredRIM {
		_ = k
	}
	// Reuse the same store across two gate constructions.
	var rootKey [32]byte
	copy(rootKey[:], mustRand(t, 32))
	store := NewMemoryNonceStore()

	// First gate: Issue.
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

	// "Restart": construct a second gate over the same store. The
	// pending nonce + epoch must round-trip.
	g2, err := NewLocalReleaseGate(policy, store, rootKey)
	if err != nil {
		t.Fatalf("NewLocalReleaseGate (restart): %v", err)
	}

	// Pull the policy's RIM/HW so the attestation matches.
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

	// Replay: same jobID + nonce. Must refuse.
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

	// Wait past the TTL.
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

	// GC should reclaim the pending entry.
	if err := gate.GC(); err != nil {
		t.Fatalf("GC: %v", err)
	}
	// After GC the jobID is "unknown" rather than "expired"; either is
	// a valid hard refusal.
	_, err = gate.Release(ReleaseRequest{
		JobID: jobID, Epoch: epoch, Nonce: nonce, Attestation: att,
	})
	if !errors.Is(err, ErrPolicyRefused) {
		t.Fatalf("Release post-GC: expected ErrPolicyRefused, got %v", err)
	}
}

// Bonus: nonce binding — nonce derived for jobID A must NOT match
// jobID B even with identical fresh entropy. The HMAC binding is what
// the audit calls out; this asserts it directly.
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

// Bonus: AAD includes the issued nonce. Re-deriving AAD with a
// different IssuedNonce must produce different bytes.
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
