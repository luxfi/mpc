// release_nonce_test.go — Red audit F2 / Blue B4 regression suite.
//
// The spec'd 5 cases (every one MUST refuse the release):
//
//  1. Round-trip       — Issue(epoch=1, jobID=A) → Release(A, returnedNonce) → success
//  2. Wrong nonce      — Issue → Release with random nonce ≠ issued       → ErrNonceMismatch
//  3. Cross-job replay — Issue(jobID=A, nonce=X) → Release(jobID=B, X)     → ErrNonceMismatch / unknown
//  4. Cross-epoch reuse— Issue(epoch=1, A) → Rotate → Release(epoch=2, A)  → ErrPolicyRefused (epoch mismatch)
//  5. Double-Release   — Issue → Release → Release                         → ErrAlreadyConsumed
//
// All five share fakeAttestation + newTestGate from release_test.go.
package kms

import (
	"errors"
	"testing"
)

// 1. Round-trip: nonce returned by Issue must satisfy Release.
func TestNonceBind_RoundTrip(t *testing.T) {
	gate, _, rim, hw, teePub := newTestGate(t)
	var jobID [32]byte
	copy(jobID[:], mustRand(t, 32))

	nonce, epoch, err := gate.Issue(jobID)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	att := &fakeAttestation{expectNonce: nonce, rim: rim, hw: hw, teePub: teePub}
	sealed, err := gate.Release(ReleaseRequest{
		JobID: jobID, Epoch: epoch, Nonce: nonce, Attestation: att,
	})
	if err != nil {
		t.Fatalf("Release: %v", err)
	}
	if sealed.IssuedNonce != nonce {
		t.Fatalf("sealed.IssuedNonce != issued nonce")
	}
}

// 2. Wrong nonce: a worker-chosen / forged nonce ≠ issued must refuse.
func TestNonceBind_WrongNonce(t *testing.T) {
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
	if !errors.Is(err, ErrPolicyRefused) {
		t.Fatalf("expected ErrPolicyRefused, got %v", err)
	}
	if !errors.Is(err, ErrNonceMismatch) {
		t.Fatalf("expected ErrNonceMismatch wrapped, got %v", err)
	}
}

// 3. Cross-job replay: Issue(A) → Release(B, nonceA) MUST refuse.
//
// This is the F2 / B4 finding directly: an attacker who observes a nonce
// issued for jobID A must not be able to redeem it under jobID B. With
// HMAC binding, nonceA is bound to A in the gate's pending map, and
// Lookup(B) either returns ErrNonceUnknown (B was never issued) or, if B
// was also issued, the stored nonceB ≠ nonceA so hmac.Equal refuses.
func TestNonceBind_CrossJobReplay(t *testing.T) {
	gate, _, rim, hw, teePub := newTestGate(t)
	var jobA, jobB [32]byte
	copy(jobA[:], mustRand(t, 32))
	copy(jobB[:], mustRand(t, 32))

	nonceA, epoch, err := gate.Issue(jobA)
	if err != nil {
		t.Fatalf("Issue A: %v", err)
	}

	// Attempt 1: jobB never issued — must refuse with "unknown".
	att := &fakeAttestation{expectNonce: nonceA, rim: rim, hw: hw, teePub: teePub}
	_, err = gate.Release(ReleaseRequest{
		JobID: jobB, Epoch: epoch, Nonce: nonceA, Attestation: att,
	})
	if !errors.Is(err, ErrPolicyRefused) {
		t.Fatalf("Release(B, nonceA, B-not-issued): expected ErrPolicyRefused, got %v", err)
	}

	// Attempt 2: issue B too, then replay A's nonce against B — must
	// refuse with ErrNonceMismatch (stored nonceB ≠ nonceA).
	nonceB, _, err := gate.Issue(jobB)
	if err != nil {
		t.Fatalf("Issue B: %v", err)
	}
	if nonceA == nonceB {
		t.Fatalf("HMAC binding broken: nonces collide across jobIDs")
	}
	_, err = gate.Release(ReleaseRequest{
		JobID: jobB, Epoch: epoch, Nonce: nonceA, Attestation: att,
	})
	if !errors.Is(err, ErrPolicyRefused) {
		t.Fatalf("Release(B, nonceA, both-issued): expected ErrPolicyRefused, got %v", err)
	}
	if !errors.Is(err, ErrNonceMismatch) {
		t.Fatalf("Release(B, nonceA, both-issued): expected ErrNonceMismatch, got %v", err)
	}
}

// 4. Cross-epoch replay: Issue at epoch=N → Rotate → Release at epoch=N+1
// MUST refuse on epoch mismatch. The gate-stored record carries epoch=N;
// the request carries epoch=N+1 (or epoch=N which now mismatches the
// gate's current epoch). Either path is a hard refusal.
func TestNonceBind_CrossEpochReplay(t *testing.T) {
	gate, _, rim, hw, teePub := newTestGate(t)
	var jobID [32]byte
	copy(jobID[:], mustRand(t, 32))

	nonceOld, oldEpoch, err := gate.Issue(jobID)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if oldEpoch != 1 {
		t.Fatalf("oldEpoch: got %d want 1", oldEpoch)
	}

	newEpoch := gate.Rotate()
	if newEpoch != oldEpoch+1 {
		t.Fatalf("Rotate: got %d want %d", newEpoch, oldEpoch+1)
	}

	att := &fakeAttestation{expectNonce: nonceOld, rim: rim, hw: hw, teePub: teePub}

	// Path A: replay with the OLD epoch — gate's current epoch is N+1, so
	// req.Epoch (N) mismatches the live epoch.
	_, err = gate.Release(ReleaseRequest{
		JobID: jobID, Epoch: oldEpoch, Nonce: nonceOld, Attestation: att,
	})
	if !errors.Is(err, ErrPolicyRefused) {
		t.Fatalf("Release(oldEpoch): expected ErrPolicyRefused, got %v", err)
	}

	// Path B: claim the NEW epoch — gate Lookup finds the stored record
	// at oldEpoch, mismatch on rec.Epoch refuses.
	_, err = gate.Release(ReleaseRequest{
		JobID: jobID, Epoch: newEpoch, Nonce: nonceOld, Attestation: att,
	})
	if !errors.Is(err, ErrPolicyRefused) {
		t.Fatalf("Release(newEpoch, oldNonce): expected ErrPolicyRefused, got %v", err)
	}
}

// 5. Double-Release: Issue → Release → Release MUST refuse the second
// call with ErrAlreadyConsumed. Consume-once semantics — a captured
// sealed token is single-use, even if the token itself is replayable
// off-chain.
func TestNonceBind_DoubleRelease(t *testing.T) {
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
	if !errors.Is(err, ErrPolicyRefused) {
		t.Fatalf("Release #2: expected ErrPolicyRefused, got %v", err)
	}
	if !errors.Is(err, ErrAlreadyConsumed) {
		t.Fatalf("Release #2: expected ErrAlreadyConsumed wrapped, got %v", err)
	}
}
