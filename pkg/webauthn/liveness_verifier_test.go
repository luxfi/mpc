package webauthn

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

// TestEd25519EnvelopeVerifier confirms the OSS-default Verifier delegates to
// the audited VerifyLiveness path and that a Binding maps through cleanly.
func TestEd25519EnvelopeVerifier(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	v := Ed25519EnvelopeVerifier{PubKey: pub, ProviderID: "acme-pad2"}

	env := signEnvelope(t, priv, LivenessAttestation{
		ProviderID: "acme-pad2", UserID: "u-1", Score: 0.9, Timestamp: time.Now().Unix(),
	})

	att, err := v.Verify(env, Binding{UserID: "u-1", MinScore: 0.8, MaxAge: time.Minute})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if att.UserID != "u-1" || att.Score != 0.9 {
		t.Fatalf("unexpected attestation: %+v", att)
	}

	// Wrong provider id lock is rejected.
	bad := Ed25519EnvelopeVerifier{PubKey: pub, ProviderID: "other"}
	if _, err := bad.Verify(env, Binding{UserID: "u-1", MinScore: 0.8, MaxAge: time.Minute}); err == nil {
		t.Fatal("expected providerId mismatch rejection")
	}
}

// TestVerifierRegistry confirms the white-label extension path: a deployment
// registers its own Verifier under a provider id and the server resolves it
// — including a fully custom scheme unrelated to Ed25519 envelopes.
func TestVerifierRegistry(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	RegisterVerifier("vendor-x", Ed25519EnvelopeVerifier{PubKey: pub, ProviderID: "vendor-x"})
	t.Cleanup(func() { RegisterVerifier("vendor-x", nil) })

	got, ok := LookupVerifier("vendor-x")
	if !ok {
		t.Fatal("vendor-x not registered")
	}
	env := signEnvelope(t, priv, LivenessAttestation{
		ProviderID: "vendor-x", UserID: "u-9", Score: 0.95, Timestamp: time.Now().Unix(),
	})
	if _, err := got.Verify(env, Binding{UserID: "u-9", MinScore: 0.8, MaxAge: time.Minute}); err != nil {
		t.Fatalf("registered verifier failed: %v", err)
	}

	// A wholly custom Verifier (no Ed25519 envelope) plugs in the same way.
	RegisterVerifier("remote-attest", stubVerifier{})
	t.Cleanup(func() { RegisterVerifier("remote-attest", nil) })
	cv, ok := LookupVerifier("remote-attest")
	if !ok {
		t.Fatal("custom verifier not registered")
	}
	if _, err := cv.Verify("anything", Binding{UserID: "u-1"}); !errors.Is(err, errStub) {
		t.Fatalf("custom verifier not invoked: %v", err)
	}

	// nil removes the entry.
	RegisterVerifier("vendor-x", nil)
	if _, ok := LookupVerifier("vendor-x"); ok {
		t.Fatal("vendor-x should have been removed")
	}
}

var errStub = errors.New("stub verifier called")

type stubVerifier struct{}

func (stubVerifier) Verify(string, Binding) (*LivenessAttestation, error) { return nil, errStub }
