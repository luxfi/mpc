package webauthn

import (
	"crypto/ed25519"
	"sync"
	"time"
)

// Binding is the vendor-neutral, per-call input to liveness verification:
// who the caller is, the score/freshness policy, and the enrollment
// ceremony the attestation must be bound to (R3-8). It deliberately holds
// no provider keys — those belong to the Verifier implementation. This is
// the seam that lets a white-label deployment swap the attestation scheme
// without the MPC call sites changing.
type Binding struct {
	UserID                 string
	MinScore               float64
	MaxAge                 time.Duration
	ExpectedCredentialHash string
	ExpectedChallengeID    string
	Mode                   BindingMode
	Now                    func() time.Time
	WarnFn                 func(string)
}

// Verifier verifies one provider's liveness attestation against a Binding,
// returning the verified attestation or an error. It is THE extension point
// for identity-verification vendors.
//
// lux OSS ships exactly one implementation — Ed25519EnvelopeVerifier — and
// names no vendor. A white-label deployment (e.g. a regulated broker that
// integrates a specific PAD-2 vendor) either:
//
//   - constructs an Ed25519EnvelopeVerifier with its vendor's public key
//     (zero code — its attestation is an Ed25519-signed envelope), or
//   - implements Verifier for a wholly different scheme (a remote
//     attestation service, a different signature suite, …),
//
// and registers it via RegisterVerifier before the MPC server boots. The
// server resolves the verifier by provider id — no fork of this package.
type Verifier interface {
	Verify(envelope string, b Binding) (*LivenessAttestation, error)
}

// Ed25519EnvelopeVerifier is the OSS-default Verifier: a JSON attestation
// envelope `{"attestation":{...},"sig":"b64"}` signed with Ed25519 over the
// canonical attestation bytes. It delegates to VerifyLiveness — the same
// audited verification logic — so registering one is the zero-code path for
// any vendor whose attestation is an Ed25519-signed envelope.
type Ed25519EnvelopeVerifier struct {
	// PubKey verifies the envelope signature.
	PubKey ed25519.PublicKey
	// ProviderID, when non-empty, locks attestation.ProviderID to this value.
	ProviderID string
}

// Verify implements Verifier.
func (v Ed25519EnvelopeVerifier) Verify(envelope string, b Binding) (*LivenessAttestation, error) {
	return VerifyLiveness(envelope, &LivenessOpts{
		PubKey:                 v.PubKey,
		ProviderID:             v.ProviderID,
		UserID:                 b.UserID,
		MinScore:               b.MinScore,
		MaxAge:                 b.MaxAge,
		ExpectedCredentialHash: b.ExpectedCredentialHash,
		ExpectedChallengeID:    b.ExpectedChallengeID,
		BindingMode:            b.Mode,
		Now:                    b.Now,
		WarnFn:                 b.WarnFn,
	})
}

// --- registry -------------------------------------------------------------

var (
	verifierMu sync.RWMutex
	verifiers  = map[string]Verifier{}
)

// RegisterVerifier registers a Verifier under a provider id. A white-label
// deployment calls this from an init() or main() before the MPC server
// boots; the server then resolves the verifier for its configured
// MPC_LIVENESS_PROVIDER_ID. Re-registering the same id replaces the prior
// entry (last write wins). Passing a nil Verifier removes the entry.
func RegisterVerifier(providerID string, v Verifier) {
	verifierMu.Lock()
	defer verifierMu.Unlock()
	if v == nil {
		delete(verifiers, providerID)
		return
	}
	verifiers[providerID] = v
}

// LookupVerifier returns the Verifier registered under providerID, if any.
func LookupVerifier(providerID string) (Verifier, bool) {
	verifierMu.RLock()
	defer verifierMu.RUnlock()
	v, ok := verifiers[providerID]
	return v, ok
}
