package webauthn

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// LivenessAttestation is the signed envelope SecureGate (or any other PAD-2
// liveness provider) returns when it scores a capture. The structure is
// canonicalized to JSON with sorted keys before signing. The KMS verifies:
//
//   - Signature is valid for the configured provider public key
//   - Subject (user) matches the authenticated caller
//   - Timestamp is fresh (< MaxAge)
//   - Score >= MinScore (PAD-2 default is 0.8)
//
// Clients MUST NOT send a bare liveness score — the server-to-server trust
// anchor is the SecureGate signature, not a float in the body. Without this
// envelope the body is rejected.
type LivenessAttestation struct {
	ProviderID string  `json:"providerId"`
	UserID     string  `json:"userId"`
	Score      float64 `json:"score"`
	Timestamp  int64   `json:"timestamp"` // unix seconds
	Nonce      string  `json:"nonce"`
}

// LivenessOpts configures server-side verification.
type LivenessOpts struct {
	PubKey     ed25519.PublicKey
	ProviderID string // optional: if non-empty, attestation.ProviderID must match
	UserID     string // attestation.UserID MUST match this (the authenticated caller)
	MinScore   float64
	MaxAge     time.Duration
	Now        func() time.Time // overridable for tests; nil → time.Now
}

// VerifyLiveness decodes the attestation envelope and returns the verified
// attestation. The envelope is JSON with `{"attestation":{...}, "sig":"b64"}`.
// The signature is Ed25519(canonicalJSON(attestation)).
func VerifyLiveness(envelopeB64 string, opts *LivenessOpts) (*LivenessAttestation, error) {
	if opts == nil || len(opts.PubKey) == 0 {
		return nil, errors.New("liveness: verifier not configured")
	}
	if opts.UserID == "" {
		return nil, errors.New("liveness: expected user id required")
	}
	if opts.MinScore <= 0 {
		return nil, errors.New("liveness: min score required")
	}
	if opts.MaxAge <= 0 {
		opts.MaxAge = 2 * time.Minute
	}
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}

	raw, err := base64.StdEncoding.DecodeString(envelopeB64)
	if err != nil {
		if r2, err2 := base64.URLEncoding.DecodeString(envelopeB64); err2 == nil {
			raw = r2
		} else {
			return nil, errors.New("liveness: invalid envelope encoding")
		}
	}
	var env struct {
		Attestation json.RawMessage `json:"attestation"`
		Sig         string          `json:"sig"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, errors.New("liveness: malformed envelope")
	}
	if len(env.Attestation) == 0 || env.Sig == "" {
		return nil, errors.New("liveness: envelope missing fields")
	}

	sig, err := base64.StdEncoding.DecodeString(env.Sig)
	if err != nil {
		return nil, errors.New("liveness: invalid signature encoding")
	}
	if !ed25519.Verify(opts.PubKey, env.Attestation, sig) {
		return nil, errors.New("liveness: signature verification failed")
	}
	// Parse the verified attestation after the signature check to avoid a
	// JSON-only oracle.
	var att LivenessAttestation
	if err := json.Unmarshal(env.Attestation, &att); err != nil {
		return nil, errors.New("liveness: malformed attestation")
	}

	if opts.ProviderID != "" && att.ProviderID != opts.ProviderID {
		return nil, fmt.Errorf("liveness: providerId mismatch: %q", att.ProviderID)
	}
	if att.UserID != opts.UserID {
		return nil, errors.New("liveness: userId mismatch")
	}
	if att.Score < opts.MinScore {
		return nil, fmt.Errorf("liveness: score %.2f below threshold %.2f", att.Score, opts.MinScore)
	}
	ts := time.Unix(att.Timestamp, 0)
	age := now().Sub(ts)
	if age < 0 || age > opts.MaxAge {
		return nil, fmt.Errorf("liveness: attestation too old: age=%s max=%s", age, opts.MaxAge)
	}
	return &att, nil
}
