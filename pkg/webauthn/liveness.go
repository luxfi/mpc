package webauthn

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// LivenessAttestation is the signed envelope Signer (or any other PAD-2
// liveness provider) returns when it scores a capture. The structure is
// canonicalized to JSON with sorted keys before signing. The KMS verifies:
//
//   - Signature is valid for the configured provider public key
//   - Subject (user) matches the authenticated caller
//   - Timestamp is fresh (< MaxAge)
//   - Score >= MinScore (PAD-2 default is 0.8)
//   - R3-8: CredentialHash (if present) == sha256(enrollment public key)
//     OR ChallengeID (if present) == the WebAuthn challenge being enrolled.
//     Binds the attestation to the specific enrollment ceremony — a stolen
//     envelope within the 2-minute validity window cannot be replayed to
//     enroll an attacker-controlled public key.
//
// Clients MUST NOT send a bare liveness score — the server-to-server trust
// anchor is the Signer signature, not a float in the body. Without this
// envelope the body is rejected.
type LivenessAttestation struct {
	ProviderID string  `json:"providerId"`
	UserID     string  `json:"userId"`
	Score      float64 `json:"score"`
	Timestamp  int64   `json:"timestamp"` // unix seconds
	Nonce      string  `json:"nonce"`
	// R3-8: at least one of these MUST be present when the server is in
	// strict binding mode (BindingMode = BindingStrict). They bind the
	// envelope to the specific WebAuthn enrollment it was minted for:
	//
	//   - CredentialHash = sha256(uncompressed P-256 public key bytes),
	//     base64 (standard). Equivalent to the "I attested the device
	//     holding THIS key" claim.
	//   - ChallengeID = the WebAuthn challenge being enrolled, base64url.
	//     Equivalent to "I attested THIS ceremony".
	//
	// Empty fields mean "provider did not assert this binding." Verify
	// returns an error if BindingMode requires one and the envelope
	// supplies none, or if a supplied field does not match the opts.
	CredentialHash string `json:"credentialHash,omitempty"`
	ChallengeID    string `json:"challengeId,omitempty"`
}

// BindingMode selects how strictly VerifyLiveness enforces the R3-8
// envelope→enrollment binding.
type BindingMode int

const (
	// BindingStrict rejects any envelope that supplies neither
	// CredentialHash nor ChallengeID. This is the only safe default for
	// production biometric enrollment on mainnet.
	BindingStrict BindingMode = iota

	// BindingLax logs a warning (via opts.WarnFn) when neither field is
	// supplied but does not reject. Intended ONLY for the transition
	// window while Signer rolls out the extended envelope. Tracked
	// as a deployment blocker in the MPC LLM.md.
	BindingLax
)

// LivenessOpts configures server-side verification.
type LivenessOpts struct {
	PubKey     ed25519.PublicKey
	ProviderID string // optional: if non-empty, attestation.ProviderID must match
	UserID     string // attestation.UserID MUST match this (the authenticated caller)
	MinScore   float64
	MaxAge     time.Duration
	Now        func() time.Time // overridable for tests; nil → time.Now

	// R3-8 binding inputs. When either is non-empty the verifier
	// requires the envelope's corresponding field to match. In
	// BindingStrict mode at least one must be non-empty OR the envelope
	// MUST carry one (otherwise the call is rejected).
	ExpectedCredentialHash string      // base64(sha256(publicKeyBytes))
	ExpectedChallengeID    string      // base64url(challengeBytes)
	BindingMode            BindingMode // default BindingStrict
	WarnFn                 func(msg string)
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

	// R3-8 / F4: envelope→enrollment binding. Only applies when the caller
	// supplies a binding expectation (ExpectedCredentialHash and/or
	// ExpectedChallengeID). Callers that don't care about binding (e.g.
	// generic liveness checks unrelated to WebAuthn enrollment) are
	// unaffected.
	requiresBinding := opts.ExpectedCredentialHash != "" || opts.ExpectedChallengeID != ""
	if requiresBinding {
		// Mismatch is always fatal — a supplied-but-wrong value means
		// the envelope was minted for a different ceremony.
		if att.CredentialHash != "" && att.CredentialHash != opts.ExpectedCredentialHash && opts.ExpectedCredentialHash != "" {
			return nil, errors.New("liveness: credentialHash mismatch — envelope not bound to this enrollment")
		}
		if att.ChallengeID != "" && att.ChallengeID != opts.ExpectedChallengeID && opts.ExpectedChallengeID != "" {
			return nil, errors.New("liveness: challengeId mismatch — envelope not bound to this ceremony")
		}

		// F4 (2026-04-18): tighten LAX. Previously LAX accepted an
		// envelope where EITHER field matched. That permitted a
		// cross-ceremony replay: an envelope whose challengeId matches
		// the current ceremony's challenge but whose credentialHash is
		// absent would be accepted — an attacker who observes a fresh
		// challenge can trick Signer into signing an envelope that
		// binds to the challenge alone, then replay it against any
		// ceremony for the same userId that reuses an uncaptured
		// credentialHash expectation.
		//
		// Two tightenings (both layered on top of the existing
		// "mismatch always rejects" guards above):
		//
		//   1. When BOTH expected fields are set AND the envelope
		//      supplies BOTH, require BOTH to match. This closes the
		//      "either-or" loophole for the happy path where Signer
		//      has already rolled out the extended envelope.
		//
		//   2. credentialHash is mandatory at minimum in LAX. The
		//      envelope MUST carry CredentialHash whenever the server
		//      expects one. challengeId alone is insufficient — it can
		//      be observed and replayed faster than credentialHash can
		//      be forged against an attacker-controlled pubkey.
		//
		// STRICT already enforced the missing-both rejection; these
		// rules add the LAX-only refinements.
		if att.CredentialHash != "" && att.ChallengeID != "" &&
			opts.ExpectedCredentialHash != "" && opts.ExpectedChallengeID != "" {
			// Both sides have both fields — require both to match.
			// The prior "mismatch rejects" guards have already caught
			// any individual mismatch; this is a belt-and-braces
			// assertion that closes the pathological both-supplied-
			// one-blank-expected corner.
			if att.CredentialHash != opts.ExpectedCredentialHash ||
				att.ChallengeID != opts.ExpectedChallengeID {
				return nil, errors.New("liveness: binding mismatch — both credentialHash and challengeId must match when both are present")
			}
		}

		if opts.BindingMode == BindingLax &&
			opts.ExpectedCredentialHash != "" &&
			att.CredentialHash == "" {
			// F4: LAX + expected credentialHash + envelope omits it =
			// reject. This is the "challengeId-only replay" gate. The
			// envelope must commit to the enrollment pubkey hash.
			return nil, errors.New("liveness: credentialHash required in LAX mode — envelope without credentialHash is replay-vulnerable")
		}

		// A "matching" envelope has at least one field that matches its
		// corresponding expected value. In STRICT mode, a missing field
		// is rejected; in LAX mode we warn and accept.
		matched := false
		if opts.ExpectedCredentialHash != "" && att.CredentialHash == opts.ExpectedCredentialHash {
			matched = true
		}
		if opts.ExpectedChallengeID != "" && att.ChallengeID == opts.ExpectedChallengeID {
			matched = true
		}
		if !matched {
			if opts.BindingMode == BindingStrict {
				return nil, errors.New("liveness: envelope carries no binding (credentialHash/challengeId); Signer must emit the extended envelope")
			}
			if opts.WarnFn != nil {
				opts.WarnFn("liveness: envelope carries no binding — accepted in LAX mode; tracked Signer rollout")
			}
		}
	}
	return &att, nil
}
