package webauthn

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func signEnvelope(t *testing.T, priv ed25519.PrivateKey, att LivenessAttestation) string {
	t.Helper()
	attJSON, _ := json.Marshal(att)
	sig := ed25519.Sign(priv, attJSON)
	env := map[string]any{
		"attestation": json.RawMessage(attJSON),
		"sig":         base64.StdEncoding.EncodeToString(sig),
	}
	raw, _ := json.Marshal(env)
	return base64.StdEncoding.EncodeToString(raw)
}

func TestLiveness_Accepts(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	att := LivenessAttestation{
		ProviderID: "signer",
		UserID:     "u-1",
		Score:      0.95,
		Timestamp:  time.Now().Unix(),
		Nonce:      "n1",
	}
	env := signEnvelope(t, priv, att)
	got, err := VerifyLiveness(env, &LivenessOpts{
		PubKey:     pub,
		ProviderID: "signer",
		UserID:     "u-1",
		MinScore:   0.8,
		MaxAge:     2 * time.Minute,
	})
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if got.Score != 0.95 {
		t.Fatalf("score: %v", got.Score)
	}
}

func TestLiveness_RejectsBadSig(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	att := LivenessAttestation{ProviderID: "signer", UserID: "u-1", Score: 0.9, Timestamp: time.Now().Unix()}
	env := signEnvelope(t, priv, att)
	// Corrupt: swap a byte in the envelope (base64 re-decode still works but
	// the JSON.sig no longer matches the attestation).
	raw, _ := base64.StdEncoding.DecodeString(env)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	// Replace signature with bad bytes.
	m["sig"] = base64.StdEncoding.EncodeToString([]byte{0x00, 0x01})
	out, _ := json.Marshal(m)
	bad := base64.StdEncoding.EncodeToString(out)

	_, err := VerifyLiveness(bad, &LivenessOpts{PubKey: pub, UserID: "u-1", MinScore: 0.8, MaxAge: time.Minute})
	if err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("want signature error, got %v", err)
	}
}

func TestLiveness_RejectsWrongUser(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	att := LivenessAttestation{ProviderID: "signer", UserID: "attacker", Score: 0.9, Timestamp: time.Now().Unix()}
	env := signEnvelope(t, priv, att)
	_, err := VerifyLiveness(env, &LivenessOpts{PubKey: pub, UserID: "u-1", MinScore: 0.8, MaxAge: time.Minute})
	if err == nil || !strings.Contains(err.Error(), "userId") {
		t.Fatalf("want userId mismatch, got %v", err)
	}
}

func TestLiveness_RejectsStale(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	att := LivenessAttestation{ProviderID: "signer", UserID: "u-1", Score: 0.9, Timestamp: time.Now().Add(-10 * time.Minute).Unix()}
	env := signEnvelope(t, priv, att)
	_, err := VerifyLiveness(env, &LivenessOpts{PubKey: pub, UserID: "u-1", MinScore: 0.8, MaxAge: time.Minute})
	if err == nil || !strings.Contains(err.Error(), "too old") {
		t.Fatalf("want stale error, got %v", err)
	}
}

func TestLiveness_RejectsLowScore(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	att := LivenessAttestation{ProviderID: "signer", UserID: "u-1", Score: 0.5, Timestamp: time.Now().Unix()}
	env := signEnvelope(t, priv, att)
	_, err := VerifyLiveness(env, &LivenessOpts{PubKey: pub, UserID: "u-1", MinScore: 0.8, MaxAge: time.Minute})
	if err == nil || !strings.Contains(err.Error(), "below threshold") {
		t.Fatalf("want low score error, got %v", err)
	}
}

func TestLiveness_RejectsWrongProvider(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	att := LivenessAttestation{ProviderID: "evil", UserID: "u-1", Score: 0.9, Timestamp: time.Now().Unix()}
	env := signEnvelope(t, priv, att)
	_, err := VerifyLiveness(env, &LivenessOpts{PubKey: pub, ProviderID: "signer", UserID: "u-1", MinScore: 0.8, MaxAge: time.Minute})
	if err == nil || !strings.Contains(err.Error(), "providerId") {
		t.Fatalf("want providerId mismatch, got %v", err)
	}
}

// R3-8: envelope→enrollment binding. A stolen envelope must not be
// replayable against a different enrollment.

// Accept: envelope credentialHash matches the enrollment pubkey hash.
func TestLiveness_R38_AcceptsMatchingCredentialHash(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	att := LivenessAttestation{
		ProviderID:     "signer",
		UserID:         "u-1",
		Score:          0.9,
		Timestamp:      time.Now().Unix(),
		CredentialHash: "ABC123==",
	}
	env := signEnvelope(t, priv, att)
	_, err := VerifyLiveness(env, &LivenessOpts{
		PubKey: pub, UserID: "u-1", MinScore: 0.8, MaxAge: time.Minute,
		ExpectedCredentialHash: "ABC123==",
		BindingMode:            BindingStrict,
	})
	if err != nil {
		t.Fatalf("matching credentialHash should accept: %v", err)
	}
}

// Reject: envelope credentialHash present but does not match (replay
// attempt against a different public key).
func TestLiveness_R38_RejectsMismatchedCredentialHash(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	att := LivenessAttestation{
		ProviderID:     "signer",
		UserID:         "u-1",
		Score:          0.9,
		Timestamp:      time.Now().Unix(),
		CredentialHash: "EVIL===",
	}
	env := signEnvelope(t, priv, att)
	_, err := VerifyLiveness(env, &LivenessOpts{
		PubKey: pub, UserID: "u-1", MinScore: 0.8, MaxAge: time.Minute,
		ExpectedCredentialHash: "VICTIM==",
		BindingMode:            BindingStrict,
	})
	if err == nil || !strings.Contains(err.Error(), "credentialHash mismatch") {
		t.Fatalf("mismatched credentialHash must reject: got %v", err)
	}
}

// Reject (STRICT): server expected binding, envelope carries none.
// This is the replay-prevention gate.
func TestLiveness_R38_RejectsMissingBindingStrict(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	att := LivenessAttestation{
		ProviderID: "signer",
		UserID:     "u-1",
		Score:      0.9,
		Timestamp:  time.Now().Unix(),
		// no CredentialHash, no ChallengeID — pre-R3-8 envelope
	}
	env := signEnvelope(t, priv, att)
	_, err := VerifyLiveness(env, &LivenessOpts{
		PubKey: pub, UserID: "u-1", MinScore: 0.8, MaxAge: time.Minute,
		ExpectedCredentialHash: "VICTIM==",
		BindingMode:            BindingStrict,
	})
	if err == nil || !strings.Contains(err.Error(), "no binding") {
		t.Fatalf("STRICT + missing binding must reject: got %v", err)
	}
}

// F4 (2026-04-18): LAX + server expects credentialHash + envelope carries
// NEITHER binding field → now rejects. Pre-F4 this was accept-with-warn;
// Red round 4 flagged that as a cross-ceremony replay window. The
// tightening makes credentialHash a hard floor in LAX.
func TestLiveness_R38_LaxRejectsMissingBindingWhenCredentialHashExpected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	att := LivenessAttestation{
		ProviderID: "signer",
		UserID:     "u-1",
		Score:      0.9,
		Timestamp:  time.Now().Unix(),
		// intentionally empty — pre-R3-8 envelope shape
	}
	env := signEnvelope(t, priv, att)
	_, err := VerifyLiveness(env, &LivenessOpts{
		PubKey: pub, UserID: "u-1", MinScore: 0.8, MaxAge: time.Minute,
		ExpectedCredentialHash: "VICTIM==",
		BindingMode:            BindingLax,
	})
	if err == nil || !strings.Contains(err.Error(), "credentialHash required in LAX mode") {
		t.Fatalf("F4: LAX + expected credentialHash + envelope empty must reject: got %v", err)
	}
}

// F4: the LAX warn path survives ONLY when the server does NOT expect a
// credentialHash (e.g. a pure challengeId-binding call site). Envelope
// missing is then accepted with a warning, as before.
func TestLiveness_R38_LaxWarnsOnMissing_ChallengeIDOnly(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	att := LivenessAttestation{
		ProviderID: "signer",
		UserID:     "u-1",
		Score:      0.9,
		Timestamp:  time.Now().Unix(),
	}
	env := signEnvelope(t, priv, att)
	var warned string
	_, err := VerifyLiveness(env, &LivenessOpts{
		PubKey: pub, UserID: "u-1", MinScore: 0.8, MaxAge: time.Minute,
		// NOTE: only ExpectedChallengeID is set — the LAX warn path is
		// reserved for call sites that never commit credentialHash.
		ExpectedChallengeID: "chal-xyz",
		BindingMode:         BindingLax,
		WarnFn:              func(m string) { warned = m },
	})
	if err != nil {
		t.Fatalf("LAX + challengeId-only expectation + missing binding must warn-accept: %v", err)
	}
	if warned == "" {
		t.Fatalf("LAX must emit a warn message on missing binding")
	}
}

// Accept: envelope challengeId matches the WebAuthn challenge id.
func TestLiveness_R38_AcceptsMatchingChallengeID(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	att := LivenessAttestation{
		ProviderID:  "signer",
		UserID:      "u-1",
		Score:       0.9,
		Timestamp:   time.Now().Unix(),
		ChallengeID: "chal-xyz",
	}
	env := signEnvelope(t, priv, att)
	_, err := VerifyLiveness(env, &LivenessOpts{
		PubKey: pub, UserID: "u-1", MinScore: 0.8, MaxAge: time.Minute,
		ExpectedChallengeID: "chal-xyz",
		BindingMode:         BindingStrict,
	})
	if err != nil {
		t.Fatalf("matching challengeId should accept: %v", err)
	}
}

// Reject: envelope challengeId mismatch.
func TestLiveness_R38_RejectsMismatchedChallengeID(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	att := LivenessAttestation{
		ProviderID:  "signer",
		UserID:      "u-1",
		Score:       0.9,
		Timestamp:   time.Now().Unix(),
		ChallengeID: "chal-ATTACKER",
	}
	env := signEnvelope(t, priv, att)
	_, err := VerifyLiveness(env, &LivenessOpts{
		PubKey: pub, UserID: "u-1", MinScore: 0.8, MaxAge: time.Minute,
		ExpectedChallengeID: "chal-VICTIM",
		BindingMode:         BindingStrict,
	})
	if err == nil || !strings.Contains(err.Error(), "challengeId mismatch") {
		t.Fatalf("mismatched challengeId must reject: got %v", err)
	}
}

// F4 (2026-04-18): LAX tightening — credentialHash is mandatory floor.
//
// Previous LAX behavior accepted an envelope that had ONLY challengeId and
// no credentialHash, so long as the challengeId matched. An attacker
// observing a fresh challenge could persuade Signer to sign an
// envelope binding to the challenge alone and replay it against any
// enrollment for the same userId. The challengeId binds the ceremony;
// the credentialHash binds the specific pubkey being enrolled. Without
// the credentialHash floor there is no binding to the pubkey — that is
// the cross-ceremony replay Red flagged in round 4.

// LAX + envelope omits credentialHash (only challengeId) → reject.
// This is the primary F4 gate.
func TestLiveness_R38_LaxRejectsMissingCredentialHash(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	att := LivenessAttestation{
		ProviderID:  "signer",
		UserID:      "u-1",
		Score:       0.9,
		Timestamp:   time.Now().Unix(),
		ChallengeID: "chal-xyz", // challengeId alone is NOT enough in LAX
	}
	env := signEnvelope(t, priv, att)
	_, err := VerifyLiveness(env, &LivenessOpts{
		PubKey: pub, UserID: "u-1", MinScore: 0.8, MaxAge: time.Minute,
		ExpectedCredentialHash: "VICTIM-HASH",
		ExpectedChallengeID:    "chal-xyz",
		BindingMode:            BindingLax,
	})
	if err == nil || !strings.Contains(err.Error(), "credentialHash required in LAX mode") {
		t.Fatalf("LAX + missing credentialHash must reject: got %v", err)
	}
}

// LAX + both fields present + both match → accept (happy path for the
// extended envelope post-Signer-rollout).
func TestLiveness_R38_LaxAcceptsBothMatch(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	att := LivenessAttestation{
		ProviderID:     "signer",
		UserID:         "u-1",
		Score:          0.9,
		Timestamp:      time.Now().Unix(),
		CredentialHash: "HASH-OK",
		ChallengeID:    "chal-ok",
	}
	env := signEnvelope(t, priv, att)
	_, err := VerifyLiveness(env, &LivenessOpts{
		PubKey: pub, UserID: "u-1", MinScore: 0.8, MaxAge: time.Minute,
		ExpectedCredentialHash: "HASH-OK",
		ExpectedChallengeID:    "chal-ok",
		BindingMode:            BindingLax,
	})
	if err != nil {
		t.Fatalf("LAX + both present + both match must accept: %v", err)
	}
}

// LAX + both fields present + credentialHash mismatch → reject. This is
// the existing "mismatch always rejects" rule; the test makes it explicit
// for LAX to prove the tightening didn't regress.
func TestLiveness_R38_LaxRejectsMismatchedCredentialHashBothPresent(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	att := LivenessAttestation{
		ProviderID:     "signer",
		UserID:         "u-1",
		Score:          0.9,
		Timestamp:      time.Now().Unix(),
		CredentialHash: "HASH-ATTACKER",
		ChallengeID:    "chal-ok",
	}
	env := signEnvelope(t, priv, att)
	_, err := VerifyLiveness(env, &LivenessOpts{
		PubKey: pub, UserID: "u-1", MinScore: 0.8, MaxAge: time.Minute,
		ExpectedCredentialHash: "HASH-VICTIM",
		ExpectedChallengeID:    "chal-ok",
		BindingMode:            BindingLax,
	})
	if err == nil || !strings.Contains(err.Error(), "credentialHash mismatch") {
		t.Fatalf("LAX + mismatched credentialHash must reject: got %v", err)
	}
}

// LAX + both fields present + challengeId mismatch → reject.
func TestLiveness_R38_LaxRejectsMismatchedChallengeIDBothPresent(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	att := LivenessAttestation{
		ProviderID:     "signer",
		UserID:         "u-1",
		Score:          0.9,
		Timestamp:      time.Now().Unix(),
		CredentialHash: "HASH-OK",
		ChallengeID:    "chal-ATTACKER",
	}
	env := signEnvelope(t, priv, att)
	_, err := VerifyLiveness(env, &LivenessOpts{
		PubKey: pub, UserID: "u-1", MinScore: 0.8, MaxAge: time.Minute,
		ExpectedCredentialHash: "HASH-OK",
		ExpectedChallengeID:    "chal-VICTIM",
		BindingMode:            BindingLax,
	})
	if err == nil || !strings.Contains(err.Error(), "challengeId mismatch") {
		t.Fatalf("LAX + mismatched challengeId must reject: got %v", err)
	}
}

// LAX + credentialHash only (no challengeId) + match → accept.
// This is the "Signer not yet rolled out challengeId" case. The
// mandatory credentialHash floor is satisfied, so the envelope carries
// enough binding to be safe.
func TestLiveness_R38_LaxAcceptsCredentialHashOnly(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	att := LivenessAttestation{
		ProviderID:     "signer",
		UserID:         "u-1",
		Score:          0.9,
		Timestamp:      time.Now().Unix(),
		CredentialHash: "HASH-OK",
		// no ChallengeID — simulates the current Signer envelope
	}
	env := signEnvelope(t, priv, att)
	_, err := VerifyLiveness(env, &LivenessOpts{
		PubKey: pub, UserID: "u-1", MinScore: 0.8, MaxAge: time.Minute,
		ExpectedCredentialHash: "HASH-OK",
		ExpectedChallengeID:    "chal-xyz",
		BindingMode:            BindingLax,
	})
	if err != nil {
		t.Fatalf("LAX + credentialHash-only + match must accept: %v", err)
	}
}
