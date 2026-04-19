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
		ProviderID: "",
		UserID:     "u-1",
		Score:      0.95,
		Timestamp:  time.Now().Unix(),
		Nonce:      "n1",
	}
	env := signEnvelope(t, priv, att)
	got, err := VerifyLiveness(env, &LivenessOpts{
		PubKey:     pub,
		ProviderID: "",
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
	att := LivenessAttestation{ProviderID: "", UserID: "u-1", Score: 0.9, Timestamp: time.Now().Unix()}
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
	att := LivenessAttestation{ProviderID: "", UserID: "attacker", Score: 0.9, Timestamp: time.Now().Unix()}
	env := signEnvelope(t, priv, att)
	_, err := VerifyLiveness(env, &LivenessOpts{PubKey: pub, UserID: "u-1", MinScore: 0.8, MaxAge: time.Minute})
	if err == nil || !strings.Contains(err.Error(), "userId") {
		t.Fatalf("want userId mismatch, got %v", err)
	}
}

func TestLiveness_RejectsStale(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	att := LivenessAttestation{ProviderID: "", UserID: "u-1", Score: 0.9, Timestamp: time.Now().Add(-10 * time.Minute).Unix()}
	env := signEnvelope(t, priv, att)
	_, err := VerifyLiveness(env, &LivenessOpts{PubKey: pub, UserID: "u-1", MinScore: 0.8, MaxAge: time.Minute})
	if err == nil || !strings.Contains(err.Error(), "too old") {
		t.Fatalf("want stale error, got %v", err)
	}
}

func TestLiveness_RejectsLowScore(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	att := LivenessAttestation{ProviderID: "", UserID: "u-1", Score: 0.5, Timestamp: time.Now().Unix()}
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
	_, err := VerifyLiveness(env, &LivenessOpts{PubKey: pub, ProviderID: "", UserID: "u-1", MinScore: 0.8, MaxAge: time.Minute})
	if err == nil || !strings.Contains(err.Error(), "providerId") {
		t.Fatalf("want providerId mismatch, got %v", err)
	}
}
