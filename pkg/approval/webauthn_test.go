package approval

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

// fakeAuthenticator simulates the WebAuthn assertion ceremony locally so
// the test exercises the full Verify path without real hardware.
type fakeAuthenticator struct {
	priv *ecdsa.PrivateKey
	rpID string
}

func newFakeAuthenticator(t *testing.T, rpID string) *fakeAuthenticator {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeAuthenticator{priv: priv, rpID: rpID}
}

func (a *fakeAuthenticator) uncompressedPub() []byte {
	out := make([]byte, 65)
	out[0] = 0x04
	xBytes := a.priv.PublicKey.X.Bytes()
	yBytes := a.priv.PublicKey.Y.Bytes()
	copy(out[1+(32-len(xBytes)):33], xBytes)
	copy(out[33+(32-len(yBytes)):65], yBytes)
	return out
}

// produceAssertion creates a clientDataJSON, authenticatorData, and
// signature consistent with the spec for a get ceremony.
func (a *fakeAuthenticator) produceAssertion(t *testing.T, challenge []byte, origin string) (string, string, string) {
	t.Helper()
	cd := map[string]string{
		"type":      "webauthn.get",
		"challenge": base64.RawURLEncoding.EncodeToString(challenge),
		"origin":    origin,
	}
	cdJSON, _ := json.Marshal(cd)
	rpHash := sha256.Sum256([]byte(a.rpID))
	authData := make([]byte, 37)
	copy(authData[:32], rpHash[:])
	authData[32] = 0x01 | 0x04 // UP + UV
	// counter 0
	signed := append(append([]byte{}, authData...), sha256ed(cdJSON)...)
	signedHash := sha256.Sum256(signed)
	r, s, err := ecdsa.Sign(rand.Reader, a.priv, signedHash[:])
	if err != nil {
		t.Fatal(err)
	}
	der, err := encodeECDSASignature(r, s)
	if err != nil {
		t.Fatal(err)
	}
	return base64.URLEncoding.EncodeToString(cdJSON),
		base64.URLEncoding.EncodeToString(authData),
		base64.URLEncoding.EncodeToString(der)
}

func sha256ed(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

func encodeECDSASignature(r, s interface{}) ([]byte, error) {
	type sig struct{ R, S interface{} }
	// Use the package-internal helper via raw r||s -> ASN.1 path.
	// That helper takes 64-byte raw form, but our r, s are *big.Int — so
	// we hand-pack into 64 bytes then convert.
	rBytes := r.(interface{ Bytes() []byte }).Bytes()
	sBytes := s.(interface{ Bytes() []byte }).Bytes()
	raw := make([]byte, 64)
	copy(raw[32-len(rBytes):32], rBytes)
	copy(raw[64-len(sBytes):], sBytes)
	return ecdsaRawToASN1(raw)
}

func TestWebAuthn_RoundTrip(t *testing.T) {
	prevEnv := os.Getenv("MPC_ENV")
	t.Cleanup(func() { os.Setenv("MPC_ENV", prevEnv) })
	os.Setenv("MPC_ENV", "test") // permit http://localhost origin in tests

	rpID := "lux.network"
	origin := "http://localhost:3000"
	auth := newFakeAuthenticator(t, rpID)

	provider, err := NewWebAuthn(map[string]string{
		"rpid":    rpID,
		"origins": origin,
		"timeout": "30s",
	})
	if err != nil {
		t.Fatalf("NewWebAuthn: %v", err)
	}
	wa := provider.(*WebAuthnProvider)
	if err := wa.Enroll("ceo@fund.com", "cred-1", auth.uncompressedPub()); err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	intent := newTestIntent("approve withdrawal")
	sessionID, challenge, err := wa.IssueChallenge(context.Background(), "ceo@fund.com", intent)
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}
	cdB64, adB64, sigB64 := auth.produceAssertion(t, challenge, origin)
	sig, err := wa.SubmitAssertion(context.Background(), sessionID, cdB64, adB64, sigB64)
	if err != nil {
		t.Fatalf("SubmitAssertion: %v", err)
	}
	if sig.Algorithm != AlgorithmWebAuthnES256 {
		t.Fatalf("Algorithm = %q, want %q", sig.Algorithm, AlgorithmWebAuthnES256)
	}

	ok, err := wa.VerifyApproval(context.Background(), intent, sig)
	if err != nil {
		t.Fatalf("VerifyApproval: %v", err)
	}
	if !ok {
		t.Fatal("VerifyApproval = false, want true")
	}

	// Tampered intent → verification fails.
	tampered := newTestIntent("steal everything")
	ok, _ = wa.VerifyApproval(context.Background(), tampered, sig)
	if ok {
		t.Fatal("VerifyApproval(tampered) = true, want false")
	}
}

func TestWebAuthn_RejectsHTTPInProduction(t *testing.T) {
	prevEnv := os.Getenv("MPC_ENV")
	t.Cleanup(func() { os.Setenv("MPC_ENV", prevEnv) })
	os.Setenv("MPC_ENV", "production")

	if _, err := NewWebAuthn(map[string]string{
		"rpid":    "fund.com",
		"origins": "http://approvals.fund.com", // no HTTPS
	}); err == nil {
		t.Fatal("NewWebAuthn with http origin in production: want error")
	}
}

func TestWebAuthn_BundleRoundTrip(t *testing.T) {
	authData := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	clientData := []byte(`{"type":"webauthn.get"}`)
	sig := []byte{0xaa, 0xbb, 0xcc}

	bundle := encodeWebAuthnBundle(authData, clientData, sig)
	a2, c2, s2, err := decodeWebAuthnBundle(bundle)
	if err != nil {
		t.Fatalf("decodeWebAuthnBundle: %v", err)
	}
	if string(a2) != string(authData) || string(c2) != string(clientData) || string(s2) != string(sig) {
		t.Fatal("bundle round-trip mismatch")
	}
}
