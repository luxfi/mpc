package webauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
)

// TestCases hit each defect R2-1 identified, and a few positive-path checks.

func TestVerify_ChallengeMismatchRejected(t *testing.T) {
	srv := newTestServer(t, CeremonyCreate)
	srv.opts.ExpectedChallenge = []byte("real-server-challenge-32bytes!")
	// Client pretends to sign a different challenge (e.g. a predictable DB ID).
	srv.cdChallenge = base64.RawURLEncoding.EncodeToString([]byte("guessed-db-row-id"))
	bundle := srv.sign(t)
	if _, err := Verify(bundle); err == nil || !strings.Contains(err.Error(), "challenge mismatch") {
		t.Fatalf("want challenge mismatch, got %v", err)
	}
}

func TestVerify_ChallengeMatchAccepted(t *testing.T) {
	srv := newTestServer(t, CeremonyCreate)
	bundle := srv.sign(t)
	out, err := Verify(bundle)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !out.SignedOK {
		t.Fatal("expected SignedOK=true")
	}
	if out.Origin != srv.origin {
		t.Fatalf("origin = %q, want %q", out.Origin, srv.origin)
	}
}

func TestVerify_OriginAllowlist(t *testing.T) {
	srv := newTestServer(t, CeremonyCreate)
	srv.origin = "https://evil.example"
	bundle := srv.sign(t)
	if _, err := Verify(bundle); err == nil || !strings.Contains(err.Error(), "origin not allowed") {
		t.Fatalf("want origin rejected, got %v", err)
	}
}

func TestVerify_RPIDHashEnforced(t *testing.T) {
	srv := newTestServer(t, CeremonyCreate)
	// Produce authenticatorData with the WRONG rpIDHash.
	srv.rpIDHashOverride = sha256sum("attacker.example")
	bundle := srv.sign(t)
	if _, err := Verify(bundle); err == nil || !strings.Contains(err.Error(), "rpIDHash mismatch") {
		t.Fatalf("want rpIDHash mismatch, got %v", err)
	}
}

func TestVerify_UVRequired(t *testing.T) {
	srv := newTestServer(t, CeremonyCreate)
	srv.flags = 0x01 // UP set but UV clear
	bundle := srv.sign(t)
	bundle.RequireUV = true
	if _, err := Verify(bundle); err == nil || !strings.Contains(err.Error(), "user verification") {
		t.Fatalf("want UV required error, got %v", err)
	}
}

func TestVerify_UPRequired(t *testing.T) {
	srv := newTestServer(t, CeremonyCreate)
	srv.flags = 0x04 // UV set but UP clear
	bundle := srv.sign(t)
	bundle.RequireUP = true
	bundle.RequireUV = false
	if _, err := Verify(bundle); err == nil || !strings.Contains(err.Error(), "user presence") {
		t.Fatalf("want UP required error, got %v", err)
	}
}

func TestVerify_CeremonyTypeMismatch(t *testing.T) {
	// Sign with webauthn.get but verify demands webauthn.create.
	srv := newTestServer(t, CeremonyGet)
	bundle := srv.sign(t)
	bundle.Ceremony = CeremonyCreate
	if _, err := Verify(bundle); err == nil || !strings.Contains(err.Error(), "ceremony type") {
		t.Fatalf("want ceremony type mismatch, got %v", err)
	}
}

func TestVerify_BadSignature(t *testing.T) {
	srv := newTestServer(t, CeremonyCreate)
	bundle := srv.sign(t)
	// Flip one byte in the signature.
	sigBytes, _ := base64.URLEncoding.DecodeString(bundle.SignatureB64)
	if len(sigBytes) == 0 {
		t.Fatal("signature empty, cannot mutate")
	}
	sigBytes[0] ^= 0xFF
	bundle.SignatureB64 = base64.URLEncoding.EncodeToString(sigBytes)
	if _, err := Verify(bundle); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("want signature failure, got %v", err)
	}
}

func TestVerify_TooShortAuthenticatorData(t *testing.T) {
	srv := newTestServer(t, CeremonyCreate)
	bundle := srv.sign(t)
	bundle.AuthDataB64 = base64.URLEncoding.EncodeToString([]byte{0x00, 0x01, 0x02})
	if _, err := Verify(bundle); err == nil || !strings.Contains(err.Error(), "too short") {
		t.Fatalf("want too short error, got %v", err)
	}
}

// --- test helper (builds a signed attestation bundle like a real browser) ---

type testSrv struct {
	rpID             string
	origin           string
	challenge        []byte
	cdChallenge      string
	cdType           Ceremony
	flags            AuthenticatorFlags
	rpIDHashOverride []byte
	priv             *ecdsa.PrivateKey
	opts             *Opts
}

func newTestServer(t *testing.T, c Ceremony) *testSrv {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	chal := make([]byte, 32)
	if _, err := rand.Read(chal); err != nil {
		t.Fatal(err)
	}
	rpID := "lux.network"
	origin := "https://lux.network"
	return &testSrv{
		rpID:        rpID,
		origin:      origin,
		challenge:   chal,
		cdChallenge: base64.RawURLEncoding.EncodeToString(chal),
		cdType:      c,
		flags:       FlagUP | FlagUV,
		priv:        priv,
		opts: &Opts{
			Ceremony:          c,
			ExpectedChallenge: chal,
			AllowedOrigins:    map[string]bool{origin: true},
			RPID:              rpID,
			RequireUP:         false,
			RequireUV:         false,
		},
	}
}

func (s *testSrv) sign(t *testing.T) *Opts {
	t.Helper()
	cd := map[string]string{
		"challenge": s.cdChallenge,
		"origin":    s.origin,
		"type":      string(s.cdType),
	}
	cdJSON, _ := json.Marshal(cd)

	rpIDHash := sha256sum(s.rpID)
	if s.rpIDHashOverride != nil {
		rpIDHash = s.rpIDHashOverride
	}
	authData := make([]byte, 37)
	copy(authData[:32], rpIDHash)
	authData[32] = byte(s.flags)
	// counter is authData[33..36], leave zeros.

	clientDataHash := sha256.Sum256(cdJSON)
	signed := append(append([]byte{}, authData...), clientDataHash[:]...)
	signedHash := sha256.Sum256(signed)
	sig, err := ecdsa.SignASN1(rand.Reader, s.priv, signedHash[:])
	if err != nil {
		t.Fatal(err)
	}

	pubBytes := append([]byte{0x04},
		append(bigEnd(s.priv.X, 32), bigEnd(s.priv.Y, 32)...)...)

	b := *s.opts
	b.ClientDataJSONB64 = base64.URLEncoding.EncodeToString(cdJSON)
	b.AuthDataB64 = base64.URLEncoding.EncodeToString(authData)
	b.SignatureB64 = base64.URLEncoding.EncodeToString(sig)
	b.PublicKeyB64 = base64.StdEncoding.EncodeToString(pubBytes)
	return &b
}

func sha256sum(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

func bigEnd(i *big.Int, size int) []byte {
	b := i.Bytes()
	if len(b) == size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}
