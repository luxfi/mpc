// Tests for the native Hanzo IAM verifier against a real JWKS endpoint and
// real RS256 signatures. The server tests use a stub verifier to isolate
// ENFORCEMENT; these isolate VERIFICATION.
//
// The claim: only a token signed by IAM's published key, minted by our
// issuer, unexpired, and speaking for an org this port serves, yields an
// Identity. Each test below breaks exactly one of those and expects a
// refusal — so no single check can be deleted without turning one red.
package api

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

const testIssuer = "https://hanzo.id"

// iamStub serves a JWKS at the path iamsdk fetches, and mints tokens
// against the matching private key.
type iamStub struct {
	key *rsa.PrivateKey
	kid string
	url string
}

func newIAMStub(t *testing.T) *iamStub {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	s := &iamStub{key: key, kid: "test-signing-key"}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/iam/.well-known/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA",
			"kid": s.kid,
			"use": "sig",
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
		}}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	s.url = srv.URL
	return s
}

// claims is the shape IAM mints. Defaults describe a KMS service token:
// client_credentials, so owner="admin" and the org rides in the name.
type claims struct {
	iss    string
	sub    string
	owner  string
	name   string
	typ    string
	tag    string
	expiry time.Duration
	noExp  bool
}

func (s *iamStub) mint(t *testing.T, c claims) string {
	t.Helper()
	if c.iss == "" {
		c.iss = testIssuer
	}
	if c.owner == "" {
		c.owner = "admin"
	}
	if c.name == "" {
		c.name = "lux-kms"
	}
	if c.typ == "" {
		c.typ = "application"
	}
	if c.sub == "" {
		c.sub = "admin/lux-kms"
	}
	if c.expiry == 0 {
		c.expiry = time.Hour
	}
	m := jwt.MapClaims{
		"iss": c.iss, "sub": c.sub,
		"owner": c.owner, "name": c.name, "type": c.typ,
		"iat": time.Now().Unix(),
	}
	if c.tag != "" {
		m["tag"] = c.tag
	}
	if !c.noExp {
		m["exp"] = time.Now().Add(c.expiry).Unix()
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, m)
	tok.Header["kid"] = s.kid
	signed, err := tok.SignedString(s.key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

func newVerifier(t *testing.T, stub *iamStub, org string) IdentityVerifier {
	t.Helper()
	v, err := NewIAMVerifier(stub.url, testIssuer, org)
	if err != nil {
		t.Fatalf("NewIAMVerifier: %v", err)
	}
	return v
}

// TestIAMAcceptsServiceToken is the control: the real credential shape a
// KMS pod presents must work, or every refusal below is meaningless.
func TestIAMAcceptsServiceToken(t *testing.T) {
	stub := newIAMStub(t)
	v := newVerifier(t, stub, "lux")

	id, err := v.Verify(t.Context(), stub.mint(t, claims{}))
	if err != nil {
		t.Fatalf("a valid KMS service token must verify: %v", err)
	}
	if id.Subject != "admin/lux-kms" {
		t.Errorf("Subject: got %q", id.Subject)
	}
	if id.Owner != "lux" {
		t.Errorf("Owner: got %q want lux", id.Owner)
	}
	if !id.Expires.After(time.Now()) {
		t.Errorf("Expires: got %v, want future", id.Expires)
	}
	t.Logf("verified: sub=%s owner=%s exp=%s", id.Subject, id.Owner, id.Expires.Format(time.RFC3339))
}

func TestIAMRefusals(t *testing.T) {
	stub := newIAMStub(t)
	other := newIAMStub(t) // a different IAM, with a different key
	v := newVerifier(t, stub, "lux")

	for _, tc := range []struct {
		name  string
		token func() string
	}{
		{"empty", func() string { return "" }},
		{"garbage", func() string { return "not.a.jwt" }},
		{"signed by another key", func() string { return other.mint(t, claims{}) }},
		{"wrong issuer", func() string { return stub.mint(t, claims{iss: "https://evil.example"}) }},
		{"expired", func() string { return stub.mint(t, claims{expiry: -time.Minute}) }},
		{"no expiry", func() string { return stub.mint(t, claims{noExp: true}) }},
		// Org scoping: a perfectly valid token for another org.
		{"another org", func() string { return stub.mint(t, claims{name: "zoo-kms"}) }},
		// "admin" is IAM's parent record, not an org. If it were treated as
		// one, every application token in the estate would reach this port.
		{"admin owner is not an org", func() string {
			return stub.mint(t, claims{typ: "user", name: "someone", owner: "admin"})
		}},
		// Boundary: "luxx" must not satisfy a port serving "lux".
		{"neighbouring org prefix", func() string { return stub.mint(t, claims{name: "luxx-kms"}) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id, err := v.Verify(t.Context(), tc.token())
			if err == nil {
				t.Fatalf("SECURITY: token accepted, identity=%+v", id)
			}
			t.Logf("refused: %v", err)
		})
	}
}

// TestIAMSubScopeIsAuthorized: a token for org "lux" reaches a port serving
// "lux-infra" — the documented sub-scope rule, matching luxfi/kms.
func TestIAMSubScopeIsAuthorized(t *testing.T) {
	stub := newIAMStub(t)
	v := newVerifier(t, stub, "lux-infra")
	if _, err := v.Verify(t.Context(), stub.mint(t, claims{name: "lux-kms"})); err != nil {
		t.Fatalf("org lux must reach sub-scope lux-infra: %v", err)
	}
}

// TestIAMTagOverridesName covers the operator escape hatch for service apps
// that don't follow <org>-<service>.
func TestIAMTagOverridesName(t *testing.T) {
	stub := newIAMStub(t)
	v := newVerifier(t, stub, "lux")
	if _, err := v.Verify(t.Context(), stub.mint(t, claims{name: "cross-cutting-thing", tag: "lux"})); err != nil {
		t.Fatalf("tag must authorize: %v", err)
	}
}

// TestIAMVerifierRequiresConfig: no endpoint or no org means no verifier,
// rather than one that accepts everything.
func TestIAMVerifierRequiresConfig(t *testing.T) {
	if _, err := NewIAMVerifier("", testIssuer, "lux"); err == nil {
		t.Error("empty JWKS endpoint must be refused")
	}
	if _, err := NewIAMVerifier(testIssuer, testIssuer, ""); err == nil {
		t.Error("empty org must be refused")
	}
}
