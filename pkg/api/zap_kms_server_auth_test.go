// Integration tests for the zapauth bearer-on-handshake gate.
//
// Spins a real KMSZapServer with a Verifier configured against a
// self-contained ES256 JWKS endpoint, dials it as a synthetic client,
// and exercises the AuthHello → ClientHello → Sign sequence end to end.
package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luxfi/mpc/pkg/zapauth"
	"github.com/luxfi/zap"
)

type authTestEnv struct {
	jwksServer *httptest.Server
	priv       *ecdsa.PrivateKey
	kid        string
}

func newAuthTestEnv(t *testing.T) *authTestEnv {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa: %v", err)
	}
	jwk := map[string]any{
		"kty": "EC", "kid": "kid-1", "alg": "ES256", "use": "sig", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(priv.PublicKey.X.Bytes()),
		"y": base64.RawURLEncoding.EncodeToString(priv.PublicKey.Y.Bytes()),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{jwk}})
	}))
	t.Cleanup(srv.Close)
	return &authTestEnv{jwksServer: srv, priv: priv, kid: "kid-1"}
}

func (e *authTestEnv) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	hdr := map[string]any{"alg": "ES256", "typ": "JWT", "kid": e.kid}
	hb, _ := json.Marshal(hdr)
	cb, _ := json.Marshal(claims)
	signing := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	digest := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, e.priv, digest[:])
	if err != nil {
		t.Fatalf("ecdsa sign: %v", err)
	}
	rb, sb := r.Bytes(), s.Bytes()
	out := make([]byte, 64)
	copy(out[32-len(rb):32], rb)
	copy(out[64-len(sb):], sb)
	_ = big.NewInt
	return signing + "." + base64.RawURLEncoding.EncodeToString(out)
}

func newVerifier(t *testing.T, env *authTestEnv) *zapauth.Verifier {
	t.Helper()
	v, err := zapauth.NewVerifier(zapauth.Config{
		JWKSURL:           env.jwksServer.URL,
		ExpectedIssuer:    "https://iam.test.local",
		ExpectedAudiences: []string{"liquid-mpc"},
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

func startServerWithAuth(t *testing.T, v *zapauth.Verifier, required bool) (*KMSZapServer, string, func()) {
	t.Helper()
	addr := pickPort(t)
	srv, err := StartKMSZAPWith(&stubBackend{}, "test-server-auth", addr, KMSZapConfig{
		Verifier: v, AuthRequired: required,
	})
	if err != nil {
		t.Fatalf("StartKMSZAPWith: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	return srv, addr, func() { srv.Stop() }
}

func sendAuthHello(t *testing.T, client *zap.Node, peer string, token string) (uint16, []byte) {
	t.Helper()
	frame, err := zapauth.MarshalAuthHello(&zapauth.AuthHelloFrame{Version: zapauth.CurrentFrameVersion, Token: token})
	if err != nil {
		t.Fatalf("MarshalAuthHello: %v", err)
	}
	body := make([]byte, 2+len(frame))
	binary.LittleEndian.PutUint16(body[:2], zapauth.OpAuthHello)
	copy(body[2:], frame)
	b := zap.NewBuilder(len(body) + 64)
	b.WriteBytes(body)
	msg, err := zap.Parse(b.Finish())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := client.Call(ctx, peer, msg)
	if err != nil {
		t.Fatalf("Call AuthHello: %v", err)
	}
	raw := resp.Bytes()
	rb := raw[zap.HeaderSize:]
	return binary.LittleEndian.Uint16(rb[:2]), rb[2:]
}

// TestKMSZAP_Auth_RequiredHappyPath: AuthRequired=true, valid JWT,
// then sign request succeeds.
func TestKMSZAP_Auth_RequiredHappyPath(t *testing.T) {
	env := newAuthTestEnv(t)
	v := newVerifier(t, env)
	_, addr, stop := startServerWithAuth(t, v, true)
	defer stop()
	client, peer := dialClient(t, addr)
	defer client.Stop()

	tok := env.sign(t, map[string]any{
		"iss": "https://iam.test.local",
		"aud": "liquid-mpc",
		"sub": "kms-pod-1",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	})
	op, body := sendAuthHello(t, client, peer, tok)
	if op != zapauth.OpAuthHello {
		t.Fatalf("auth resp opcode: got 0x%04x want 0x%04x", op, zapauth.OpAuthHello)
	}
	if !strings.Contains(string(body), `"ok":true`) {
		t.Fatalf("auth resp body: got %s", string(body))
	}

	// Now a sign call should succeed.
	respOp, signBody := callOp(t, client, peer, OpKMSSign, kmsZapSignRequest{
		VaultID:  "v1", WalletID: "w1", Payload: []byte("x"),
	})
	if respOp != OpKMSSign {
		t.Fatalf("sign opcode: got 0x%04x want 0x%04x", respOp, OpKMSSign)
	}
	var sr SignResult
	if err := json.Unmarshal(signBody, &sr); err != nil {
		t.Fatalf("unmarshal sign: %v body=%s", err, string(signBody))
	}
	if sr.R == "" {
		t.Fatalf("expected sign result R, got empty")
	}
}

// TestKMSZAP_Auth_RequiredRejectsMissing: AuthRequired=true and no
// AuthHello frame → sign request returns "auth required".
func TestKMSZAP_Auth_RequiredRejectsMissing(t *testing.T) {
	env := newAuthTestEnv(t)
	v := newVerifier(t, env)
	_, addr, stop := startServerWithAuth(t, v, true)
	defer stop()
	client, peer := dialClient(t, addr)
	defer client.Stop()

	op, body := callOp(t, client, peer, OpKMSSign, kmsZapSignRequest{
		VaultID:  "v1", WalletID: "w1", Payload: []byte("x"),
	})
	if op != OpKMSSign {
		t.Fatalf("opcode echo: got 0x%04x want 0x%04x", op, OpKMSSign)
	}
	if !strings.Contains(string(body), "auth required") {
		t.Fatalf("expected auth required, got %s", string(body))
	}
}

// TestKMSZAP_Auth_RequiredRejectsBadToken: AuthHello with a token that
// fails JWKS verification → AuthHello replies with the verifier error
// and a follow-up sign request is rejected because no claims attached.
func TestKMSZAP_Auth_RequiredRejectsBadToken(t *testing.T) {
	env := newAuthTestEnv(t)
	v := newVerifier(t, env)
	_, addr, stop := startServerWithAuth(t, v, true)
	defer stop()
	client, peer := dialClient(t, addr)
	defer client.Stop()

	tok := env.sign(t, map[string]any{
		"iss": "https://iam.test.local",
		"aud": "wrong-audience",
		"sub": "kms-pod-1",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	})
	_, body := sendAuthHello(t, client, peer, tok)
	if !strings.Contains(string(body), "audience mismatch") {
		t.Fatalf("expected audience mismatch, got %s", string(body))
	}

	op, signBody := callOp(t, client, peer, OpKMSSign, kmsZapSignRequest{
		VaultID:  "v1", WalletID: "w1", Payload: []byte("x"),
	})
	if op != OpKMSSign {
		t.Fatalf("opcode echo: got 0x%04x want 0x%04x", op, OpKMSSign)
	}
	if !strings.Contains(string(signBody), "auth required") {
		t.Fatalf("expected auth required after bad token, got %s", string(signBody))
	}
}

// TestKMSZAP_Auth_AdvisoryAcceptsMissing: ZAP_AUTH_REQUIRED=false (the
// v1.14.0 default) → sign request still succeeds even without auth.
func TestKMSZAP_Auth_AdvisoryAcceptsMissing(t *testing.T) {
	env := newAuthTestEnv(t)
	v := newVerifier(t, env)
	_, addr, stop := startServerWithAuth(t, v, false)
	defer stop()
	client, peer := dialClient(t, addr)
	defer client.Stop()

	op, body := callOp(t, client, peer, OpKMSSign, kmsZapSignRequest{
		VaultID:  "v1", WalletID: "w1", Payload: []byte("x"),
	})
	if op != OpKMSSign {
		t.Fatalf("opcode echo: got 0x%04x want 0x%04x", op, OpKMSSign)
	}
	var sr SignResult
	if err := json.Unmarshal(body, &sr); err != nil {
		t.Fatalf("unmarshal sign: %v body=%s", err, string(body))
	}
	if sr.R == "" {
		t.Fatalf("advisory mode should still serve sign; got empty R")
	}
}

// TestKMSZAP_Auth_RequiredVerifierMustBeNonNil: Without a verifier you
// cannot ask for AuthRequired=true.
func TestKMSZAP_Auth_RequiredVerifierMustBeNonNil(t *testing.T) {
	addr := pickPort(t)
	_, err := StartKMSZAPWith(&stubBackend{}, "id", addr, KMSZapConfig{Verifier: nil, AuthRequired: true})
	if err == nil {
		t.Fatalf("expected start error when AuthRequired=true and Verifier=nil")
	}
}
