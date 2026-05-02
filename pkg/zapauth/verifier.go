// Package zapauth gates the MPC ZAP server on a JWKS-validated bearer
// token presented BEFORE the X25519+ML-KEM-768 handshake (pkg/zap).
//
// Wire contract (LP-103):
//
//   1. Client sends OpAuthHello (0x00EF) carrying a bearer JWT in a
//      versioned frame. The server verifies signature via a cached JWKS,
//      checks iss + aud + exp, and records the claims keyed by the
//      ZAP peer ID for the lifetime of the connection.
//   2. Client sends OpClientHello (0x00F0). Server runs the existing
//      hybrid handshake unchanged. The session AEAD remains the only
//      authenticator on the wire after this point.
//   3. Subsequent KMS opcodes (0x00xx) dispatch as before. The
//      connection's claims are available on every handler via Session().
//
// Security boundary: zapauth authenticates the *peer*, not individual
// requests. A peer that successfully authenticates once may issue any
// opcode that its claims permit. Authorization (per-opcode policy) is
// the caller's responsibility — zapauth records claims and exposes them
// for downstream checks.
//
// Backwards compatibility: ZAP_AUTH_REQUIRED defaults to false in v1.14.0.
// When false, missing/invalid auth is logged and the connection proceeds
// in unauthenticated mode (legacy KMS clients keep working). When true,
// missing auth is rejected at OpClientHello and never reaches handshake
// state. The flag flips to true in v1.15.0 once every KMS deployment
// has rolled to a build that mints the bearer.
package zapauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// OpAuthHello is the opcode for the pre-handshake bearer-token frame.
// Reserved at 0x00EF — one slot below OpClientHello (0x00F0) so the
// auth message is wire-adjacent to the handshake it gates.
const OpAuthHello uint16 = 0x00EF

// CurrentFrameVersion is the wire revision of the auth hello frame.
// An incompatible peer rejects with ErrUnsupportedVersion.
const CurrentFrameVersion uint8 = 1

// Errors surfaced to callers and (in error frames) to remote peers.
// Keep error strings stable across releases — operators alert on them.
var (
	ErrMissingToken        = errors.New("zapauth: bearer token required")
	ErrInvalidToken        = errors.New("zapauth: token validation failed")
	ErrIssuerMismatch      = errors.New("zapauth: issuer mismatch")
	ErrAudienceMismatch    = errors.New("zapauth: audience mismatch")
	ErrTokenExpired        = errors.New("zapauth: token expired")
	ErrUnsupportedAlg      = errors.New("zapauth: unsupported alg")
	ErrUnsupportedVersion  = errors.New("zapauth: unsupported frame version")
	ErrJWKSFetch           = errors.New("zapauth: jwks fetch failed")
	ErrKidNotFound         = errors.New("zapauth: kid not in jwks")
	ErrTruncated           = errors.New("zapauth: frame truncated")
)

// Config controls one Verifier. Zero-value is invalid; call Validate()
// before NewVerifier to surface a missing JWKSURL early.
type Config struct {
	// JWKSURL is the absolute URL of the JWKS document. Required.
	JWKSURL string
	// ExpectedIssuer is matched exactly against the JWT iss claim. Required.
	ExpectedIssuer string
	// ExpectedAudiences is the allow-list. The JWT aud must contain at
	// least one of these. Required (empty list disables aud check, which
	// is rejected at Validate so callers don't ship a permissive setup).
	ExpectedAudiences []string
	// CacheTTL governs how long a JWKS fetch is reused. Default 5 minutes.
	CacheTTL time.Duration
	// HTTPClient overrides the default JWKS fetch client. Default has a
	// 10-second timeout and a 1MiB response size cap.
	HTTPClient *http.Client
	// Clock substitution for tests. Defaults to time.Now.
	Now func() time.Time
}

// Validate enforces invariants Config-wise so NewVerifier never returns
// a partially configured object.
func (c *Config) Validate() error {
	if strings.TrimSpace(c.JWKSURL) == "" {
		return errors.New("zapauth: JWKSURL required")
	}
	if strings.TrimSpace(c.ExpectedIssuer) == "" {
		return errors.New("zapauth: ExpectedIssuer required")
	}
	if len(c.ExpectedAudiences) == 0 {
		return errors.New("zapauth: at least one ExpectedAudience required")
	}
	for _, a := range c.ExpectedAudiences {
		if strings.TrimSpace(a) == "" {
			return errors.New("zapauth: ExpectedAudience entries must be non-empty")
		}
	}
	return nil
}

// Claims is the verified-claims subset zapauth surfaces to callers.
// Raw is the full claims map for callers that need additional fields.
type Claims struct {
	Subject  string
	Issuer   string
	Audience []string
	ExpiresAt time.Time
	Raw      map[string]any
}

// Verifier validates JWTs against a remote JWKS endpoint and tracks
// per-peer claims. A single Verifier is safe for concurrent use.
type Verifier struct {
	cfg    Config
	jwks   *jwksCache
	now    func() time.Time

	mu     sync.RWMutex
	claims map[string]Claims // keyed by ZAP peer ID
}

// NewVerifier constructs a Verifier from cfg. Returns an error when cfg
// is incomplete (see Config.Validate). The verifier does not contact the
// JWKS URL eagerly — first Verify() triggers the fetch.
func NewVerifier(cfg Config) (*Verifier, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = 5 * time.Minute
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Verifier{
		cfg:    cfg,
		jwks:   &jwksCache{url: cfg.JWKSURL, client: cfg.HTTPClient, ttl: cfg.CacheTTL, now: cfg.Now},
		now:    cfg.Now,
		claims: make(map[string]Claims),
	}, nil
}

// Verify validates a bearer token against the configured JWKS, issuer,
// and audience set. Returns the verified claims subset on success or a
// classified zapauth.* error on failure.
func (v *Verifier) Verify(ctx context.Context, token string) (*Claims, error) {
	if strings.TrimSpace(token) == "" {
		return nil, ErrMissingToken
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: malformed jwt", ErrInvalidToken)
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: header b64: %v", ErrInvalidToken, err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("%w: header json: %v", ErrInvalidToken, err)
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload b64: %v", ErrInvalidToken, err)
	}
	var raw map[string]any
	if err := json.Unmarshal(payloadBytes, &raw); err != nil {
		return nil, fmt.Errorf("%w: payload json: %v", ErrInvalidToken, err)
	}

	if iss, _ := raw["iss"].(string); iss != v.cfg.ExpectedIssuer {
		return nil, fmt.Errorf("%w: got %q want %q", ErrIssuerMismatch, iss, v.cfg.ExpectedIssuer)
	}
	if !audMatches(raw, v.cfg.ExpectedAudiences) {
		return nil, ErrAudienceMismatch
	}
	if expFloat, ok := raw["exp"].(float64); ok {
		exp := time.Unix(int64(expFloat), 0)
		if v.now().After(exp) {
			return nil, ErrTokenExpired
		}
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: signature b64: %v", ErrInvalidToken, err)
	}
	key, err := v.jwks.getKey(ctx, header.Kid)
	if err != nil {
		return nil, err
	}
	signed := []byte(parts[0] + "." + parts[1])
	if err := verifySignature(header.Alg, key, signed, sigBytes); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	c := Claims{Raw: raw}
	c.Subject, _ = raw["sub"].(string)
	c.Issuer, _ = raw["iss"].(string)
	c.Audience = audSlice(raw)
	if expFloat, ok := raw["exp"].(float64); ok {
		c.ExpiresAt = time.Unix(int64(expFloat), 0)
	}
	return &c, nil
}

// AttachClaims associates verified claims with a ZAP peer ID. The
// server stores this after a successful AuthHello. Subsequent handlers
// look up claims via Lookup() to enforce per-opcode policy.
func (v *Verifier) AttachClaims(peerID string, c Claims) {
	v.mu.Lock()
	v.claims[peerID] = c
	v.mu.Unlock()
}

// Lookup returns the claims attached to a peer ID, or false if the peer
// never authenticated (or auth was disabled by config).
func (v *Verifier) Lookup(peerID string) (Claims, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	c, ok := v.claims[peerID]
	return c, ok
}

// Drop releases per-peer claim state. Called by the ZAP server when a
// peer disconnects so claim memory doesn't grow unbounded.
func (v *Verifier) Drop(peerID string) {
	v.mu.Lock()
	delete(v.claims, peerID)
	v.mu.Unlock()
}

// audMatches returns true iff the JWT aud claim contains any allowed
// audience. JWT aud may be a string or an array of strings (RFC 7519).
func audMatches(claims map[string]any, allowed []string) bool {
	got := audSlice(claims)
	for _, a := range got {
		for _, want := range allowed {
			if a == want {
				return true
			}
		}
	}
	return false
}

// audSlice normalizes the aud claim to a slice.
func audSlice(claims map[string]any) []string {
	switch v := claims["aud"].(type) {
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, a := range v {
			if s, ok := a.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// ----------------------------------------------------------------------
// JWKS cache — stdlib only (mirrors goa/pkg/iam/oidc.go pattern).
// ----------------------------------------------------------------------

type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

type jwksCache struct {
	url    string
	client *http.Client
	ttl    time.Duration
	now    func() time.Time

	mu         sync.RWMutex
	keys       map[string]crypto.PublicKey
	fetchedAt  time.Time
}

func (c *jwksCache) getKey(ctx context.Context, kid string) (crypto.PublicKey, error) {
	c.mu.RLock()
	if c.keys != nil && c.now().Sub(c.fetchedAt) < c.ttl {
		if k, ok := c.keys[kid]; ok {
			c.mu.RUnlock()
			return k, nil
		}
	}
	c.mu.RUnlock()
	return c.fetchAndGet(ctx, kid)
}

func (c *jwksCache) fetchAndGet(ctx context.Context, kid string) (crypto.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.keys != nil && c.now().Sub(c.fetchedAt) < c.ttl {
		if k, ok := c.keys[kid]; ok {
			return k, nil
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrJWKSFetch, err)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrJWKSFetch, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d", ErrJWKSFetch, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrJWKSFetch, err)
	}
	var jwks jwksResponse
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrJWKSFetch, err)
	}
	keys := make(map[string]crypto.PublicKey, len(jwks.Keys))
	for _, k := range jwks.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pub, err := parseJWK(k)
		if err != nil {
			continue
		}
		keys[k.Kid] = pub
	}
	c.keys = keys
	c.fetchedAt = c.now()

	k, ok := keys[kid]
	if !ok {
		return nil, fmt.Errorf("%w: kid=%q", ErrKidNotFound, kid)
	}
	return k, nil
}

func parseJWK(k jwkKey) (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, err
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, err
		}
		n := new(big.Int).SetBytes(nBytes)
		e := 0
		for _, b := range eBytes {
			e = e<<8 | int(b)
		}
		return &rsa.PublicKey{N: n, E: e}, nil
	case "EC":
		xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, err
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return nil, err
		}
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("zapauth: unsupported curve %q", k.Crv)
		}
		return &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(xBytes), Y: new(big.Int).SetBytes(yBytes)}, nil
	case "OKP":
		xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, err
		}
		if len(xBytes) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("zapauth: invalid ed25519 key size %d", len(xBytes))
		}
		return ed25519.PublicKey(xBytes), nil
	default:
		return nil, fmt.Errorf("zapauth: unsupported key type %q", k.Kty)
	}
}

func verifySignature(alg string, key crypto.PublicKey, signed, sig []byte) error {
	switch alg {
	case "RS256":
		return verifyRSA(crypto.SHA256, key, signed, sig)
	case "RS384":
		return verifyRSA(crypto.SHA384, key, signed, sig)
	case "RS512":
		return verifyRSA(crypto.SHA512, key, signed, sig)
	case "ES256":
		return verifyECDSA(crypto.SHA256, key, signed, sig)
	case "ES384":
		return verifyECDSA(crypto.SHA384, key, signed, sig)
	case "ES512":
		return verifyECDSA(crypto.SHA512, key, signed, sig)
	case "EdDSA":
		return verifyEdDSA(key, signed, sig)
	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedAlg, alg)
	}
}

func verifyRSA(hash crypto.Hash, key crypto.PublicKey, signed, sig []byte) error {
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return errors.New("zapauth: key is not RSA")
	}
	h := hash.New()
	h.Write(signed)
	return rsa.VerifyPKCS1v15(rsaKey, hash, h.Sum(nil), sig)
}

func verifyECDSA(hash crypto.Hash, key crypto.PublicKey, signed, sig []byte) error {
	ecKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("zapauth: key is not ECDSA")
	}
	h := hash.New()
	h.Write(signed)
	digest := h.Sum(nil)
	// Try ASN.1 first (RFC 3279, what crypto/ecdsa.SignASN1 emits).
	if ecdsa.VerifyASN1(ecKey, digest, sig) {
		return nil
	}
	// JWS ES256/384/512 emit fixed-width R||S (RFC 7518 §3.4). Accept that.
	octetSize := (ecKey.Curve.Params().BitSize + 7) / 8
	if len(sig) == 2*octetSize {
		r := new(big.Int).SetBytes(sig[:octetSize])
		s := new(big.Int).SetBytes(sig[octetSize:])
		if ecdsa.Verify(ecKey, digest, r, s) {
			return nil
		}
	}
	return errors.New("zapauth: ecdsa signature invalid")
}

func verifyEdDSA(key crypto.PublicKey, signed, sig []byte) error {
	edKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return errors.New("zapauth: key is not Ed25519")
	}
	if !ed25519.Verify(edKey, signed, sig) {
		return errors.New("zapauth: ed25519 signature invalid")
	}
	return nil
}

// ----------------------------------------------------------------------
// Wire framing for OpAuthHello.
// ----------------------------------------------------------------------
//
// AuthHello frame layout (little-endian):
//
//   +0   uint8  version  // CurrentFrameVersion
//   +1   uint16 token_len
//   +3   [token_len]byte token
//
// Total = 3 + len(token). Tokens >64 KiB are rejected at MarshalAuthHello.

const maxTokenSize = 64 * 1024

// AuthHelloFrame is the parsed AuthHello payload (no opcode prefix).
type AuthHelloFrame struct {
	Version uint8
	Token   string
}

// MarshalAuthHello serializes an AuthHelloFrame to its on-the-wire bytes.
func MarshalAuthHello(f *AuthHelloFrame) ([]byte, error) {
	if len(f.Token) > maxTokenSize {
		return nil, fmt.Errorf("zapauth: token too large (%d > %d)", len(f.Token), maxTokenSize)
	}
	out := make([]byte, 3+len(f.Token))
	out[0] = f.Version
	binary.LittleEndian.PutUint16(out[1:3], uint16(len(f.Token)))
	copy(out[3:], f.Token)
	return out, nil
}

// UnmarshalAuthHello parses an AuthHello wire frame. Rejects future
// versions with ErrUnsupportedVersion so peers that ship a newer wire
// can negotiate downward instead of mis-parsing.
func UnmarshalAuthHello(b []byte) (*AuthHelloFrame, error) {
	if len(b) < 3 {
		return nil, ErrTruncated
	}
	f := &AuthHelloFrame{Version: b[0]}
	if f.Version != CurrentFrameVersion {
		return nil, fmt.Errorf("%w: got=%d want=%d", ErrUnsupportedVersion, f.Version, CurrentFrameVersion)
	}
	tokenLen := binary.LittleEndian.Uint16(b[1:3])
	if int(tokenLen) > maxTokenSize {
		return nil, fmt.Errorf("zapauth: declared token length %d exceeds max %d", tokenLen, maxTokenSize)
	}
	if len(b) < 3+int(tokenLen) {
		return nil, ErrTruncated
	}
	f.Token = string(b[3 : 3+int(tokenLen)])
	return f, nil
}
