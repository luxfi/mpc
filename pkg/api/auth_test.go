package api

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func newTestServer(secret string) *Server {
	return &Server{
		jwtSecret: []byte(secret),
	}
}

func TestGenerateAndValidateJWT(t *testing.T) {
	s := newTestServer("test-secret-key-for-jwt")

	token, err := s.generateJWT("user-123", "org-456", "admin")
	if err != nil {
		t.Fatalf("generateJWT: %v", err)
	}
	if token == "" {
		t.Fatal("generateJWT returned empty token")
	}

	claims, err := s.validateJWT(token)
	if err != nil {
		t.Fatalf("validateJWT: %v", err)
	}

	if claims.UserID != "user-123" {
		t.Errorf("UserID = %q, want %q", claims.UserID, "user-123")
	}
	if claims.OrgID != "org-456" {
		t.Errorf("OrgID = %q, want %q", claims.OrgID, "org-456")
	}
	if claims.Role != "admin" {
		t.Errorf("Role = %q, want %q", claims.Role, "admin")
	}

	// Check expiry is ~24h from now
	if claims.ExpiresAt == nil {
		t.Fatal("ExpiresAt is nil")
	}
	expDelta := time.Until(claims.ExpiresAt.Time)
	if expDelta < 23*time.Hour || expDelta > 25*time.Hour {
		t.Errorf("ExpiresAt delta = %v, want ~24h", expDelta)
	}
}

func TestHashPassword(t *testing.T) {
	password := "correct-horse-battery-staple"

	hash, err := hashPassword(password)
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	if hash == "" {
		t.Fatal("hashPassword returned empty hash")
	}
	if hash == password {
		t.Fatal("hash must not equal plaintext password")
	}

	// Correct password verifies
	if !checkPassword(hash, password) {
		t.Error("checkPassword(hash, correct) = false, want true")
	}

	// Wrong password does not verify
	if checkPassword(hash, "wrong-password") {
		t.Error("checkPassword(hash, wrong) = true, want false")
	}
}

func TestGenerateAPIKey(t *testing.T) {
	key, hash, err := generateAPIKeyToken()
	if err != nil {
		t.Fatalf("generateAPIKeyToken: %v", err)
	}

	// Key has "lux_" prefix
	if !strings.HasPrefix(key, "lux_") {
		t.Errorf("key prefix = %q, want lux_", key[:4])
	}

	// Key is lux_ + 64 hex chars = 68 chars total
	if len(key) != 68 {
		t.Errorf("key length = %d, want 68", len(key))
	}

	// Hash is a 64-char hex string (SHA-256)
	if len(hash) != 64 {
		t.Errorf("hash length = %d, want 64", len(hash))
	}

	// Two calls produce different keys
	key2, hash2, err := generateAPIKeyToken()
	if err != nil {
		t.Fatalf("generateAPIKeyToken (2nd call): %v", err)
	}
	if key == key2 {
		t.Error("two calls produced identical keys")
	}
	if hash == hash2 {
		t.Error("two calls produced identical hashes")
	}
}

func TestInvalidJWT_WrongSecret(t *testing.T) {
	s1 := newTestServer("secret-one")
	s2 := newTestServer("secret-two")

	token, err := s1.generateJWT("user-1", "org-1", "admin")
	if err != nil {
		t.Fatalf("generateJWT: %v", err)
	}

	// Validate with different secret must fail
	_, err = s2.validateJWT(token)
	if err == nil {
		t.Fatal("validateJWT with wrong secret should fail")
	}
}

func TestInvalidJWT_Expired(t *testing.T) {
	s := newTestServer("test-secret")

	// Manually create an expired token
	claims := JWTClaims{
		UserID: "user-exp",
		OrgID:  "org-exp",
		Role:   "viewer",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString(s.jwtSecret)
	if err != nil {
		t.Fatalf("sign expired token: %v", err)
	}

	_, err = s.validateJWT(tokenStr)
	if err == nil {
		t.Fatal("validateJWT should reject expired token")
	}
}

func TestInvalidJWT_Malformed(t *testing.T) {
	s := newTestServer("test-secret")

	_, err := s.validateJWT("not-a-jwt-token")
	if err == nil {
		t.Fatal("validateJWT should reject malformed token")
	}
}

func TestInvalidJWT_EmptyString(t *testing.T) {
	s := newTestServer("test-secret")

	_, err := s.validateJWT("")
	if err == nil {
		t.Fatal("validateJWT should reject empty string")
	}
}

// === JWT Issuer / Audience regression tests ===

func TestAccessToken_IssuerAndAudience(t *testing.T) {
	s := newTestServer("iss-aud-secret")

	tokenStr, err := s.generateJWT("u1", "o1", "admin")
	if err != nil {
		t.Fatalf("generateJWT: %v", err)
	}

	// Parse without validation to inspect raw claims.
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenStr, &JWTClaims{})
	if err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}
	claims := token.Claims.(*JWTClaims)

	if claims.Issuer != "mpc.lux.network" {
		t.Errorf("access token Issuer = %q, want %q", claims.Issuer, "mpc.lux.network")
	}
	found := false
	for _, aud := range claims.Audience {
		if aud == "mpc-api" {
			found = true
		}
	}
	if !found {
		t.Errorf("access token Audience = %v, want to contain %q", claims.Audience, "mpc-api")
	}
}

func TestRefreshToken_IssuerAndAudience(t *testing.T) {
	s := newTestServer("iss-aud-secret")

	tokenStr, err := s.generateRefreshToken("u1", "o1", "admin")
	if err != nil {
		t.Fatalf("generateRefreshToken: %v", err)
	}

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenStr, &JWTClaims{})
	if err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}
	claims := token.Claims.(*JWTClaims)

	if claims.Issuer != "mpc.lux.network" {
		t.Errorf("refresh token Issuer = %q, want %q", claims.Issuer, "mpc.lux.network")
	}
	found := false
	for _, aud := range claims.Audience {
		if aud == "mpc-refresh" {
			found = true
		}
	}
	if !found {
		t.Errorf("refresh token Audience = %v, want to contain %q", claims.Audience, "mpc-refresh")
	}
}

func TestValidateJWT_RejectsWrongIssuer(t *testing.T) {
	s := newTestServer("iss-test-secret")

	// Create a token with wrong issuer.
	claims := JWTClaims{
		UserID: "u1",
		OrgID:  "o1",
		Role:   "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "evil.example.com",
			Audience:  jwt.ClaimStrings{"mpc-api"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString(s.jwtSecret)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	_, err = s.validateJWT(tokenStr)
	if err == nil {
		t.Fatal("validateJWT should reject token with wrong issuer")
	}
}

func TestValidateJWT_RejectsWrongAudience(t *testing.T) {
	s := newTestServer("aud-test-secret")

	// Create a token with wrong audience.
	claims := JWTClaims{
		UserID: "u1",
		OrgID:  "o1",
		Role:   "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "mpc.lux.network",
			Audience:  jwt.ClaimStrings{"wrong-audience"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString(s.jwtSecret)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	_, err = s.validateJWT(tokenStr)
	if err == nil {
		t.Fatal("validateJWT should reject token with wrong audience")
	}
}

func TestValidateJWT_RejectsRefreshToken(t *testing.T) {
	s := newTestServer("cross-token-secret")

	// A refresh token (audience "mpc-refresh") must NOT pass validateJWT
	// (which expects audience "mpc-api").
	refreshStr, err := s.generateRefreshToken("u1", "o1", "admin")
	if err != nil {
		t.Fatalf("generateRefreshToken: %v", err)
	}

	_, err = s.validateJWT(refreshStr)
	if err == nil {
		t.Fatal("validateJWT should reject a refresh token (audience mpc-refresh)")
	}
}

func TestValidateRefreshToken_RejectsAccessToken(t *testing.T) {
	s := newTestServer("cross-token-secret")

	// An access token (audience "mpc-api") must NOT pass validateRefreshToken
	// (which expects audience "mpc-refresh").
	accessStr, err := s.generateJWT("u1", "o1", "admin")
	if err != nil {
		t.Fatalf("generateJWT: %v", err)
	}

	_, err = s.validateRefreshToken(accessStr)
	if err == nil {
		t.Fatal("validateRefreshToken should reject an access token (audience mpc-api)")
	}
}
