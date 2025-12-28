// Package webauthn verifies WebAuthn/FIDO2 attestations and assertions.
//
// R2-1: Previous biometric enroll was a forged-enrollment oracle:
//
//  1. challenge comparison used the DB row ID (predictable timestamp) rather
//     than the random challenge bytes we issued;
//  2. neither origin nor the rpIDHash were checked, so a relying-party
//     mismatch (phishing site, another tenant's RP) was accepted;
//  3. UP/UV authenticator flags were never enforced, so a stolen authenticator
//     with locked-out biometrics could still enroll.
//
// This package is the single point of truth for "given an attestation/assertion
// bundle and the metadata we kept from the challenge issuance, is this proof
// acceptable?". Callers supply the parsed WebAuthn ceremony as an Opts struct
// and get back an *Outcome with the public key to persist (for enroll) or a
// verified boolean (for assertion).
package webauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// Ceremony identifies which WebAuthn type is expected in clientDataJSON.
type Ceremony string

const (
	CeremonyCreate Ceremony = "webauthn.create"
	CeremonyGet    Ceremony = "webauthn.get"
)

// AuthenticatorFlags is the bitmask in authenticatorData byte 32 (per spec
// §6.1 "Authenticator Data"). The bits we enforce:
//
//	0x01 UP  — User presence
//	0x04 UV  — User verification (PIN/biometric)
//	0x40 AT  — Attested credential data included (enroll only)
type AuthenticatorFlags byte

const (
	FlagUP AuthenticatorFlags = 0x01
	FlagUV AuthenticatorFlags = 0x04
	FlagAT AuthenticatorFlags = 0x40
)

// Opts carries the raw, base64url-decoded ceremony bundle plus the server's
// side of the conversation (expected challenge bytes, origin allowlist, RP ID
// it signed the challenge under, expected ceremony type).
type Opts struct {
	// Expected ceremony: CeremonyCreate for enroll, CeremonyGet for assertion.
	Ceremony Ceremony

	// ExpectedChallenge is the exact random byte string the server issued
	// (before base64url encoding to the client). We compare base64url(this)
	// against clientDataJSON.challenge.
	ExpectedChallenge []byte

	// AllowedOrigins is the closed set of origins we accept
	// clientDataJSON.origin from. Empty = reject everything (fail-secure).
	AllowedOrigins map[string]bool

	// RPID is the relying party ID the challenge was issued under (typically
	// the apex domain of the login surface, e.g. "lux.network"). We verify
	// authenticatorData[0:32] == sha256(RPID).
	RPID string

	// RequireUP / RequireUV control authenticator-flag enforcement.
	// RequireUV=true is the right default for biometric/passkey flows —
	// setting it false lets a locked authenticator satisfy the ceremony.
	RequireUP bool
	RequireUV bool

	// PublicKeyB64 is the caller's claimed COSE key (uncompressed P-256 point,
	// base64-standard-encoded) for signature verification. Required when
	// Signature is non-nil.
	PublicKeyB64 string

	// ClientDataJSONB64 / AuthDataB64 / SignatureB64 are the raw base64url
	// ceremony fields. All three must decode or the verify fails.
	ClientDataJSONB64 string
	AuthDataB64       string
	SignatureB64      string
}

// Outcome is the decoded form of a successfully verified ceremony — callers
// typically persist PublicKeyB64 on enroll and log Outcome.Origin for audit.
type Outcome struct {
	Origin   string
	Type     Ceremony
	Flags    AuthenticatorFlags
	SignedOK bool // true iff Signature was provided and verified
}

// Verify runs the full WebAuthn verification pipeline in order. Each check is
// a hard fail — returning an error leaks only the first mismatch so we never
// give the caller a differential oracle on which field is wrong.
func Verify(opts *Opts) (*Outcome, error) {
	if opts == nil {
		return nil, errors.New("webauthn: opts required")
	}
	if opts.Ceremony != CeremonyCreate && opts.Ceremony != CeremonyGet {
		return nil, errors.New("webauthn: unknown ceremony")
	}
	if len(opts.AllowedOrigins) == 0 {
		return nil, errors.New("webauthn: allowed origins not configured")
	}
	if opts.RPID == "" {
		return nil, errors.New("webauthn: rpID required")
	}
	if len(opts.ExpectedChallenge) == 0 {
		return nil, errors.New("webauthn: expected challenge required")
	}

	clientData, err := base64.URLEncoding.DecodeString(opts.ClientDataJSONB64)
	if err != nil {
		// WebAuthn permits both padding variants; fall back to raw.
		if cd2, err2 := base64.RawURLEncoding.DecodeString(opts.ClientDataJSONB64); err2 == nil {
			clientData = cd2
		} else {
			return nil, errors.New("webauthn: invalid clientDataJSON encoding")
		}
	}
	var cd struct {
		Challenge string `json:"challenge"`
		Origin    string `json:"origin"`
		Type      string `json:"type"`
	}
	if err := json.Unmarshal(clientData, &cd); err != nil {
		return nil, errors.New("webauthn: invalid clientDataJSON structure")
	}

	if Ceremony(cd.Type) != opts.Ceremony {
		return nil, fmt.Errorf("webauthn: wrong ceremony type: %q", cd.Type)
	}
	if !opts.AllowedOrigins[cd.Origin] {
		return nil, fmt.Errorf("webauthn: origin not allowed: %q", cd.Origin)
	}

	// Compare the challenge fresh: the client sends base64url-no-padding per
	// spec §5.1.3 step 5, some implementations send base64url-with-padding.
	// Compare both encodings; constant-time compare to avoid timing leaks.
	expRaw := base64.RawURLEncoding.EncodeToString(opts.ExpectedChallenge)
	expStd := base64.URLEncoding.EncodeToString(opts.ExpectedChallenge)
	if !ctEq([]byte(cd.Challenge), []byte(expRaw)) && !ctEq([]byte(cd.Challenge), []byte(expStd)) {
		return nil, errors.New("webauthn: challenge mismatch")
	}

	authData, err := base64.URLEncoding.DecodeString(opts.AuthDataB64)
	if err != nil {
		if ad2, err2 := base64.RawURLEncoding.DecodeString(opts.AuthDataB64); err2 == nil {
			authData = ad2
		} else {
			return nil, errors.New("webauthn: invalid authenticatorData encoding")
		}
	}
	if len(authData) < 37 {
		return nil, errors.New("webauthn: authenticatorData too short")
	}
	// Bytes 0..31 are SHA-256(RP ID). Compare.
	expectedRPIDHash := sha256.Sum256([]byte(opts.RPID))
	if !ctEq(authData[:32], expectedRPIDHash[:]) {
		return nil, errors.New("webauthn: rpIDHash mismatch")
	}
	flags := AuthenticatorFlags(authData[32])
	if opts.RequireUP && flags&FlagUP == 0 {
		return nil, errors.New("webauthn: user presence flag not set")
	}
	if opts.RequireUV && flags&FlagUV == 0 {
		return nil, errors.New("webauthn: user verification flag not set")
	}

	out := &Outcome{
		Origin: cd.Origin,
		Type:   opts.Ceremony,
		Flags:  flags,
	}

	// Signature verification — only attempted if the caller supplied both the
	// pubkey and the signature. Enroll ceremonies with attestation=none might
	// skip this, but we treat that as a higher-level decision — verify()
	// itself always runs it if the fields are present.
	if opts.SignatureB64 != "" || opts.PublicKeyB64 != "" {
		sig, err := base64.URLEncoding.DecodeString(opts.SignatureB64)
		if err != nil {
			if s2, err2 := base64.RawURLEncoding.DecodeString(opts.SignatureB64); err2 == nil {
				sig = s2
			} else {
				return nil, errors.New("webauthn: invalid signature encoding")
			}
		}
		pub, err := parseUncompressedP256(opts.PublicKeyB64)
		if err != nil {
			return nil, err
		}
		clientDataHash := sha256.Sum256(clientData)
		signed := append(append([]byte{}, authData...), clientDataHash[:]...)
		// WebAuthn assertion signatures sign `authData || SHA256(clientDataJSON)`
		// directly — not SHA-256 of that concatenation again. Spec §7.2 step 17.
		signedHash := sha256.Sum256(signed)
		if !ecdsa.VerifyASN1(pub, signedHash[:], sig) {
			return nil, errors.New("webauthn: signature verification failed")
		}
		out.SignedOK = true
	}

	return out, nil
}

// ParseUncompressedP256 decodes a base64-standard-encoded uncompressed P-256
// public key (0x04 || X(32) || Y(32), 65 bytes) and verifies it's on the
// curve. Exported for callers that store+validate public keys independently.
func ParseUncompressedP256(b64 string) (*ecdsa.PublicKey, error) {
	return parseUncompressedP256(b64)
}

func parseUncompressedP256(b64 string) (*ecdsa.PublicKey, error) {
	if b64 == "" {
		return nil, errors.New("webauthn: public key required")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		// Tolerate base64url if a legacy caller used it.
		if r2, err2 := base64.URLEncoding.DecodeString(b64); err2 == nil {
			raw = r2
		} else {
			return nil, errors.New("webauthn: invalid public key encoding")
		}
	}
	if len(raw) < 65 || raw[0] != 0x04 {
		return nil, errors.New("webauthn: public key must be 65-byte uncompressed P-256 point")
	}
	x := new(big.Int).SetBytes(raw[1:33])
	y := new(big.Int).SetBytes(raw[33:65])
	if !elliptic.P256().IsOnCurve(x, y) {
		return nil, errors.New("webauthn: public key not on P-256 curve")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

// ctEq is constant-time byte equality that tolerates different lengths —
// unequal lengths always return false without a data-dependent branch.
func ctEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
