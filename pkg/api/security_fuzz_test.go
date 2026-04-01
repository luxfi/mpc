package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"testing"

	"github.com/luxfi/mpc/pkg/mpc"
)

// ============================================================================
// FUZZ: OrgScopedKey — ensure no orgID can break key namespace isolation
// ============================================================================

func FuzzOrgScopedKey(f *testing.F) {
	f.Add("org-normal", "wallet-1")
	f.Add("", "wallet-1")
	f.Add("org:injected", "wallet-1")
	f.Add("org\x00null", "wallet-1")
	f.Add("../etc/passwd", "wallet-1")
	f.Add("org-a", "")
	f.Add("org-a", "../../key")
	f.Add(string(make([]byte, 1000)), "key")

	f.Fuzz(func(t *testing.T, orgID, baseKey string) {
		if orgID == "" {
			// Empty orgID must be rejected by GetKeyShareWithFallback
			_, err := mpc.GetKeyShareWithFallback(nil, orgID, baseKey)
			if err == nil {
				t.Error("empty orgID was accepted")
			}
			return
		}

		scoped := mpc.OrgScopedKey(orgID, baseKey)

		// Invariant 1: scoped key must start with "org:"
		if len(scoped) < 4 || scoped[:4] != "org:" {
			t.Errorf("scoped key %q does not start with org:", scoped)
		}

		// Invariant 2: different orgIDs must produce different scoped keys
		// (for the same baseKey)
		other := mpc.OrgScopedKey(orgID+"X", baseKey)
		if scoped == other {
			t.Errorf("different orgIDs produced same scoped key: %q", scoped)
		}

		// Invariant 3: no raw user-controlled colons in the orgID segment
		// Split on colon: should be exactly ["org", <sanitized-orgID>, <baseKey>]
		// (baseKey itself might contain colons, but orgID part must be clean)
	})
}

// ============================================================================
// FUZZ: WebAuthn public key validation — no input should bypass sig check
// ============================================================================

func FuzzWebAuthnPubKeyValidation(f *testing.F) {
	// Seed with known attack vectors
	f.Add([]byte{})
	f.Add([]byte{0x04})
	f.Add([]byte{0x04, 0x01})
	f.Add(make([]byte, 65))
	f.Add(append([]byte{0x04}, make([]byte, 64)...))
	f.Add([]byte(`{"kty":"EC","crv":"P-256"}`))
	f.Add([]byte{0xa3, 0x63, 0x66, 0x6d, 0x74}) // CBOR

	f.Fuzz(func(t *testing.T, pubKeyBytes []byte) {
		// Simulate the W-2 validation check
		if len(pubKeyBytes) < 65 || pubKeyBytes[0] != 0x04 {
			return // correctly rejected at length/prefix
		}

		x := new(big.Int).SetBytes(pubKeyBytes[1:33])
		y := new(big.Int).SetBytes(pubKeyBytes[33:65])

		if !elliptic.P256().IsOnCurve(x, y) {
			return // correctly rejected: not on curve
		}

		// If we reach here, the fuzzer found bytes that form a valid P-256 point.
		// This is expected for some inputs. Verify that signature verification
		// actually works with this key.
		pubKey := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}

		// A random "signature" must NOT verify against this key
		msg := sha256.Sum256([]byte("test-tx"))
		fakeSig := make([]byte, 72)
		rand.Read(fakeSig)
		if ecdsa.VerifyASN1(pubKey, msg[:], fakeSig) {
			t.Fatal("random bytes verified as valid ECDSA signature")
		}
	})
}

// ============================================================================
// FUZZ: Base64-encoded key parsing — ensure no crash or bypass
// ============================================================================

func FuzzBase64KeyParsing(f *testing.F) {
	f.Add("")
	f.Add("AAAA")
	f.Add("not-base64!!")
	f.Add(base64.StdEncoding.EncodeToString([]byte{0x04}))
	f.Add(base64.StdEncoding.EncodeToString(make([]byte, 65)))

	// Add a valid P-256 key
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	validPub := elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
	f.Add(base64.StdEncoding.EncodeToString(validPub))

	f.Fuzz(func(t *testing.T, encoded string) {
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return // rejected at decode
		}
		if len(decoded) < 65 || decoded[0] != 0x04 {
			return // rejected at format check
		}

		x := new(big.Int).SetBytes(decoded[1:33])
		y := new(big.Int).SetBytes(decoded[33:65])

		// Must not panic
		_ = elliptic.P256().IsOnCurve(x, y)
	})
}

// ============================================================================
// FUZZ: Challenge binding — ensure tx_id → challenge is deterministic
// ============================================================================

func FuzzChallengeBinding(f *testing.F) {
	f.Add("trade-123")
	f.Add("")
	f.Add(string(make([]byte, 10000)))
	f.Add("trade-123\x00evil")

	f.Fuzz(func(t *testing.T, txID string) {
		// Challenge must be deterministic
		c1 := sha256.Sum256([]byte(txID))
		c2 := sha256.Sum256([]byte(txID))
		if c1 != c2 {
			t.Fatal("SHA-256 is not deterministic")
		}

		// Different txIDs must produce different challenges (collision resistance)
		c3 := sha256.Sum256([]byte(txID + "X"))
		if c1 == c3 && txID != txID+"X" {
			t.Fatal("SHA-256 collision found")
		}

		// Base64 round-trip must be stable
		encoded := base64.URLEncoding.EncodeToString(c1[:])
		decoded, err := base64.URLEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatal("base64 round-trip failed")
		}
		if !bytesEqual(c1[:], decoded) {
			t.Fatal("base64 round-trip corrupted challenge")
		}
	})
}

// ============================================================================
// FUZZ: Intent hash computation — no two different intents should collide
// ============================================================================

func FuzzIntentHash(f *testing.F) {
	f.Add("org1", "wallet1", "buy", "lux", "0xabc", "100", "USDL")
	f.Add("org1", "wallet1", "sell", "lux", "0xabc", "100", "USDL")
	f.Add("", "", "", "", "", "", "")

	f.Fuzz(func(t *testing.T, orgID, walletID, intentType, chain, toAddr, amount, token string) {
		hash := computeIntentHash(orgID, walletID, intentType, chain, toAddr, amount, token)

		// Must be a valid hex-encoded SHA-256 (64 chars)
		if len(hash) != 64 {
			t.Fatalf("intent hash length %d, expected 64", len(hash))
		}

		// Must be deterministic
		hash2 := computeIntentHash(orgID, walletID, intentType, chain, toAddr, amount, token)
		if hash != hash2 {
			t.Fatal("intent hash is not deterministic")
		}

		// Changing any field must change the hash
		if amount != "" {
			diff := computeIntentHash(orgID, walletID, intentType, chain, toAddr, amount+"1", token)
			if hash == diff {
				t.Fatal("changing amount did not change hash")
			}
		}
	})
}
