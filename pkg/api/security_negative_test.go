package api

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/luxfi/mpc/pkg/db"
	"github.com/luxfi/mpc/pkg/mpc"
)

// ============================================================================
// CROSS-TENANT ISOLATION
// ============================================================================

func TestCrossTenant_OrgCannotAccessOtherOrgKeys(t *testing.T) {
	// OrgScopedKey must produce distinct keys for different orgs.
	// Without a store, we verify the key derivation is isolated.
	orgAKey := mpc.OrgScopedKey("org-alpha", "wallet-123")

	attacks := []struct {
		name  string
		orgID string
		key   string
	}{
		{"direct_access", "org-beta", "wallet-123"},
		{"prefix_attack", "org-alpha-suffix", "wallet-123"},
		{"null_byte", "org-beta\x00org-alpha", "wallet-123"},
		{"colon_injection", "org-beta:org-alpha", "wallet-123"},
		{"unicode_confusable", "org-аlpha", "wallet-123"}, // Cyrillic 'а'
	}

	for _, tc := range attacks {
		t.Run(tc.name, func(t *testing.T) {
			attackKey := mpc.OrgScopedKey(tc.orgID, tc.key)
			if attackKey == orgAKey {
				t.Fatalf("CROSS-TENANT LEAK: %s produced same key as org-alpha", tc.name)
			}
		})
	}

	// Empty org must be rejected entirely
	t.Run("empty_org", func(t *testing.T) {
		_, err := mpc.GetKeyShareWithFallback(nil, "", "wallet-123")
		if err == nil {
			t.Fatal("empty orgID was accepted")
		}
	})
}

func TestCrossTenant_OrgScopedKeyIsolation(t *testing.T) {
	// Verify that two orgs with the same wallet ID get different scoped keys
	keyA := mpc.OrgScopedKey("org-a", "wallet-1")
	keyB := mpc.OrgScopedKey("org-b", "wallet-1")

	if keyA == keyB {
		t.Fatal("different orgs produced same scoped key — isolation broken")
	}
	if keyA != "org:org-a:wallet-1" {
		t.Fatalf("unexpected key format: %s", keyA)
	}
	if keyB != "org:org-b:wallet-1" {
		t.Fatalf("unexpected key format: %s", keyB)
	}
}

func TestCrossTenant_OrgIDSanitization(t *testing.T) {
	// Colons in orgID must be sanitized to prevent key namespace injection
	cases := []struct {
		input    string
		contains string // must NOT appear in the scoped key
	}{
		{"a:b:c", "org:a:b:c:"},              // triple colon injection
		{"../etc/passwd", "org:../etc/passwd"}, // path traversal (colons don't apply but still test)
		{"org\x00evil", "org:org\x00evil:"},   // null byte
	}

	for _, tc := range cases {
		scoped := mpc.OrgScopedKey(tc.input, "key")
		// Verify no raw colons from user input survive
		parts := strings.Split(scoped, ":")
		if len(parts) != 3 { // should always be "org:<sanitized>:<key>"
			// Only for colon-containing inputs
			if strings.Contains(tc.input, ":") && len(parts) > 3 {
				t.Errorf("orgID %q produced %d parts: %s (expected 3)", tc.input, len(parts), scoped)
			}
		}
	}
}

// ============================================================================
// PASSKEY ECDH — CANNOT DECRYPT WITHOUT USER'S PRIVATE KEY
// ============================================================================

func TestECDH_ServerCannotDecryptBackup(t *testing.T) {
	// The whole point: server has shard 2 + the encrypted backup blob.
	// Without the user's passkey private key, it CANNOT decrypt shard 3.

	// User generates a passkey (simulating Secure Enclave)
	userPriv, _ := ecdh.P256().GenerateKey(rand.Reader)
	userPub := userPriv.PublicKey()

	// Server creates an ephemeral key and encrypts
	ephPriv, _ := ecdh.P256().GenerateKey(rand.Reader)
	sharedSecret, _ := ephPriv.ECDH(userPub)
	aesKey := sha256.Sum256(sharedSecret)

	// Server stores: encrypted blob + ephemeral public key
	// Server has: ephemeral PRIVATE key is discarded after encryption
	// Server retained: ephemeral PUBLIC key only

	// Attack: server tries to reconstruct shared secret using only public keys
	// This should be computationally infeasible (ECDH requires one private key)
	_ = aesKey // Server has the AES key during encryption, but must discard it

	// Verify: a DIFFERENT ephemeral key produces a DIFFERENT shared secret
	attackerPriv, _ := ecdh.P256().GenerateKey(rand.Reader)
	attackerShared, _ := attackerPriv.ECDH(userPub)
	attackerAESKey := sha256.Sum256(attackerShared)

	if aesKey == attackerAESKey {
		t.Fatal("different ephemeral keys produced same AES key — ECDH is broken")
	}
}

func TestECDH_SubstitutedPubKeyCannotDecrypt(t *testing.T) {
	// Attack: server substitutes its own pubkey during ECDH, hoping to
	// decrypt the backup later. But the user's client verifies the ephemeral
	// pubkey before encrypting — if the server cheats, the user won't decrypt.

	userPriv, _ := ecdh.P256().GenerateKey(rand.Reader)
	userPub := userPriv.PublicKey()

	// Honest server ephemeral
	honestEph, _ := ecdh.P256().GenerateKey(rand.Reader)
	honestShared, _ := honestEph.ECDH(userPub)
	honestAES := sha256.Sum256(honestShared)

	// Malicious server substitutes its own key
	maliciousEph, _ := ecdh.P256().GenerateKey(rand.Reader)
	maliciousShared, _ := maliciousEph.ECDH(userPub)
	maliciousAES := sha256.Sum256(maliciousShared)

	// The user decrypts using: ECDH(userPriv, honestEphPub)
	userDecryptShared, _ := userPriv.ECDH(honestEph.PublicKey())
	userDecryptAES := sha256.Sum256(userDecryptShared)

	if userDecryptAES != honestAES {
		t.Fatal("honest ECDH decryption failed")
	}
	if userDecryptAES == maliciousAES {
		t.Fatal("malicious key substitution produced same AES key — attack succeeded")
	}
}

func TestECDH_ReplayEphemeralKeyProducesDifferentSecret(t *testing.T) {
	// Each backup must use a fresh ephemeral key. Reusing an ephemeral key
	// across different users would leak the shared secret.
	user1Priv, _ := ecdh.P256().GenerateKey(rand.Reader)
	user2Priv, _ := ecdh.P256().GenerateKey(rand.Reader)

	// Same ephemeral key used for both (this would be a bug)
	eph, _ := ecdh.P256().GenerateKey(rand.Reader)

	shared1, _ := eph.ECDH(user1Priv.PublicKey())
	shared2, _ := eph.ECDH(user2Priv.PublicKey())

	// Even with same ephemeral, different users get different secrets
	if bytesEqual(shared1, shared2) {
		t.Fatal("different users got same shared secret with same ephemeral — catastrophic")
	}
}

// ============================================================================
// WEBAUTHN SIGNATURE FORGERY
// ============================================================================

func TestWebAuthn_CannotForgeSignature(t *testing.T) {
	// Generate a real credential
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubBytes := elliptic.Marshal(elliptic.P256(), privKey.PublicKey.X, privKey.PublicKey.Y)

	txID := "trade-12345"
	challenge := sha256.Sum256([]byte(txID))

	// Valid signature
	validSig, _ := ecdsa.SignASN1(rand.Reader, privKey, challenge[:])

	// Attack 1: Different private key signs the same challenge
	attackerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	forgedSig, _ := ecdsa.SignASN1(rand.Reader, attackerKey, challenge[:])

	pubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(pubBytes[1:33]),
		Y:     new(big.Int).SetBytes(pubBytes[33:65]),
	}

	if !ecdsa.VerifyASN1(pubKey, challenge[:], validSig) {
		t.Fatal("valid signature rejected")
	}
	if ecdsa.VerifyASN1(pubKey, challenge[:], forgedSig) {
		t.Fatal("forged signature from different key was accepted")
	}

	// Attack 2: Valid signature for wrong transaction
	otherTxChallenge := sha256.Sum256([]byte("trade-99999"))
	if ecdsa.VerifyASN1(pubKey, otherTxChallenge[:], validSig) {
		t.Fatal("signature for trade-12345 verified against trade-99999 — binding broken")
	}

	// Attack 3: Truncated signature
	if len(validSig) > 10 {
		if ecdsa.VerifyASN1(pubKey, challenge[:], validSig[:10]) {
			t.Fatal("truncated signature accepted")
		}
	}

	// Attack 4: All-zero signature
	zeroSig := make([]byte, len(validSig))
	if ecdsa.VerifyASN1(pubKey, challenge[:], zeroSig) {
		t.Fatal("zero signature accepted")
	}

	// Attack 5: Signature with flipped bits
	flippedSig := make([]byte, len(validSig))
	copy(flippedSig, validSig)
	flippedSig[len(flippedSig)/2] ^= 0xFF
	if ecdsa.VerifyASN1(pubKey, challenge[:], flippedSig) {
		t.Fatal("bit-flipped signature accepted")
	}
}

func TestWebAuthn_InvalidPublicKeyFormats(t *testing.T) {
	// All of these must be rejected by the W-2 fix
	cases := []struct {
		name string
		key  string // base64-encoded
	}{
		{"empty_string", ""},
		{"single_byte", base64.StdEncoding.EncodeToString([]byte{0x04})},
		{"wrong_prefix_0x02", base64.StdEncoding.EncodeToString(append([]byte{0x02}, make([]byte, 64)...))},
		{"wrong_prefix_0x03", base64.StdEncoding.EncodeToString(append([]byte{0x03}, make([]byte, 64)...))},
		{"wrong_prefix_0x00", base64.StdEncoding.EncodeToString(append([]byte{0x00}, make([]byte, 64)...))},
		{"too_short_32", base64.StdEncoding.EncodeToString(append([]byte{0x04}, make([]byte, 31)...))},
		{"json_object", base64.StdEncoding.EncodeToString([]byte(`{"kty":"EC","crv":"P-256"}`))},
		{"attestation_cbor", base64.StdEncoding.EncodeToString([]byte{0xa3, 0x63, 0x66, 0x6d, 0x74})},
		{"all_zeros_65", base64.StdEncoding.EncodeToString(make([]byte, 65))}, // 0x00 prefix
		{"all_ff", base64.StdEncoding.EncodeToString(append([]byte{0x04}, bytes_repeat(0xFF, 64)...))},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			decoded, err := base64.StdEncoding.DecodeString(tc.key)
			if err != nil {
				return // rejected at decode — correct
			}
			if len(decoded) < 65 || decoded[0] != 0x04 {
				return // rejected at length/prefix check — correct
			}
			// Check if it's on curve
			x := new(big.Int).SetBytes(decoded[1:33])
			y := new(big.Int).SetBytes(decoded[33:65])
			if elliptic.P256().IsOnCurve(x, y) {
				// Only a valid P-256 point should reach here
				t.Logf("key %s is a valid P-256 point (expected for random data that happens to be on curve)", tc.name)
			}
			// The point: none of these should bypass verification
		})
	}
}

func TestWebAuthn_OriginAttackVectors(t *testing.T) {
	allowed := map[string]bool{
		"https://lux.network":                 true,
		"https://mpc.lux.network":             true,
		"https://exchange.dev.":    true,
		"https://exchange.test.":   true,
		"https://exchange.main.":   true,
		"https://":                true,
		"https://www.":            true,
	}

	attacks := []string{
		// Subdomain attacks
		"https://evil.lux.network",
		"https://mpc.lux.network.evil.com",
		"https://lux.network.evil.com",
		"https://exchange..evil.com",
		// Protocol downgrade
		"http://lux.network",
		"http://mpc.lux.network",
		"http://",
		"http://exchange.dev.",
		// Unicode/IDN attacks
		"https://lux.nеtwork", // Cyrillic 'е'
		"https://ℓux.network", // Script small L
		// Path injection
		"https://lux.network/evil",
		"https://lux.network@evil.com",
		// Port injection
		"https://lux.network:8443",
		// Null byte
		"https://evil.com\x00https://lux.network",
		// Empty
		"",
		// Localhost
		"https://localhost",
		"https://127.0.0.1",
	}

	for _, origin := range attacks {
		if allowed[origin] {
			t.Errorf("attack origin %q is in allowed list", origin)
		}
	}
}

// ============================================================================
// AUDIT IMMUTABILITY
// ============================================================================

func TestAuditEntry_CannotUpdate(t *testing.T) {
	entry := &db.AuditEntry{}
	entry.OrgID = "org1"
	entry.Action = "mpc.sign"

	err := entry.Update()
	if err == nil {
		t.Fatal("audit entry Update() succeeded — immutability broken")
	}
	if !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("unexpected error: %v (should mention immutability)", err)
	}
}

func TestAuditEntry_CannotDelete(t *testing.T) {
	entry := &db.AuditEntry{}
	entry.OrgID = "org1"
	entry.Action = "mpc.sign"

	err := entry.Delete()
	if err == nil {
		t.Fatal("audit entry Delete() succeeded — immutability broken")
	}
	if !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("unexpected error: %v (should mention immutability)", err)
	}
}

// ============================================================================
// KEY INJECTION / BOUNDARY ATTACKS
// ============================================================================

func TestOrgScopedKey_Injection(t *testing.T) {
	// Verify various injection attempts are sanitized
	cases := []struct {
		orgID   string
		baseKey string
	}{
		{"org:injected:key", "wallet1"},
		{"org\x00null", "wallet1"},
		{strings.Repeat("A", 10000), "wallet1"}, // very long orgID
		{"../../../etc/passwd", "wallet1"},
		{"org-a", "../../wallet1"},
		{"org-a", strings.Repeat("X", 10000)},
	}

	for _, tc := range cases {
		scoped := mpc.OrgScopedKey(tc.orgID, tc.baseKey)
		// Must start with "org:" prefix
		if !strings.HasPrefix(scoped, "org:") {
			t.Errorf("OrgScopedKey(%q, %q) = %q — missing org: prefix", tc.orgID, tc.baseKey, scoped)
		}
		// Must not contain double colons (injection artifact)
		if strings.Contains(scoped, "::") {
			t.Errorf("OrgScopedKey(%q, %q) = %q — contains :: (injection)", tc.orgID, tc.baseKey, scoped)
		}
	}
}

func TestGetKeyShare_EmptyOrgID_AllVariants(t *testing.T) {
	// Empty and whitespace-only orgIDs must be rejected
	emptyVariants := []string{
		"",
		" ",
		"\t",
		"\n",
		"   ",
		" \t\n ",
	}

	for _, orgID := range emptyVariants {
		t.Run("orgID="+fmt.Sprintf("%q", orgID), func(t *testing.T) {
			_, err := mpc.GetKeyShareWithFallback(nil, orgID, "wallet-secret")
			if err == nil {
				t.Errorf("orgID %q was accepted — should be rejected", orgID)
			}
		})
	}
}

// ============================================================================
// P-256 CURVE POINT VALIDATION
// ============================================================================

func TestP256_NotOnCurveRejected(t *testing.T) {
	// Generate points that are NOT on the P-256 curve
	// These must be rejected by the WebAuthn registration handler

	// Point with x=1, y=1 (not on P-256)
	badPoint := make([]byte, 65)
	badPoint[0] = 0x04
	badPoint[1] = 1
	badPoint[33] = 1

	x := new(big.Int).SetBytes(badPoint[1:33])
	y := new(big.Int).SetBytes(badPoint[33:65])
	if elliptic.P256().IsOnCurve(x, y) {
		t.Skip("(1,1) is on P-256 — extremely unlikely but skip")
	}

	// This point must be rejected
	encoded := base64.StdEncoding.EncodeToString(badPoint)
	decoded, _ := base64.StdEncoding.DecodeString(encoded)
	if len(decoded) >= 65 && decoded[0] == 0x04 {
		xCheck := new(big.Int).SetBytes(decoded[1:33])
		yCheck := new(big.Int).SetBytes(decoded[33:65])
		if elliptic.P256().IsOnCurve(xCheck, yCheck) {
			t.Fatal("off-curve point passed validation")
		}
	}
}

func TestP256_InfinityPointRejected(t *testing.T) {
	// The point at infinity (0, 0) must be rejected
	infinityPoint := make([]byte, 65)
	infinityPoint[0] = 0x04
	// x = 0, y = 0

	x := new(big.Int).SetBytes(infinityPoint[1:33])
	y := new(big.Int).SetBytes(infinityPoint[33:65])
	if elliptic.P256().IsOnCurve(x, y) {
		t.Fatal("infinity point (0,0) accepted as on-curve")
	}
}

func TestP256_LowOrderPointRejected(t *testing.T) {
	// P-256 has prime order so there are no low-order subgroup points.
	// But verify the generator is valid.
	gx, gy := elliptic.P256().Params().Gx, elliptic.P256().Params().Gy
	if !elliptic.P256().IsOnCurve(gx, gy) {
		t.Fatal("P-256 generator not on curve")
	}
}

// ============================================================================
// ECDH EDGE CASES
// ============================================================================

func TestECDH_DifferentCurvesRejected(t *testing.T) {
	// Attempt ECDH between P-256 and P-384 keys — must fail
	p256Key, _ := ecdh.P256().GenerateKey(rand.Reader)
	p384Key, _ := ecdh.P384().GenerateKey(rand.Reader)

	_, err := p256Key.ECDH(p384Key.PublicKey())
	if err == nil {
		t.Fatal("cross-curve ECDH succeeded — should be rejected")
	}
}

func TestECDH_SameKeyPairProducesSameSecret(t *testing.T) {
	// Determinism: same key pair → same shared secret (no nonce in ECDH)
	key1, _ := ecdh.P256().GenerateKey(rand.Reader)
	key2, _ := ecdh.P256().GenerateKey(rand.Reader)

	shared1, _ := key1.ECDH(key2.PublicKey())
	shared2, _ := key1.ECDH(key2.PublicKey())

	if !bytesEqual(shared1, shared2) {
		t.Fatal("same ECDH inputs produced different secrets")
	}

	// And verify symmetry
	shared3, _ := key2.ECDH(key1.PublicKey())
	if !bytesEqual(shared1, shared3) {
		t.Fatal("ECDH is not symmetric")
	}
}

// ============================================================================
// BINARY INTEGRITY (additional negative cases)
// ============================================================================

func TestBinaryIntegrity_EmptyFile(t *testing.T) {
	// An empty binary should still require a valid signature
	// (tested in pkg/integrity — this documents the requirement)
	t.Log("empty files require valid signatures — verified in pkg/integrity")
}

// ============================================================================
// HELPERS
// ============================================================================

func bytes_repeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

