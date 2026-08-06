package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/require"
)

// These tests sit at the daemon's own boundary: eddsaPubKeyToSolAddress is the
// function whose return value becomes the sol_address field of a /keygen
// response, which is the string a customer is told to deposit into.

// TestSolAddressFromRealEd25519Key checks the happy path still produces exactly
// the base58 of the key, so the change that added a curve check did not also
// change the encoding.
func TestSolAddressFromRealEd25519Key(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	addr := eddsaPubKeyToSolAddress(pub)
	require.NotEmpty(t, addr)

	decoded, err := base58.Decode(addr)
	require.NoError(t, err)
	require.Equal(t, []byte(pub), decoded)
}

// TestSolAddressRefusesSecp256k1Keys is the regression guard for the bug this
// change removes.
//
// A BIP-340 x-only secp256k1 public key is 32 bytes, so the length test that
// used to guard this call site accepted it and base58-encoded it into a
// well-formed Solana address. Deposits to that address were unrecoverable,
// because no Ed25519 signature can ever satisfy a secp256k1 key. The daemon must
// now return "" and omit the field.
func TestSolAddressRefusesSecp256k1Keys(t *testing.T) {
	tested := 0
	for attempt := 0; attempt < 512 && tested < 32; attempt++ {
		candidate := make([]byte, 32)
		_, err := rand.Read(candidate)
		require.NoError(t, err)

		// Only interested in bytes that are genuinely a secp256k1 x-only key —
		// that is what makes this the real confusion and not just garbage.
		if _, err := (curve.Secp256k1{}).LiftX(candidate); err != nil {
			continue
		}
		// Skip the ~1-in-16 that also happen to be valid Ed25519 keys. Those are
		// indistinguishable by inspection, which is exactly why provenance and
		// not validation is the primary defence upstream of here.
		if err := (curve.Ed25519{}).NewPoint().UnmarshalBinary(candidate); err == nil {
			continue
		}
		tested++

		require.Len(t, candidate, 32, "the premise: it passes any length test")
		require.Empty(t, eddsaPubKeyToSolAddress(candidate),
			"a secp256k1 x-only key must never produce a Solana address: %x", candidate)
	}
	require.GreaterOrEqual(t, tested, 32, "did not find enough secp256k1-only keys to test")
}

// TestSolAddressRefusesMissingKey covers the ordinary case: the Ed25519 keygen
// leg failed, so there is no key. The daemon must publish a wallet with no
// Solana address rather than invent one.
func TestSolAddressRefusesMissingKey(t *testing.T) {
	for name, key := range map[string][]byte{
		"nil":       nil,
		"empty":     {},
		"truncated": make([]byte, 31),
		"oversized": make([]byte, 33),
	} {
		t.Run(name, func(t *testing.T) {
			require.Empty(t, eddsaPubKeyToSolAddress(key))
		})
	}
}
