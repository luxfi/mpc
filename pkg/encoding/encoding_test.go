package encoding

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncodeS256PubKey(t *testing.T) {
	// Generate a test ECDSA key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pubKey := &privateKey.PublicKey

	// Test encoding
	encoded, err := EncodeS256PubKey(pubKey)
	require.NoError(t, err)
	assert.NotEmpty(t, encoded)

	// The encoded key should be exactly 64 bytes (32 bytes X + 32 bytes Y)
	// regardless of the actual byte length of X and Y (fixed-size encoding)
	assert.Equal(t, 64, len(encoded))

	// Verify X is right-aligned in first 32 bytes
	xBytes := pubKey.X.Bytes()
	expectedX := make([]byte, 32)
	copy(expectedX[32-len(xBytes):], xBytes)
	assert.Equal(t, expectedX, encoded[:32])

	// Verify Y is right-aligned in last 32 bytes
	yBytes := pubKey.Y.Bytes()
	expectedY := make([]byte, 32)
	copy(expectedY[32-len(yBytes):], yBytes)
	assert.Equal(t, expectedY, encoded[32:])
}

func TestEncodeS256PubKey_SpecificValues(t *testing.T) {
	// Create a public key with specific values
	x := big.NewInt(12345)
	y := big.NewInt(67890)
	pubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	encoded, err := EncodeS256PubKey(pubKey)
	require.NoError(t, err)

	// The encoding should be exactly 64 bytes with fixed-size padding
	assert.Equal(t, 64, len(encoded))

	// X = 12345 = 0x3039, padded to 32 bytes (right-aligned)
	expectedX := make([]byte, 32)
	copy(expectedX[32-len(x.Bytes()):], x.Bytes())
	assert.Equal(t, expectedX, encoded[:32])

	// Y = 67890 = 0x10932, padded to 32 bytes (right-aligned)
	expectedY := make([]byte, 32)
	copy(expectedY[32-len(y.Bytes()):], y.Bytes())
	assert.Equal(t, expectedY, encoded[32:])
}

func TestEncodeEDDSAPubKey(t *testing.T) {
	// Generate a test EdDSA key pair using the correct API
	privateKey, err := edwards.GeneratePrivateKey()
	require.NoError(t, err)

	pubKey := privateKey.PubKey()

	// Test encoding
	encoded, err := EncodeEDDSAPubKey(pubKey)
	require.NoError(t, err)
	assert.NotEmpty(t, encoded)

	// EdDSA compressed public key should be 32 bytes (not 33 as initially assumed)
	assert.Equal(t, 32, len(encoded))
}

func TestDecodeEDDSAPubKey(t *testing.T) {
	// Generate a test EdDSA key pair
	privateKey, err := edwards.GeneratePrivateKey()
	require.NoError(t, err)

	originalPubKey := privateKey.PubKey()

	// Encode the public key
	encoded, err := EncodeEDDSAPubKey(originalPubKey)
	require.NoError(t, err)

	// Decode the public key
	decodedPubKey, err := DecodeEDDSAPubKey(encoded)
	require.NoError(t, err)
	assert.NotNil(t, decodedPubKey)

	// Verify the decoded key matches the original by comparing serialized forms
	originalSerialized := originalPubKey.SerializeCompressed()
	decodedSerialized := decodedPubKey.SerializeCompressed()
	assert.Equal(t, originalSerialized, decodedSerialized)
}

func TestDecodeEDDSAPubKey_InvalidData(t *testing.T) {
	// Test with invalid data
	invalidData := []byte("invalid key data")

	_, err := DecodeEDDSAPubKey(invalidData)
	assert.Error(t, err)
}

func TestDecodeEDDSAPubKey_EmptyData(t *testing.T) {
	// Test with empty data
	emptyData := []byte{}

	_, err := DecodeEDDSAPubKey(emptyData)
	assert.Error(t, err)
}

func TestEncodeDecodeEDDSA_RoundTrip(t *testing.T) {
	// Test multiple round trips to ensure consistency
	for i := 0; i < 10; i++ {
		// Generate a new key pair
		privateKey, err := edwards.GeneratePrivateKey()
		require.NoError(t, err)

		originalPubKey := privateKey.PubKey()

		// Encode
		encoded, err := EncodeEDDSAPubKey(originalPubKey)
		require.NoError(t, err)

		// Decode
		decodedPubKey, err := DecodeEDDSAPubKey(encoded)
		require.NoError(t, err)

		// Verify they match by comparing serialized forms
		originalSerialized := originalPubKey.SerializeCompressed()
		decodedSerialized := decodedPubKey.SerializeCompressed()
		assert.Equal(t, originalSerialized, decodedSerialized, "Round trip %d failed", i)
	}
}

func TestEncodeS256PubKey_NilPublicKey(t *testing.T) {
	// Test with nil public key - this should panic or return an error
	// depending on the implementation
	defer func() {
		if r := recover(); r != nil {
			// Expected panic due to nil pointer
			t.Log("Correctly panicked on nil public key")
		}
	}()

	_, err := EncodeS256PubKey(nil)
	if err == nil {
		t.Error("Expected error or panic with nil public key")
	}
}

func TestEncodeS256PubKey_ZeroCoordinates(t *testing.T) {
	// Test with zero coordinates
	x := big.NewInt(0)
	y := big.NewInt(0)
	pubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	encoded, err := EncodeS256PubKey(pubKey)
	require.NoError(t, err)

	// Should be exactly 64 bytes (all zeros for zero coordinates)
	assert.Equal(t, 64, len(encoded))
	// All bytes should be zero
	expected := make([]byte, 64)
	assert.Equal(t, expected, encoded)
}
