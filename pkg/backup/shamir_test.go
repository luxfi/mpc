package backup

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShamirSplitCombine2of2(t *testing.T) {
	secret := []byte("wallet-key-share-secp256k1-privkey-material")

	shares, err := ShamirSplit(secret, 2, 2)
	require.NoError(t, err)
	require.Len(t, shares, 2)

	// Both shares required
	recovered, err := ShamirCombine(shares)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(secret, recovered), "recovered secret must match original")
}

func TestShamirSplitCombine2of3(t *testing.T) {
	secret := []byte("threshold-signing-key-material-32bytes!")

	shares, err := ShamirSplit(secret, 3, 2)
	require.NoError(t, err)
	require.Len(t, shares, 3)

	// Any 2 of 3 should work
	combos := [][]Share{
		{shares[0], shares[1]},
		{shares[0], shares[2]},
		{shares[1], shares[2]},
	}
	for i, combo := range combos {
		recovered, err := ShamirCombine(combo)
		require.NoError(t, err, "combo %d failed", i)
		assert.True(t, bytes.Equal(secret, recovered), "combo %d: recovered secret must match", i)
	}

	// All 3 should also work
	recovered, err := ShamirCombine(shares)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(secret, recovered))
}

func TestShamirSplitCombine3of5(t *testing.T) {
	secret := make([]byte, 64)
	_, err := rand.Read(secret)
	require.NoError(t, err)

	shares, err := ShamirSplit(secret, 5, 3)
	require.NoError(t, err)
	require.Len(t, shares, 5)

	// Any 3 of 5 should work
	combos := [][]Share{
		{shares[0], shares[1], shares[2]},
		{shares[0], shares[2], shares[4]},
		{shares[1], shares[3], shares[4]},
		{shares[2], shares[3], shares[4]},
	}
	for i, combo := range combos {
		recovered, err := ShamirCombine(combo)
		require.NoError(t, err, "combo %d failed", i)
		assert.True(t, bytes.Equal(secret, recovered), "combo %d mismatch", i)
	}
}

func TestShamirInsufficientShares(t *testing.T) {
	secret := []byte("cannot-recover-with-fewer-shares")

	shares, err := ShamirSplit(secret, 3, 3)
	require.NoError(t, err)

	// 2 of 3 shares when threshold is 3 → should NOT reconstruct correctly
	partial, err := ShamirCombine(shares[:2])
	require.NoError(t, err) // combine doesn't error, it just gives wrong data
	assert.False(t, bytes.Equal(secret, partial), "should NOT recover with insufficient shares")
}

func TestShamirSingleShareFails(t *testing.T) {
	_, err := ShamirCombine([]Share{{Index: 1, Data: []byte{1}}})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least 2 shares")
}

func TestShamirDuplicateIndex(t *testing.T) {
	shares := []Share{
		{Index: 1, Data: []byte{10}},
		{Index: 1, Data: []byte{20}},
	}
	_, err := ShamirCombine(shares)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate")
}

func TestShamirZeroIndexRejected(t *testing.T) {
	shares := []Share{
		{Index: 0, Data: []byte{10}},
		{Index: 1, Data: []byte{20}},
	}
	_, err := ShamirCombine(shares)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must not be 0")
}

func TestShamirEmptySecretRejected(t *testing.T) {
	_, err := ShamirSplit(nil, 2, 2)
	assert.Error(t, err)

	_, err = ShamirSplit([]byte{}, 2, 2)
	assert.Error(t, err)
}

func TestShamirInvalidParams(t *testing.T) {
	secret := []byte("test")

	_, err := ShamirSplit(secret, 1, 2)
	assert.Error(t, err, "n < threshold")

	_, err = ShamirSplit(secret, 2, 1)
	assert.Error(t, err, "threshold < 2")

	_, err = ShamirSplit(secret, 256, 2)
	assert.Error(t, err, "n > 255")
}

func TestShamirLargeSecret(t *testing.T) {
	// Test with a 256-byte secret (typical encrypted key share)
	secret := make([]byte, 256)
	_, err := rand.Read(secret)
	require.NoError(t, err)

	shares, err := ShamirSplit(secret, 3, 2)
	require.NoError(t, err)

	recovered, err := ShamirCombine(shares[:2])
	require.NoError(t, err)
	assert.True(t, bytes.Equal(secret, recovered))
}

func TestGF256Arithmetic(t *testing.T) {
	// Addition is XOR
	assert.Equal(t, byte(0), gf256Add(5, 5))
	assert.Equal(t, byte(6), gf256Add(5, 3))

	// Multiplication identity
	assert.Equal(t, byte(7), gf256Mul(7, 1))
	assert.Equal(t, byte(0), gf256Mul(7, 0))

	// Inverse: a * a^(-1) = 1
	for a := byte(1); a != 0; a++ {
		inv := gf256Inv(a)
		assert.Equal(t, byte(1), gf256Mul(a, inv), "a=%d, inv=%d", a, inv)
	}
}

func BenchmarkShamirSplit(b *testing.B) {
	secret := make([]byte, 32)
	rand.Read(secret)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ShamirSplit(secret, 3, 2)
	}
}

func BenchmarkShamirCombine(b *testing.B) {
	secret := make([]byte, 32)
	rand.Read(secret)
	shares, _ := ShamirSplit(secret, 3, 2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ShamirCombine(shares[:2])
	}
}
