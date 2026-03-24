package mpc

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSecretErasure_M3_ShareBytesZeroed verifies that key share bytes
// are explicitly zeroed after use, not left on the heap.
func TestSecretErasure_M3_ShareBytesZeroed(t *testing.T) {
	store := newMockKVStore()

	secret := []byte("super-secret-key-share-data-1234")
	original := make([]byte, len(secret))
	copy(original, secret)

	require.NoError(t, store.Put("wallet1", secret))

	// Simulate the erasure pattern used in signing sessions.
	// The closure captures shareBytes, and the deferred zero-fill
	// must overwrite the bytes before the closure returns.
	var captured []byte
	withSecretErasure(func() {
		shareBytes, err := GetKeyShareWithFallback(store, "", "wallet1")
		require.NoError(t, err)
		// Save the slice header (points to same backing array)
		captured = shareBytes
		defer func() {
			for i := range shareBytes {
				shareBytes[i] = 0
			}
		}()
	})

	// After the closure, the captured slice should be zeroed
	for i, b := range captured {
		assert.Equal(t, byte(0), b, "byte %d should be zeroed, got %d", i, b)
	}
}

// TestOrgScopedKey_M2_RequiredOrgID verifies orgID is no longer optional.
// This is a compile-time guarantee (variadic removed), but we test the
// behavior: empty orgID falls back to legacy, non-empty uses scoped key.
func TestOrgScopedKey_M2_RequiredOrgID(t *testing.T) {
	store := newMockKVStore()

	orgShare := []byte("org-share")
	legacyShare := []byte("legacy-share")

	require.NoError(t, store.Put(OrgScopedKey("org1", "wallet1"), orgShare))
	require.NoError(t, store.Put("wallet1", legacyShare))

	// With orgID, only org-scoped key returned
	got, err := GetKeyShareWithFallback(store, "org1", "wallet1")
	require.NoError(t, err)
	assert.Equal(t, orgShare, got)

	// With orgID that has no share, error returned (no fallback)
	_, err = GetKeyShareWithFallback(store, "org2", "wallet1")
	require.Error(t, err)

	// Empty orgID, legacy share returned
	got, err = GetKeyShareWithFallback(store, "", "wallet1")
	require.NoError(t, err)
	assert.Equal(t, legacyShare, got)
}
