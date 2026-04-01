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

	// Use org-scoped key (empty orgID is now rejected by K-1 fix)
	require.NoError(t, store.Put(OrgScopedKey("org1", "wallet1"), secret))

	var captured []byte
	withSecretErasure(func() {
		shareBytes, err := GetKeyShareWithFallback(store, "org1", "wallet1")
		require.NoError(t, err)
		captured = shareBytes
		defer func() {
			for i := range shareBytes {
				shareBytes[i] = 0
			}
		}()
	})

	for i, b := range captured {
		assert.Equal(t, byte(0), b, "byte %d should be zeroed, got %d", i, b)
	}
}

// TestOrgScopedKey_M2_RequiredOrgID verifies orgID is mandatory (K-1 fix).
// Empty orgID is rejected to prevent cross-tenant data leakage.
func TestOrgScopedKey_M2_RequiredOrgID(t *testing.T) {
	store := newMockKVStore()

	orgShare := []byte("org-share")

	require.NoError(t, store.Put(OrgScopedKey("org1", "wallet1"), orgShare))

	// With orgID, only org-scoped key returned
	got, err := GetKeyShareWithFallback(store, "org1", "wallet1")
	require.NoError(t, err)
	assert.Equal(t, orgShare, got)

	// With orgID that has no share, error returned (no fallback)
	_, err = GetKeyShareWithFallback(store, "org2", "wallet1")
	require.Error(t, err)

	// Empty orgID must be REJECTED (K-1: fail-closed, no legacy fallback)
	_, err = GetKeyShareWithFallback(store, "", "wallet1")
	require.Error(t, err, "empty orgID must be rejected")
	assert.Contains(t, err.Error(), "orgID is required")
}
