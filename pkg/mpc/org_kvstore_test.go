package mpc

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockKVStore is a simple in-memory KVStore for testing.
type mockKVStore struct {
	data map[string][]byte
}

func newMockKVStore() *mockKVStore {
	return &mockKVStore{data: make(map[string][]byte)}
}

func (m *mockKVStore) Put(key string, value []byte) error {
	m.data[key] = value
	return nil
}

func (m *mockKVStore) Get(key string) ([]byte, error) {
	v, ok := m.data[key]
	if !ok {
		return nil, errors.New("key not found")
	}
	return v, nil
}

func (m *mockKVStore) Delete(key string) error {
	delete(m.data, key)
	return nil
}

func (m *mockKVStore) Close() error { return nil }
func (m *mockKVStore) Backup() error { return nil }

func TestOrgScopedKey(t *testing.T) {
	assert.Equal(t, "testkey", OrgScopedKey("", "testkey"))
	assert.Equal(t, "org:myorg:testkey", OrgScopedKey("myorg", "testkey"))
	// Colons in orgID are sanitized
	assert.Equal(t, "org:my_org:testkey", OrgScopedKey("my:org", "testkey"))
}

// TestGetKeyShareWithFallback_M1_CrossTenantLeak is the regression test for M-1.
// When orgID is provided, only the org-scoped key must be checked.
// The legacy unscoped key must NOT be returned, even if it exists.
func TestGetKeyShareWithFallback_M1_CrossTenantLeak(t *testing.T) {
	store := newMockKVStore()

	// Store a legacy (unscoped) key share
	legacyShare := []byte("legacy-secret-key-share")
	require.NoError(t, store.Put("wallet123", legacyShare))

	// A different org requests the share -- must NOT get the legacy share
	_, err := GetKeyShareWithFallback(store, "org-attacker", "wallet123")
	require.Error(t, err, "must not fall back to legacy key when orgID is provided")

	// The correct org that has its own share gets it
	orgShare := []byte("org-specific-share")
	require.NoError(t, store.Put(OrgScopedKey("org-owner", "wallet123"), orgShare))
	got, err := GetKeyShareWithFallback(store, "org-owner", "wallet123")
	require.NoError(t, err)
	assert.Equal(t, orgShare, got)

	// Empty orgID still returns legacy key (backward compat for unscoped callers)
	got, err = GetKeyShareWithFallback(store, "", "wallet123")
	require.NoError(t, err)
	assert.Equal(t, legacyShare, got)
}

func TestGetKeyShareWithFallback_OrgScopedNotFound(t *testing.T) {
	store := newMockKVStore()

	// No data at all
	_, err := GetKeyShareWithFallback(store, "someorg", "wallet999")
	require.Error(t, err)
}

func TestGetKeyShareWithFallback_EmptyOrgID_NoData(t *testing.T) {
	store := newMockKVStore()

	_, err := GetKeyShareWithFallback(store, "", "wallet999")
	require.Error(t, err)
}
