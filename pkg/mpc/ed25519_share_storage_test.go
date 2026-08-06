package mpc

import (
	"crypto/ed25519"
	"fmt"
	"testing"

	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/frost"
	"github.com/stretchr/testify/require"
)

// mapKVStore is the smallest thing satisfying kvstore.KVStore, so the real
// org-scoping and key-naming code can run against it.
type mapKVStore map[string][]byte

func (m mapKVStore) Put(key string, value []byte) error { m[key] = value; return nil }
func (m mapKVStore) Delete(key string) error            { delete(m, key); return nil }
func (m mapKVStore) Close() error                       { return nil }
func (m mapKVStore) Backup() error                      { return nil }
func (m mapKVStore) Get(key string) ([]byte, error) {
	v, ok := m[key]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", key)
	}
	return v, nil
}

// TestEd25519ShareSurvivesTheRealStorageSeam closes the gap between "the codec
// round-trips" and "signing can find what keygen wrote".
//
// The two halves compute their storage key independently — keygen in
// publishResult, signing in newFROSTSigningSession — and a wallet whose share is
// written to one key and read from another is a wallet with a perfectly good
// address that can never spend. This exercises the real Ed25519ShareKey and the
// real org-scoping on both sides.
func TestEd25519ShareSurvivesTheRealStorageSeam(t *testing.T) {
	ids := ceremonyParties()
	const (
		threshold = 1
		orgID     = "org-with:colons"
		walletID  = "wallet-abc123"
	)

	raw := runCeremony(t, ids, []byte("storage-seam"), func(id party.ID) protocol.StartFunc {
		return ed25519KeygenStart(id, ids, threshold)
	})

	store := mapKVStore{}

	// WRITE — exactly as frostKeygenSession.publishResult does. Checked, not a
	// bare assertion: a wrong type here means the daemon ran a different curve,
	// which must fail this test rather than panic and abort the whole package.
	original, ok := raw[ids[0]].(*frost.Config)
	require.True(t, ok, "keygen must produce *frost.Config, got %T", raw[ids[0]])
	shareBytes, err := MarshalEd25519Config(original)
	require.NoError(t, err)
	require.NoError(t, store.Put(OrgScopedKey(orgID, Ed25519ShareKey(walletID)), shareBytes))

	// READ — exactly as newFROSTSigningSession does.
	loadedBytes, err := GetKeyShareWithFallback(store, orgID, Ed25519ShareKey(walletID))
	require.NoError(t, err, "signing must find the share keygen wrote")
	loaded, err := UnmarshalEd25519Config(loadedBytes)
	require.NoError(t, err)

	// The reloaded share must still sign for the same address.
	originalPub, err := original.PublicKey.MarshalBinary()
	require.NoError(t, err)
	loadedPub, err := loaded.PublicKey.MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, originalPub, loadedPub, "storage must not change the wallet key")
	require.Equal(t, original.Threshold, loaded.Threshold)
	require.Equal(t, original.ID, loaded.ID)

	// And prove it end-to-end: sign with configs that all came back out of the
	// store, then verify against the address those bytes encode.
	configs := make(map[party.ID]*frost.Config, len(ids))
	for id, res := range raw {
		produced, ok := res.(*frost.Config)
		require.True(t, ok, "party %s: want *frost.Config, got %T", id, res)
		blob, err := MarshalEd25519Config(produced)
		require.NoError(t, err)
		require.NoError(t, store.Put(OrgScopedKey(orgID, Ed25519ShareKey(walletID)+":"+string(id)), blob))

		back, err := GetKeyShareWithFallback(store, orgID, Ed25519ShareKey(walletID)+":"+string(id))
		require.NoError(t, err)
		cfg, err := UnmarshalEd25519Config(back)
		require.NoError(t, err)
		configs[id] = cfg
	}

	signers := ids[:threshold+1]
	message := []byte("spend from a wallet reloaded entirely from storage")
	rawSign := runCeremony(t, signers, []byte("storage-seam-sign"), func(id party.ID) protocol.StartFunc {
		return ed25519SignStart(configs[id], signers, message)
	})
	sig, ok := rawSign[signers[0]].(frost.Ed25519Signature)
	require.True(t, ok, "want frost.Ed25519Signature, got %T", rawSign[signers[0]])
	encoded, err := sig.MarshalBinary()
	require.NoError(t, err)

	require.True(t, ed25519.Verify(ed25519.PublicKey(originalPub), message, encoded),
		"shares reloaded from the kvstore must still sign for the wallet address")
}

// TestEd25519ShareIsNotReachableUnderTheLegacyPrefix pins the deliberate break.
// Shares written under "frost:" were BIP-340 over secp256k1 and can never
// satisfy an Ed25519 verifier, so they must stay unreachable rather than be
// migrated into a path that would treat them as spendable.
func TestEd25519ShareIsNotReachableUnderTheLegacyPrefix(t *testing.T) {
	const (
		orgID    = "org1"
		walletID = "w1"
	)
	store := mapKVStore{}
	store.Put(OrgScopedKey(orgID, "frost:"+walletID), []byte("legacy taproot share"))

	_, err := GetKeyShareWithFallback(store, orgID, Ed25519ShareKey(walletID))
	require.Error(t, err, "an Ed25519 lookup must not fall back to a legacy secp256k1 share")
}

// TestKeyShareLookupRequiresAnOrg guards the org boundary: an empty org must not
// silently read some other tenant's share.
func TestKeyShareLookupRequiresAnOrg(t *testing.T) {
	store := mapKVStore{}
	store.Put(Ed25519ShareKey("w1"), []byte("unscoped"))

	_, err := GetKeyShareWithFallback(store, "", Ed25519ShareKey("w1"))
	require.Error(t, err, "unscoped key access must be refused")
}
