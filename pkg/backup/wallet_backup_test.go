package backup

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWalletBackupAndRecover(t *testing.T) {
	keyShare := make([]byte, 64)
	_, err := rand.Read(keyShare)
	require.NoError(t, err)

	// Default 2-of-2: iCloud + HSM
	result, err := BackupWallet("wallet-123", keyShare, DefaultBackupConfig())
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "wallet-123", result.WalletID)
	assert.Equal(t, 2, result.Threshold)
	assert.Equal(t, 2, result.TotalShards)
	assert.Len(t, result.Shards, 2)
	assert.Equal(t, ShardDestICloud, result.Shards[0].Destination)
	assert.Equal(t, ShardDestHSM, result.Shards[1].Destination)
	assert.NotEmpty(t, result.BackupID)
	assert.NotEmpty(t, result.EncryptedKeyShare)

	// Recover with both shards
	recovered, err := RecoverWallet(result.EncryptedKeyShare, result.Shards)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(keyShare, recovered), "recovered key share must match original")
}

func TestWalletBackupInstitutional(t *testing.T) {
	keyShare := make([]byte, 32)
	rand.Read(keyShare)

	cfg := InstitutionalBackupConfig() // 3-of-5
	result, err := BackupWallet("vault-inst-1", keyShare, cfg)
	require.NoError(t, err)
	assert.Len(t, result.Shards, 5)

	// Any 3 shards should reconstruct
	combos := [][]LabeledShard{
		{result.Shards[0], result.Shards[1], result.Shards[2]},
		{result.Shards[0], result.Shards[2], result.Shards[4]},
		{result.Shards[1], result.Shards[3], result.Shards[4]},
	}
	for i, combo := range combos {
		recovered, err := RecoverWallet(result.EncryptedKeyShare, combo)
		require.NoError(t, err, "combo %d", i)
		assert.True(t, bytes.Equal(keyShare, recovered), "combo %d mismatch", i)
	}
}

func TestWalletBackupWrongShards(t *testing.T) {
	keyShare := []byte("real-key-material")

	result, err := BackupWallet("w1", keyShare, DefaultBackupConfig())
	require.NoError(t, err)

	// Create a different backup → different shards
	result2, err := BackupWallet("w2", []byte("other-key"), DefaultBackupConfig())
	require.NoError(t, err)

	// Try to decrypt result1's data with result2's shards → should fail
	_, err = RecoverWallet(result.EncryptedKeyShare, result2.Shards)
	assert.Error(t, err, "should fail with wrong shards")
}

func TestWalletBackupPartialShardsInsufficientFor2of2(t *testing.T) {
	keyShare := []byte("secret-key-share")

	result, err := BackupWallet("w1", keyShare, DefaultBackupConfig())
	require.NoError(t, err)

	// Only 1 shard for a 2-of-2 → should fail
	_, err = RecoverWallet(result.EncryptedKeyShare, result.Shards[:1])
	assert.Error(t, err, "should fail with only 1 shard in 2-of-2")
}

func TestWalletBackupEmptyInput(t *testing.T) {
	_, err := BackupWallet("w1", nil, DefaultBackupConfig())
	assert.Error(t, err)

	_, err = BackupWallet("w1", []byte{}, DefaultBackupConfig())
	assert.Error(t, err)
}

func TestWalletBackupMismatchedDestinations(t *testing.T) {
	_, err := BackupWallet("w1", []byte("key"), WalletBackupConfig{
		Threshold:    2,
		TotalShards:  3,
		Destinations: []string{"icloud", "hsm"}, // only 2, but TotalShards=3
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "destinations length")
}

func TestAESGCMRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	plaintext := []byte("hello world, this is a test of AES-256-GCM encryption")

	ct, err := aesGCMEncrypt(key, plaintext)
	require.NoError(t, err)
	assert.NotEqual(t, plaintext, ct)

	pt, err := aesGCMDecrypt(key, ct)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(plaintext, pt))
}

func TestAESGCMWrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	rand.Read(key1)
	rand.Read(key2)

	ct, err := aesGCMEncrypt(key1, []byte("secret"))
	require.NoError(t, err)

	_, err = aesGCMDecrypt(key2, ct)
	assert.Error(t, err, "should fail with wrong key")
}
