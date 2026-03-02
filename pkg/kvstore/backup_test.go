package kvstore

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to generate random encryption key
func generateRandomKey(size int) []byte {
	key := make([]byte, size)
	_, err := rand.Read(key)
	if err != nil {
		panic(err)
	}
	return key
}

// Helper function to generate test encryption keys
func generateTestKeys() ([]byte, []byte) {
	return generateRandomKey(32), generateRandomKey(32)
}

func newTestStore(t *testing.T, dbPath, backupDir string, encKey, backupKey []byte) *Store {
	t.Helper()
	store, err := New(Config{
		NodeID:    "test-node",
		Key:       encKey,
		BackupKey: backupKey,
		Dir:       backupDir,
		Path:      dbPath,
	})
	require.NoError(t, err)
	return store
}

func TestBackup_Execute(t *testing.T) {
	testDir := t.TempDir()
	dbPath := filepath.Join(testDir, "testdb")
	backupDir := filepath.Join(testDir, "backups")

	encryptionKey, backupEncryptionKey := generateTestKeys()

	store := newTestStore(t, dbPath, backupDir, encryptionKey, backupEncryptionKey)
	defer store.Close()

	exec := store.Exec

	t.Run("first backup should create initial backup", func(t *testing.T) {
		err := store.Put("key1", []byte("value1"))
		require.NoError(t, err)

		err = exec.Execute()
		require.NoError(t, err)

		files, err := filepath.Glob(filepath.Join(backupDir, "backup-*.enc"))
		require.NoError(t, err)
		assert.Len(t, files, 1)

		info, err := exec.LoadVersionInfo()
		require.NoError(t, err)
		assert.Greater(t, info.Version, uint64(0))
	})

	t.Run("incremental backup should only backup changes", func(t *testing.T) {
		initialInfo, err := exec.LoadVersionInfo()
		require.NoError(t, err)
		initialVersion := initialInfo.Version

		err = store.Put("key2", []byte("value2"))
		require.NoError(t, err)

		err = exec.Execute()
		require.NoError(t, err)

		files, err := filepath.Glob(filepath.Join(backupDir, "backup-*.enc"))
		require.NoError(t, err)
		assert.Len(t, files, 2)

		finalInfo, err := exec.LoadVersionInfo()
		require.NoError(t, err)
		assert.Greater(t, finalInfo.Version, initialVersion)
	})

	t.Run("backup with no changes should be skipped", func(t *testing.T) {
		info, err := exec.LoadVersionInfo()
		require.NoError(t, err)
		currentVersion := info.Version

		err = exec.Execute()
		require.NoError(t, err)

		newInfo, err := exec.LoadVersionInfo()
		require.NoError(t, err)
		assert.Equal(t, currentVersion, newInfo.Version)

		files, err := filepath.Glob(filepath.Join(backupDir, "backup-*.enc"))
		require.NoError(t, err)
		assert.Len(t, files, 2)
	})
}

func TestBackup_BackupMetadata(t *testing.T) {
	testDir := t.TempDir()
	dbPath := filepath.Join(testDir, "testdb")
	backupDir := filepath.Join(testDir, "backups")

	encryptionKey, backupEncryptionKey := generateTestKeys()

	store := newTestStore(t, dbPath, backupDir, encryptionKey, backupEncryptionKey)
	defer store.Close()

	exec := store.Exec

	err := store.Put("test-key", []byte("test-value"))
	require.NoError(t, err)

	err = exec.Execute()
	require.NoError(t, err)

	files, err := filepath.Glob(filepath.Join(backupDir, "backup-*.enc"))
	require.NoError(t, err)
	require.Len(t, files, 1)

	t.Run("backup metadata should have correct fields", func(t *testing.T) {
		meta, err := exec.parseBackupMetadata(files[0])
		if err != nil {
			t.Logf("parseBackupMetadata error: %v", err)
		}
		require.NoError(t, err)

		assert.Equal(t, "AES-256-GCM", meta.Algo)
		assert.NotEmpty(t, meta.NonceB64)
		assert.NotEmpty(t, meta.CreatedAt)
		assert.NotEmpty(t, meta.EncryptionKeyID)
		assert.Greater(t, meta.NextSince, uint64(0))
	})

	t.Run("backup metadata timestamp should be recent", func(t *testing.T) {
		meta, err := exec.parseBackupMetadata(files[0])
		require.NoError(t, err)

		createdAt, err := time.Parse(time.RFC3339, meta.CreatedAt)
		require.NoError(t, err)

		assert.WithinDuration(t, time.Now(), createdAt, 10*time.Second)
	})

	t.Run("backup metadata should reference correct encryption key", func(t *testing.T) {
		meta, err := exec.parseBackupMetadata(files[0])
		require.NoError(t, err)

		// EncryptionKeyID should be first 16 chars of sha256 hex of backup key
		assert.Len(t, meta.EncryptionKeyID, 16)
		assert.NotEmpty(t, meta.EncryptionKeyID)
	})
}

func TestBackup_VersionTracking(t *testing.T) {
	testDir := t.TempDir()
	backupDir := filepath.Join(testDir, "backups")

	err := os.MkdirAll(backupDir, 0755)
	require.NoError(t, err)

	// Create a mock executor just for version tracking tests
	exec := &Backup{
		NodeID: "test-node",
		Key:    generateRandomKey(32),
		Dir:    backupDir,
	}

	t.Run("should create version file on first save", func(t *testing.T) {
		version := uint64(12345)
		since := uint64(100)
		err := exec.SaveVersionInfo(version, since)
		require.NoError(t, err)

		versionFile := filepath.Join(backupDir, "latest.version")
		_, err = os.Stat(versionFile)
		require.NoError(t, err)

		info, err := exec.LoadVersionInfo()
		require.NoError(t, err)
		assert.Equal(t, version, info.Version)
		assert.NotEmpty(t, info.UpdatedAt)
	})

	t.Run("should update version file on subsequent saves", func(t *testing.T) {
		versionFile := filepath.Join(backupDir, "latest.version")
		oldFileInfo, err := os.Stat(versionFile)
		require.NoError(t, err)
		oldModTime := oldFileInfo.ModTime()

		time.Sleep(10 * time.Millisecond)

		newVersion := uint64(99999)
		err = exec.SaveVersionInfo(newVersion, 200)
		require.NoError(t, err)

		newFileInfo, err := os.Stat(versionFile)
		require.NoError(t, err)
		assert.True(t, newFileInfo.ModTime().After(oldModTime) || newFileInfo.ModTime().Equal(oldModTime))

		info, err := exec.LoadVersionInfo()
		require.NoError(t, err)
		assert.Equal(t, newVersion, info.Version)
	})

	t.Run("should return default info if version file doesn't exist", func(t *testing.T) {
		emptyDir := t.TempDir()
		emptyExec := &Backup{
			NodeID: "test",
			Key:    generateRandomKey(32),
			Dir:    emptyDir,
		}

		info, err := emptyExec.LoadVersionInfo()
		require.NoError(t, err)
		assert.Equal(t, uint64(0), info.Version)
		assert.Equal(t, uint64(0), info.Since)
	})

	t.Run("should parse version info correctly", func(t *testing.T) {
		info, err := exec.LoadVersionInfo()
		require.NoError(t, err)

		assert.Equal(t, uint64(99999), info.Version)
		assert.Equal(t, uint64(200), info.Since)

		_, err = time.Parse(time.RFC3339, info.UpdatedAt)
		require.NoError(t, err)
	})
}

func TestBackup_Restore(t *testing.T) {
	testDir := t.TempDir()
	dbPath := filepath.Join(testDir, "testdb")
	backupDir := filepath.Join(testDir, "backups")
	restorePath := filepath.Join(testDir, "restored")

	encryptionKey, backupEncryptionKey := generateTestKeys()

	store := newTestStore(t, dbPath, backupDir, encryptionKey, backupEncryptionKey)

	exec := store.Exec

	testData := map[string]string{
		"key1": "value1",
		"key2": "value2",
		"key3": "value3",
	}

	err := store.Put("key1", []byte("value1"))
	require.NoError(t, err)
	err = exec.Execute()
	require.NoError(t, err)

	err = store.Put("key2", []byte("value2"))
	require.NoError(t, err)
	err = exec.Execute()
	require.NoError(t, err)

	err = store.Put("key3", []byte("value3"))
	require.NoError(t, err)
	err = exec.Execute()
	require.NoError(t, err)

	store.Close()

	t.Run("should restore all backups in order", func(t *testing.T) {
		err := exec.RestoreAllBackupsEncrypted(restorePath, encryptionKey)
		require.NoError(t, err)

		// Open restored database via KVStore abstraction
		restored := newTestStore(t, restorePath, t.TempDir(), encryptionKey, backupEncryptionKey)
		defer restored.Close()

		for key, expectedValue := range testData {
			value, err := restored.Get(key)
			require.NoError(t, err)
			assert.Equal(t, expectedValue, string(value))
		}
	})

	t.Run("should handle empty backup directory", func(t *testing.T) {
		emptyBackupDir := filepath.Join(testDir, "empty_backups")
		err := os.MkdirAll(emptyBackupDir, 0755)
		require.NoError(t, err)

		emptyExec := NewBackup("test-node", nil, backupEncryptionKey, emptyBackupDir)

		emptyRestorePath := filepath.Join(testDir, "empty_restored")
		err = emptyExec.RestoreAllBackupsEncrypted(emptyRestorePath, encryptionKey)
		require.NoError(t, err)

		// Should create an empty database
		emptyStore := newTestStore(t, emptyRestorePath, t.TempDir(), encryptionKey, backupEncryptionKey)
		defer emptyStore.Close()
	})
}

func TestBackup_FileFormat(t *testing.T) {
	testDir := t.TempDir()
	backupDir := filepath.Join(testDir, "backups")

	encryptionKey, backupEncryptionKey := generateTestKeys()

	store := newTestStore(t, filepath.Join(testDir, "testdb"), backupDir, encryptionKey, backupEncryptionKey)
	defer store.Close()

	exec := store.Exec

	err := store.Put("test-key", []byte("test-value"))
	require.NoError(t, err)

	err = exec.Execute()
	require.NoError(t, err)

	files, err := filepath.Glob(filepath.Join(backupDir, "backup-*.enc"))
	require.NoError(t, err)
	require.Len(t, files, 1)

	t.Run("backup file should have correct format", func(t *testing.T) {
		data, err := os.ReadFile(files[0])
		require.NoError(t, err)

		assert.True(t, len(data) >= len(magic))
		assert.Equal(t, magic, string(data[:len(magic)]))

		if len(data) >= len(magic)+4 {
			metaLen := uint32(data[len(magic)])<<24 | uint32(data[len(magic)+1])<<16 |
				uint32(data[len(magic)+2])<<8 | uint32(data[len(magic)+3])
			assert.Greater(t, metaLen, uint32(0))
			assert.Less(t, metaLen, uint32(len(data)-len(magic)-4))
		}
	})

	t.Run("backup metadata should be valid JSON", func(t *testing.T) {
		data, err := os.ReadFile(files[0])
		require.NoError(t, err)

		offset := len(magic)
		metaLen := binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4

		var meta BackupMeta
		err = json.Unmarshal(data[offset:offset+int(metaLen)], &meta)
		require.NoError(t, err)
		assert.Equal(t, "AES-256-GCM", meta.Algo)
	})

	t.Run("backup filename should follow pattern", func(t *testing.T) {
		filename := filepath.Base(files[0])
		assert.Contains(t, filename, "backup-test-node-")
		assert.Contains(t, filename, ".enc")
	})
}

// Helper method to parse backup metadata for testing
func (b *Backup) parseBackupMetadata(path string) (BackupMeta, error) {
	var meta BackupMeta

	f, err := os.Open(path)
	if err != nil {
		return meta, err
	}
	defer f.Close()

	// Skip magic
	magicBuf := make([]byte, len(magic))
	if _, err := f.Read(magicBuf); err != nil {
		return meta, err
	}

	// Read metadata length
	var metaLen uint32
	if err := binary.Read(f, binary.BigEndian, &metaLen); err != nil {
		return meta, err
	}

	// Read metadata
	metaBuf := make([]byte, metaLen)
	if _, err := f.Read(metaBuf); err != nil {
		return meta, err
	}

	err = json.Unmarshal(metaBuf, &meta)
	return meta, err
}

func TestStore_BackupIntegration(t *testing.T) {
	testDir := t.TempDir()
	dbPath := filepath.Join(testDir, "testdb")
	backupDir := filepath.Join(testDir, "backups")

	encryptionKey, backupEncryptionKey := generateTestKeys()

	config := Config{
		NodeID:    "test-node",
		Key:       encryptionKey,
		BackupKey: backupEncryptionKey,
		Dir:       backupDir,
		Path:      dbPath,
	}

	store, err := New(config)
	require.NoError(t, err)
	defer store.Close()

	t.Run("store should work with incremental backup", func(t *testing.T) {
		err := store.Put("key1", []byte("value1"))
		require.NoError(t, err)

		err = store.Backup()
		require.NoError(t, err)

		err = store.Put("key2", []byte("value2"))
		require.NoError(t, err)
		err = store.Put("key3", []byte("value3"))
		require.NoError(t, err)

		err = store.Backup()
		require.NoError(t, err)

		value1, err := store.Get("key1")
		require.NoError(t, err)
		assert.Equal(t, "value1", string(value1))

		value2, err := store.Get("key2")
		require.NoError(t, err)
		assert.Equal(t, "value2", string(value2))

		value3, err := store.Get("key3")
		require.NoError(t, err)
		assert.Equal(t, "value3", string(value3))

		files, err := filepath.Glob(filepath.Join(backupDir, "backup-*.enc"))
		require.NoError(t, err)
		assert.Len(t, files, 2)
	})

	t.Run("store should handle backup without executor", func(t *testing.T) {
		store.Exec = nil
		err := store.Backup()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "backup executor is not initialized")
	})
}
