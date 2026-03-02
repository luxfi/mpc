package kvstore

import (
	"errors"

	"github.com/luxfi/database"
	"github.com/luxfi/database/encdb"
	"github.com/luxfi/database/zapdb"
	"github.com/luxfi/metric"

	"github.com/luxfi/mpc/pkg/logger"
)

var (
	ErrEncryptionKeyNotProvided       = errors.New("encryption key not provided")
	ErrBackupEncryptionKeyNotProvided = errors.New("backup encryption key not provided")
)

// BadgerKVStore is an implementation of the KVStore interface using ZapDB.
type BadgerKVStore struct {
	db             database.Database
	BackupExecutor *BadgerBackupExecutor
}

type BadgerConfig struct {
	NodeID              string
	EncryptionKey       []byte
	BackupEncryptionKey []byte
	BackupDir           string
	DBPath              string
}

// NewBadgerKVStore creates a new BadgerKVStore backed by ZapDB with encryption.
func NewBadgerKVStore(config BadgerConfig) (*BadgerKVStore, error) {
	if len(config.EncryptionKey) == 0 {
		return nil, ErrEncryptionKeyNotProvided
	}
	if len(config.BackupEncryptionKey) == 0 {
		return nil, ErrBackupEncryptionKeyNotProvided
	}

	raw, err := zapdb.New(config.DBPath, nil, config.NodeID, metric.NewNoOpRegistry())
	if err != nil {
		return nil, err
	}

	enc, err := encdb.New(config.EncryptionKey, raw)
	if err != nil {
		raw.Close() //nolint:errcheck
		return nil, err
	}

	logger.Info("Connected to ZapDB successfully!", "path", config.DBPath)

	backupExecutor := NewBadgerBackupExecutor(
		config.NodeID,
		enc,
		config.BackupEncryptionKey,
		config.BackupDir,
	)

	return &BadgerKVStore{db: enc, BackupExecutor: backupExecutor}, nil
}

// Put stores a key-value pair in ZapDB.
func (b *BadgerKVStore) Put(key string, value []byte) error {
	return b.db.Put([]byte(key), value)
}

// Get retrieves the value associated with a key from ZapDB.
func (b *BadgerKVStore) Get(key string) ([]byte, error) {
	v, err := b.db.Get([]byte(key))
	if errors.Is(err, database.ErrNotFound) {
		return nil, err
	}
	return v, err
}

func (b *BadgerKVStore) Keys() ([]string, error) {
	it := b.db.NewIterator()
	defer it.Release()

	var keys []string
	for it.Next() {
		keys = append(keys, string(it.Key()))
	}
	if err := it.Error(); err != nil {
		return nil, err
	}
	return keys, nil
}

// Delete removes a key-value pair from ZapDB.
func (b *BadgerKVStore) Delete(key string) error {
	return b.db.Delete([]byte(key))
}

func (b *BadgerKVStore) Backup() error {
	if b.BackupExecutor == nil {
		return errors.New("backup executor is not initialized")
	}
	return b.BackupExecutor.Execute()
}

// Close closes the ZapDB.
func (b *BadgerKVStore) Close() error {
	return b.db.Close()
}
