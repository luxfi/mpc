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

// Store is an implementation of the KVStore interface backed by ZapDB.
type Store struct {
	DB   database.Database
	Exec *Backup
}

// Config holds configuration for opening a Store.
type Config struct {
	NodeID    string
	Key       []byte
	BackupKey []byte
	Dir       string
	Path      string
}

// New creates a new Store backed by ZapDB with encryption.
func New(config Config) (*Store, error) {
	if len(config.Key) == 0 {
		return nil, ErrEncryptionKeyNotProvided
	}
	if len(config.BackupKey) == 0 {
		return nil, ErrBackupEncryptionKeyNotProvided
	}

	raw, err := zapdb.New(config.Path, nil, config.NodeID, metric.NewNoOpRegistry())
	if err != nil {
		return nil, err
	}

	enc, err := encdb.New(config.Key, raw)
	if err != nil {
		raw.Close() //nolint:errcheck
		return nil, err
	}

	logger.Info("Connected to ZapDB successfully!", "path", config.Path)

	exec := NewBackup(
		config.NodeID,
		enc,
		config.BackupKey,
		config.Dir,
	)

	return &Store{DB: enc, Exec: exec}, nil
}

// Put stores a key-value pair in ZapDB.
func (s *Store) Put(key string, value []byte) error {
	return s.DB.Put([]byte(key), value)
}

// Get retrieves the value associated with a key from ZapDB.
func (s *Store) Get(key string) ([]byte, error) {
	v, err := s.DB.Get([]byte(key))
	if errors.Is(err, database.ErrNotFound) {
		return nil, err
	}
	return v, err
}

func (s *Store) Keys() ([]string, error) {
	it := s.DB.NewIterator()
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
func (s *Store) Delete(key string) error {
	return s.DB.Delete([]byte(key))
}

func (s *Store) Backup() error {
	if s.Exec == nil {
		return errors.New("backup executor is not initialized")
	}
	return s.Exec.Execute()
}

// Close closes the ZapDB.
func (s *Store) Close() error {
	return s.DB.Close()
}
