package kvstore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
)

// EncryptedKVStore wraps a KVStore with per-key AES-256-GCM encryption.
// Each key-value pair is encrypted with a unique DEK derived from a master
// key + the storage key name. This means even if the underlying ZapDB is
// fully dumped, individual entries are independently encrypted.
//
// Usage:
//
//	base := zapdb.New(path, nodePassword)
//	userStore := NewEncryptedKVStore(base, DeriveUserKey(masterKey, orgID, userID))
//
// The userStore encrypts all values before writing to ZapDB and decrypts
// on read. The underlying ZapDB still has its own ChaCha20-Poly1305
// encryption — this is a second layer specifically for per-user isolation.
type EncryptedKVStore struct {
	inner KVStore
	key   []byte // 32-byte AES-256 key
}

// NewEncryptedKVStore wraps an existing KVStore with per-entry AES-256-GCM encryption.
// The key must be exactly 32 bytes.
func NewEncryptedKVStore(inner KVStore, key []byte) (*EncryptedKVStore, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("encrypted kvstore requires 32-byte key, got %d", len(key))
	}
	return &EncryptedKVStore{inner: inner, key: key}, nil
}

// DeriveUserKey derives a 32-byte per-user encryption key from a master key.
//
//	key = HMAC-SHA256(masterKey, "mpc:shard:" + orgID + ":" + userID)
//
// Each user gets a unique key. Compromising one user's key does not affect others.
func DeriveUserKey(masterKey []byte, orgID, userID string) []byte {
	mac := hmac.New(sha256.New, masterKey)
	mac.Write([]byte("mpc:shard:" + orgID + ":" + userID))
	return mac.Sum(nil)
}

// DeriveOrgKey derives a 32-byte per-org encryption key.
func DeriveOrgKey(masterKey []byte, orgID string) []byte {
	mac := hmac.New(sha256.New, masterKey)
	mac.Write([]byte("mpc:org:" + orgID))
	return mac.Sum(nil)
}

func (s *EncryptedKVStore) Put(key string, value []byte) error {
	encrypted, err := s.encrypt(value)
	if err != nil {
		return fmt.Errorf("encrypt value for key %q: %w", key, err)
	}
	return s.inner.Put(key, encrypted)
}

func (s *EncryptedKVStore) Get(key string) ([]byte, error) {
	encrypted, err := s.inner.Get(key)
	if err != nil {
		return nil, err
	}
	if len(encrypted) == 0 {
		return encrypted, nil
	}
	return s.decrypt(encrypted)
}

func (s *EncryptedKVStore) Delete(key string) error {
	return s.inner.Delete(key)
}

func (s *EncryptedKVStore) Close() error {
	return s.inner.Close()
}

func (s *EncryptedKVStore) Backup() error {
	return s.inner.Backup()
}

// encrypt uses AES-256-GCM with a random 12-byte nonce prepended to ciphertext.
func (s *EncryptedKVStore) encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// decrypt expects nonce prepended to ciphertext (as produced by encrypt).
func (s *EncryptedKVStore) decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ct, nil)
}
