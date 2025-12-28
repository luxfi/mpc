package kms

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/scrypt"

	"github.com/luxfi/mpc/pkg/logger"
)

// MPCKMSIntegration provides KMS integration for MPC nodes
type MPCKMSIntegration struct {
	kms    *KMS
	nodeID string
}

// NewMPCKMSIntegration creates a new MPC KMS integration
func NewMPCKMSIntegration(nodeID string, dataDir string) (*MPCKMSIntegration, error) {
	// Create KMS directory
	kmsDir := filepath.Join(dataDir, "kms")

	// Derive master key from environment or generate one
	masterKeyStr := os.Getenv("MPC_KMS_MASTER_KEY")
	var masterKey []byte

	if masterKeyStr == "" {
		// For production, this should be properly managed
		// For now, we'll use a deterministic key based on node ID
		logger.Warn("No MPC_KMS_MASTER_KEY provided, using deterministic key (NOT FOR PRODUCTION)")
		masterKey, _ = DeriveKeyFromPassword(fmt.Sprintf("mpc-node-%s-default-key", nodeID), []byte(nodeID))
	} else {
		var err error
		masterKey, err = base64.StdEncoding.DecodeString(masterKeyStr)
		if err != nil {
			return nil, fmt.Errorf("invalid MPC_KMS_MASTER_KEY: %w", err)
		}
	}

	kms, err := NewKMS(kmsDir, masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize KMS: %w", err)
	}

	return &MPCKMSIntegration{
		kms:    kms,
		nodeID: nodeID,
	}, nil
}

// StoreMPCKeyShare stores an MPC key share
func (m *MPCKMSIntegration) StoreMPCKeyShare(walletID string, keyType string, share []byte) error {
	keyID := fmt.Sprintf("mpc-%s-%s-%s", m.nodeID, walletID, keyType)
	name := fmt.Sprintf("MPC Share for %s (%s)", walletID, keyType)
	description := fmt.Sprintf("MPC key share for wallet %s, key type %s, node %s", walletID, keyType, m.nodeID)

	return m.kms.StoreKey(keyID, name, keyType, share, description)
}

// RetrieveMPCKeyShare retrieves an MPC key share
func (m *MPCKMSIntegration) RetrieveMPCKeyShare(walletID string, keyType string) ([]byte, error) {
	keyID := fmt.Sprintf("mpc-%s-%s-%s", m.nodeID, walletID, keyType)
	return m.kms.RetrieveKey(keyID)
}

// StoreInitiatorKey stores the initiator private key
func (m *MPCKMSIntegration) StoreInitiatorKey(privateKey []byte) error {
	keyID := fmt.Sprintf("initiator-%s", m.nodeID)
	name := fmt.Sprintf("Initiator Key for %s", m.nodeID)
	description := fmt.Sprintf("Ed25519 initiator private key for node %s", m.nodeID)

	return m.kms.StoreKey(keyID, name, "ed25519", privateKey, description)
}

// RetrieveInitiatorKey retrieves the initiator private key
func (m *MPCKMSIntegration) RetrieveInitiatorKey() ([]byte, error) {
	keyID := fmt.Sprintf("initiator-%s", m.nodeID)
	return m.kms.RetrieveKey(keyID)
}

// StoreNodePrivateKey stores the node's P2P private key
func (m *MPCKMSIntegration) StoreNodePrivateKey(privateKey []byte) error {
	keyID := fmt.Sprintf("node-p2p-%s", m.nodeID)
	name := fmt.Sprintf("P2P Key for %s", m.nodeID)
	description := fmt.Sprintf("P2P communication private key for node %s", m.nodeID)

	return m.kms.StoreKey(keyID, name, "ecdsa", privateKey, description)
}

// RetrieveNodePrivateKey retrieves the node's P2P private key
func (m *MPCKMSIntegration) RetrieveNodePrivateKey() ([]byte, error) {
	keyID := fmt.Sprintf("node-p2p-%s", m.nodeID)
	return m.kms.RetrieveKey(keyID)
}

// ListStoredKeys lists all keys stored for this node
func (m *MPCKMSIntegration) ListStoredKeys() []EncryptedKey {
	return m.kms.ListKeys()
}

// backupEnvelope is the on-disk format for an encrypted KMS backup.
type backupEnvelope struct {
	Version int    `json:"version"`
	Salt    string `json:"salt"`   // base64-encoded scrypt salt
	Nonce   string `json:"nonce"`  // base64-encoded AES-GCM nonce
	KeyID   string `json:"key_id"` // sha256(derived key) prefix for verification
	Data    string `json:"data"`   // base64-encoded AES-256-GCM ciphertext
	Count   int    `json:"count"`  // number of keys in backup
}

// deriveBackupKey derives a 32-byte AES-256 key from a password and salt using scrypt.
func deriveBackupKey(password string, salt []byte) ([]byte, error) {
	return scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
}

// BackupKeys creates an encrypted backup of all keys.
// Keys are serialized to JSON, then encrypted with AES-256-GCM using a key
// derived from backupPassword via scrypt. The encrypted envelope (with salt
// and nonce metadata) is written to backupPath.
func (m *MPCKMSIntegration) BackupKeys(backupPath string, backupPassword string) error {
	if backupPassword == "" {
		return fmt.Errorf("backup password must not be empty")
	}

	// Read all key entries including encrypted data for backup
	m.kms.mu.RLock()
	fullKeys := make([]*EncryptedKey, 0, len(m.kms.keys))
	for _, ek := range m.kms.keys {
		cp := *ek
		fullKeys = append(fullKeys, &cp)
	}
	m.kms.mu.RUnlock()

	if len(fullKeys) == 0 {
		return fmt.Errorf("no keys to back up")
	}

	// Serialize to JSON
	plaintext, err := json.Marshal(fullKeys)
	if err != nil {
		return fmt.Errorf("failed to serialize keys for backup: %w", err)
	}

	// Generate salt
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive encryption key from password
	encKey, err := deriveBackupKey(backupPassword, salt)
	if err != nil {
		return fmt.Errorf("failed to derive backup key: %w", err)
	}

	// Encrypt with AES-256-GCM
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Build verification key ID (first 16 hex chars of sha256 of derived key)
	keyHash := sha256.Sum256(encKey)
	keyID := fmt.Sprintf("%x", keyHash[:])[:16]

	// Build envelope
	envelope := backupEnvelope{
		Version: 1,
		Salt:    base64.StdEncoding.EncodeToString(salt),
		Nonce:   base64.StdEncoding.EncodeToString(nonce),
		KeyID:   keyID,
		Data:    base64.StdEncoding.EncodeToString(ciphertext),
		Count:   len(fullKeys),
	}

	envelopeJSON, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal backup envelope: %w", err)
	}

	// Ensure parent directory exists
	if dir := filepath.Dir(backupPath); dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("failed to create backup directory: %w", err)
		}
	}

	if err := os.WriteFile(backupPath, envelopeJSON, 0600); err != nil {
		return fmt.Errorf("failed to write backup file: %w", err)
	}

	logger.Info("KMS backup created",
		"path", backupPath,
		"keys", len(fullKeys),
		"keyID", keyID,
	)
	return nil
}

// RestoreKeys restores keys from an encrypted backup.
// It reads the backup envelope from backupPath, derives the decryption key from
// backupPassword via scrypt, decrypts with AES-256-GCM, deserializes the keys,
// and writes each one to the KMS storage directory.
func (m *MPCKMSIntegration) RestoreKeys(backupPath string, backupPassword string) error {
	if backupPassword == "" {
		return fmt.Errorf("backup password must not be empty")
	}

	// Read backup file
	envelopeJSON, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("failed to read backup file: %w", err)
	}

	var envelope backupEnvelope
	if err := json.Unmarshal(envelopeJSON, &envelope); err != nil {
		return fmt.Errorf("failed to parse backup envelope: %w", err)
	}

	if envelope.Version != 1 {
		return fmt.Errorf("unsupported backup version: %d", envelope.Version)
	}

	// Decode base64 fields
	salt, err := base64.StdEncoding.DecodeString(envelope.Salt)
	if err != nil {
		return fmt.Errorf("failed to decode salt: %w", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(envelope.Nonce)
	if err != nil {
		return fmt.Errorf("failed to decode nonce: %w", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(envelope.Data)
	if err != nil {
		return fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	// Derive decryption key
	decKey, err := deriveBackupKey(backupPassword, salt)
	if err != nil {
		return fmt.Errorf("failed to derive backup key: %w", err)
	}

	// Verify key ID matches
	keyHash := sha256.Sum256(decKey)
	keyID := fmt.Sprintf("%x", keyHash[:])[:16]
	if keyID != envelope.KeyID {
		return fmt.Errorf("backup password incorrect (key ID mismatch)")
	}

	// Decrypt with AES-256-GCM
	block, err := aes.NewCipher(decKey)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("failed to decrypt backup (wrong password?): %w", err)
	}

	// Deserialize keys
	var keys []*EncryptedKey
	if err := json.Unmarshal(plaintext, &keys); err != nil {
		return fmt.Errorf("failed to deserialize backup keys: %w", err)
	}

	// Write each key to KMS storage
	m.kms.mu.Lock()
	defer m.kms.mu.Unlock()

	restored := 0
	for _, ek := range keys {
		m.kms.keys[ek.ID] = ek
		if err := m.kms.saveKey(ek); err != nil {
			logger.Warn("Failed to restore key", "id", ek.ID, "err", err)
			continue
		}
		restored++
	}

	logger.Info("KMS backup restored",
		"path", backupPath,
		"total", len(keys),
		"restored", restored,
	)
	return nil
}
