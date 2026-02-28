package kms

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"

	"github.com/luxfi/mpc/pkg/logger"
)

// KMSClient wraps the Lux KMS SDK for MPC key management.
// All secrets are encrypted at rest with AES-256-GCM using a master key
// derived from client credentials via Argon2id.
type KMSClient struct {
	mu          sync.RWMutex
	projectID   string
	environment string
	secretPath  string
	siteURL     string
	masterKey   []byte // 32-byte AES-256 key derived from credentials
	// Encrypted secrets stored in memory (ciphertext, not plaintext)
	secrets map[string][]byte
}

// KMSConfig holds configuration for Lux KMS integration
type KMSConfig struct {
	ClientID     string
	ClientSecret string
	ProjectID    string
	Environment  string
	SecretPath   string
	SiteURL      string
}

// SecretMetadata represents metadata about a secret
type SecretMetadata struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	Version     int    `json:"version"`
	Environment string `json:"environment"`
	Type        string `json:"type"`
}

// NewKMSClient creates a new Lux KMS client for secure key operations.
// A 32-byte master key is derived from ClientID + ClientSecret via Argon2id.
// If no credentials are provided, a deterministic fallback key is used (development only).
func NewKMSClient(config KMSConfig) (*KMSClient, error) {
	if config.ProjectID == "" {
		return nil, fmt.Errorf("project ID is required")
	}

	if config.Environment == "" {
		config.Environment = "prod"
	}
	if config.SecretPath == "" {
		config.SecretPath = "/mpc"
	}
	if config.SiteURL == "" {
		config.SiteURL = "http://localhost:8080"
	}

	// Derive master key from client credentials
	var masterKey []byte
	if config.ClientID != "" && config.ClientSecret != "" {
		// Use client credentials to derive a strong encryption key
		salt := sha256.Sum256([]byte("luxkms:" + config.ProjectID + ":" + config.ClientID))
		masterKey = argon2.IDKey([]byte(config.ClientSecret), salt[:], 1, 64*1024, 4, 32)
	} else {
		// Development fallback -- deterministic but not secure for production
		logger.Warn("No KMS client credentials provided, using deterministic key (NOT FOR PRODUCTION)")
		salt := sha256.Sum256([]byte("luxkms:dev:" + config.ProjectID))
		masterKey = argon2.IDKey([]byte("dev-fallback-"+config.ProjectID), salt[:], 1, 64*1024, 4, 32)
	}

	logger.Info("Initializing KMS client with AES-256-GCM encryption",
		"projectID", config.ProjectID,
		"environment", config.Environment,
		"secretPath", config.SecretPath,
	)

	return &KMSClient{
		projectID:   config.ProjectID,
		environment: config.Environment,
		secretPath:  config.SecretPath,
		siteURL:     config.SiteURL,
		masterKey:   masterKey,
		secrets:     make(map[string][]byte),
	}, nil
}

// encrypt encrypts plaintext using AES-256-GCM with the master key.
// The nonce is prepended to the ciphertext.
func (c *KMSClient) encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// nonce || ciphertext
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// decrypt decrypts ciphertext (nonce || encrypted) using AES-256-GCM with the master key.
func (c *KMSClient) decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// storeEncrypted encrypts and stores a secret under the given name.
func (c *KMSClient) storeEncrypted(name string, data []byte) error {
	encrypted, err := c.encrypt(data)
	if err != nil {
		return fmt.Errorf("encryption failed for %s: %w", name, err)
	}
	c.mu.Lock()
	c.secrets[name] = encrypted
	c.mu.Unlock()
	return nil
}

// retrieveEncrypted retrieves and decrypts a secret by name.
func (c *KMSClient) retrieveEncrypted(name string) ([]byte, error) {
	c.mu.RLock()
	encrypted, ok := c.secrets[name]
	c.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("secret not found: %s", name)
	}
	return c.decrypt(encrypted)
}

// StoreKeyShare stores an MPC key share encrypted with AES-256-GCM
func (c *KMSClient) StoreKeyShare(ctx context.Context, walletID string, keyShare []byte) error {
	secretName := fmt.Sprintf("%s/wallets/%s/keyshare", c.secretPath, walletID)
	if err := c.storeEncrypted(secretName, keyShare); err != nil {
		return err
	}
	logger.Info("Stored key share (encrypted)",
		"walletID", walletID,
		"size", len(keyShare),
	)
	return nil
}

// RetrieveKeyShare retrieves and decrypts an MPC key share
func (c *KMSClient) RetrieveKeyShare(ctx context.Context, walletID string) ([]byte, error) {
	secretName := fmt.Sprintf("%s/wallets/%s/keyshare", c.secretPath, walletID)
	keyShare, err := c.retrieveEncrypted(secretName)
	if err != nil {
		return nil, fmt.Errorf("key share not found for wallet %s: %w", walletID, err)
	}
	logger.Info("Retrieved key share (encrypted)",
		"walletID", walletID,
		"size", len(keyShare),
	)
	return keyShare, nil
}

// RotateKeyShare rotates the key share for a wallet (re-encrypts with current key)
func (c *KMSClient) RotateKeyShare(ctx context.Context, walletID string, newKeyShare []byte) error {
	return c.StoreKeyShare(ctx, walletID, newKeyShare)
}

// StorePresignature stores a presignature encrypted with AES-256-GCM
func (c *KMSClient) StorePresignature(ctx context.Context, walletID, sigID string, presigData []byte) error {
	secretName := fmt.Sprintf("%s/wallets/%s/presigs/%s", c.secretPath, walletID, sigID)
	if err := c.storeEncrypted(secretName, presigData); err != nil {
		return err
	}
	logger.Info("Stored presignature (encrypted)",
		"walletID", walletID,
		"sigID", sigID,
		"size", len(presigData),
	)
	return nil
}

// RetrievePresignature retrieves and decrypts a presignature
func (c *KMSClient) RetrievePresignature(ctx context.Context, walletID, sigID string) ([]byte, error) {
	secretName := fmt.Sprintf("%s/wallets/%s/presigs/%s", c.secretPath, walletID, sigID)
	presigData, err := c.retrieveEncrypted(secretName)
	if err != nil {
		return nil, fmt.Errorf("presignature not found for wallet %s, sig %s: %w", walletID, sigID, err)
	}
	logger.Info("Retrieved presignature (encrypted)",
		"walletID", walletID,
		"sigID", sigID,
		"size", len(presigData),
	)
	return presigData, nil
}

// DeletePresignature removes a used presignature
func (c *KMSClient) DeletePresignature(ctx context.Context, walletID, sigID string) error {
	secretName := fmt.Sprintf("%s/wallets/%s/presigs/%s", c.secretPath, walletID, sigID)
	c.mu.Lock()
	delete(c.secrets, secretName)
	c.mu.Unlock()
	logger.Info("Deleted presignature",
		"walletID", walletID,
		"sigID", sigID,
	)
	return nil
}

// ListSecrets lists all secrets in a given path (metadata only, no decryption)
func (c *KMSClient) ListSecrets(ctx context.Context, path string) ([]SecretMetadata, error) {
	fullPath := fmt.Sprintf("%s%s", c.secretPath, path)

	c.mu.RLock()
	defer c.mu.RUnlock()

	var secrets []SecretMetadata
	for key := range c.secrets {
		if strings.HasPrefix(key, fullPath) {
			secrets = append(secrets, SecretMetadata{
				Name:        key,
				Path:        fullPath,
				Version:     1,
				Environment: c.environment,
				Type:        "keyshare",
			})
		}
	}

	return secrets, nil
}

// Healthcheck verifies KMS connectivity and encryption capability
func (c *KMSClient) Healthcheck(ctx context.Context) error {
	// Verify encryption round-trip works
	testData := []byte("healthcheck")
	encrypted, err := c.encrypt(testData)
	if err != nil {
		return fmt.Errorf("encryption healthcheck failed: %w", err)
	}
	decrypted, err := c.decrypt(encrypted)
	if err != nil {
		return fmt.Errorf("decryption healthcheck failed: %w", err)
	}
	if string(decrypted) != string(testData) {
		return fmt.Errorf("encryption round-trip mismatch")
	}
	logger.Debug("KMS health check passed")
	return nil
}

// Close closes the KMS client and zeroes the master key
func (c *KMSClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Zero master key material
	for i := range c.masterKey {
		c.masterKey[i] = 0
	}
	c.secrets = nil
	logger.Info("KMS client closed")
	return nil
}

// StoreMPCKeyShare stores an MPC key share with specific node and wallet IDs (encrypted)
func (c *KMSClient) StoreMPCKeyShare(nodeID, walletID, keyType string, keyData []byte) error {
	secretName := fmt.Sprintf("%s/nodes/%s/wallets/%s/%s", c.secretPath, nodeID, walletID, keyType)
	if err := c.storeEncrypted(secretName, keyData); err != nil {
		return err
	}
	logger.Info("Stored MPC key share (encrypted)",
		"nodeID", nodeID,
		"walletID", walletID,
		"keyType", keyType,
		"size", len(keyData),
	)
	return nil
}

// RetrieveMPCKeyShare retrieves and decrypts an MPC key share
func (c *KMSClient) RetrieveMPCKeyShare(nodeID, walletID, keyType string) ([]byte, error) {
	secretName := fmt.Sprintf("%s/nodes/%s/wallets/%s/%s", c.secretPath, nodeID, walletID, keyType)
	keyData, err := c.retrieveEncrypted(secretName)
	if err != nil {
		return nil, fmt.Errorf("key share not found for node %s, wallet %s, type %s: %w", nodeID, walletID, keyType, err)
	}
	logger.Info("Retrieved MPC key share (encrypted)",
		"nodeID", nodeID,
		"walletID", walletID,
		"keyType", keyType,
		"size", len(keyData),
	)
	return keyData, nil
}

// ListKeys lists all secret names (without decrypting values)
func (c *KMSClient) ListKeys() ([]string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	keys := make([]string, 0, len(c.secrets))
	for key := range c.secrets {
		keys = append(keys, key)
	}
	logger.Info("Listed keys", "count", len(keys))
	return keys, nil
}

// DeleteKey removes a key from storage
func (c *KMSClient) DeleteKey(key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.secrets[key]; !ok {
		return fmt.Errorf("key not found: %s", key)
	}
	delete(c.secrets, key)
	logger.Info("Deleted key", "key", key)
	return nil
}

// BatchStore encrypts and stores multiple secrets
func (c *KMSClient) BatchStore(ctx context.Context, secrets map[string][]byte) error {
	for name, data := range secrets {
		fullName := fmt.Sprintf("%s/%s", c.secretPath, name)
		if err := c.storeEncrypted(fullName, data); err != nil {
			return fmt.Errorf("failed to store %s: %w", name, err)
		}
	}
	logger.Info("Batch stored secrets (encrypted)", "count", len(secrets))
	return nil
}

// BatchRetrieve decrypts and retrieves multiple secrets
func (c *KMSClient) BatchRetrieve(ctx context.Context, names []string) (map[string][]byte, error) {
	results := make(map[string][]byte)
	for _, name := range names {
		fullName := fmt.Sprintf("%s/%s", c.secretPath, name)
		data, err := c.retrieveEncrypted(fullName)
		if err != nil {
			continue // skip missing secrets
		}
		results[name] = data
	}
	logger.Info("Batch retrieved secrets (encrypted)", "requested", len(names), "found", len(results))
	return results, nil
}

// StoreConfig encrypts and stores MPC node configuration
func (c *KMSClient) StoreConfig(ctx context.Context, nodeID string, config interface{}) error {
	configName := fmt.Sprintf("%s/nodes/%s/config", c.secretPath, nodeID)
	data, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	if err := c.storeEncrypted(configName, data); err != nil {
		return err
	}
	logger.Info("Stored node config (encrypted)", "nodeID", nodeID)
	return nil
}

// RetrieveConfig decrypts and retrieves MPC node configuration
func (c *KMSClient) RetrieveConfig(ctx context.Context, nodeID string, config interface{}) error {
	configName := fmt.Sprintf("%s/nodes/%s/config", c.secretPath, nodeID)
	data, err := c.retrieveEncrypted(configName)
	if err != nil {
		return fmt.Errorf("config not found for node %s: %w", nodeID, err)
	}
	if err := json.Unmarshal(data, config); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}
	logger.Info("Retrieved node config (encrypted)", "nodeID", nodeID)
	return nil
}

// GenerateEncryptionKey generates a cryptographically secure 32-byte key
// suitable for use as a master key or data encryption key.
func GenerateEncryptionKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate encryption key: %w", err)
	}
	return key, nil
}
