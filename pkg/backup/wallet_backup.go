package backup

// WalletBackup manages encrypted wallet key share backup with Shamir sharding.
//
// Default: 2-of-2 split — Shard A for user storage (iCloud/Keychain),
// Shard B for platform HSM. Supports N-of-M for institutional custody.
//
// The wallet key share is encrypted with AES-256-GCM using a random backup key.
// The backup key is then Shamir-split into labeled shards that are stored in
// different locations (iCloud, HSM, offline paper, custodian).

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"
)

// Shard destination constants — where each Shamir share is stored.
const (
	ShardDestICloud  = "icloud"  // User's iCloud Keychain / Secure Enclave
	ShardDestHSM     = "hsm"     // Platform HSM (AWS KMS, GCP KMS, etc.)
	ShardDestOffline = "offline" // Paper/USB offline backup key
	ShardDestCustody = "custody" // Third-party custodian
	ShardDestDevice  = "device"  // Local device Secure Enclave / Keystore
)

// WalletBackupConfig configures how a wallet key share is backed up.
type WalletBackupConfig struct {
	Threshold    int      // T shares required (default 2)
	TotalShards  int      // N total shares (default 2)
	Destinations []string // where each shard goes, len must == TotalShards
}

// DefaultBackupConfig returns the standard 2-of-2 split: iCloud + HSM.
func DefaultBackupConfig() WalletBackupConfig {
	return WalletBackupConfig{
		Threshold:    2,
		TotalShards:  2,
		Destinations: []string{ShardDestICloud, ShardDestHSM},
	}
}

// InstitutionalBackupConfig returns a 3-of-5 institutional custody split.
func InstitutionalBackupConfig() WalletBackupConfig {
	return WalletBackupConfig{
		Threshold:   3,
		TotalShards: 5,
		Destinations: []string{
			ShardDestHSM,     // Platform HSM
			ShardDestHSM,     // Second HSM (different provider/region)
			ShardDestCustody, // Third-party custodian
			ShardDestDevice,  // Admin device
			ShardDestOffline, // Offline paper backup
		},
	}
}

// LabeledShard is a Shamir share tagged with its storage destination and metadata.
type LabeledShard struct {
	Share       Share             `json:"share"`
	Destination string            `json:"destination"`
	StorageRef  *string           `json:"storageRef,omitempty"` // reference in destination system
	CreatedAt   time.Time         `json:"createdAt"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// WalletBackupResult contains everything needed to track and recover the backup.
type WalletBackupResult struct {
	BackupID          string         `json:"backupId"`
	WalletID          string         `json:"walletId"`
	EncryptedKeyShare []byte         `json:"encryptedKeyShare"` // AES-256-GCM encrypted
	Shards            []LabeledShard `json:"shards"`
	Threshold         int            `json:"threshold"`
	TotalShards       int            `json:"totalShards"`
	CreatedAt         time.Time      `json:"createdAt"`
}

// BackupWallet encrypts a wallet key share and splits the encryption key
// into labeled Shamir shards according to the given configuration.
func BackupWallet(walletID string, keyShare []byte, cfg WalletBackupConfig) (*WalletBackupResult, error) {
	if len(keyShare) == 0 {
		return nil, errors.New("wallet_backup: key share must not be empty")
	}

	if cfg.Threshold == 0 {
		cfg = DefaultBackupConfig()
	}
	if len(cfg.Destinations) != cfg.TotalShards {
		return nil, fmt.Errorf("wallet_backup: destinations length (%d) must equal total shards (%d)",
			len(cfg.Destinations), cfg.TotalShards)
	}

	// Generate a random 32-byte backup key
	backupKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, backupKey); err != nil {
		return nil, fmt.Errorf("wallet_backup: failed to generate backup key: %w", err)
	}

	// Encrypt the key share with AES-256-GCM
	encryptedKeyShare, err := aesGCMEncrypt(backupKey, keyShare)
	if err != nil {
		return nil, fmt.Errorf("wallet_backup: encryption failed: %w", err)
	}

	// Split the backup key via Shamir
	shamirShares, err := ShamirSplit(backupKey, cfg.TotalShards, cfg.Threshold)
	if err != nil {
		return nil, fmt.Errorf("wallet_backup: shamir split failed: %w", err)
	}

	// Label each shard with its destination
	now := time.Now()
	labeled := make([]LabeledShard, len(shamirShares))
	for i, share := range shamirShares {
		labeled[i] = LabeledShard{
			Share:       share,
			Destination: cfg.Destinations[i],
			CreatedAt:   now,
		}
	}

	// Generate backup ID
	backupIDBytes := make([]byte, 16)
	io.ReadFull(rand.Reader, backupIDBytes)
	backupID := fmt.Sprintf("bk_%x", backupIDBytes)

	return &WalletBackupResult{
		BackupID:          backupID,
		WalletID:          walletID,
		EncryptedKeyShare: encryptedKeyShare,
		Shards:            labeled,
		Threshold:         cfg.Threshold,
		TotalShards:       cfg.TotalShards,
		CreatedAt:         now,
	}, nil
}

// RecoverWallet reconstructs a wallet key share from labeled shards and the
// encrypted key share. Requires at least `threshold` shards.
func RecoverWallet(encryptedKeyShare []byte, shards []LabeledShard) ([]byte, error) {
	if len(encryptedKeyShare) == 0 {
		return nil, errors.New("wallet_backup: encrypted key share must not be empty")
	}
	if len(shards) < 2 {
		return nil, errors.New("wallet_backup: need at least 2 shards for recovery")
	}

	// Extract raw Shamir shares from labeled shards
	rawShares := make([]Share, len(shards))
	for i, ls := range shards {
		rawShares[i] = ls.Share
	}

	// Reconstruct the backup key
	backupKey, err := ShamirCombine(rawShares)
	if err != nil {
		return nil, fmt.Errorf("wallet_backup: shamir combine failed: %w", err)
	}

	// Decrypt the key share
	keyShare, err := aesGCMDecrypt(backupKey, encryptedKeyShare)
	if err != nil {
		return nil, fmt.Errorf("wallet_backup: decryption failed (wrong shards?): %w", err)
	}

	return keyShare, nil
}

// --- AES-256-GCM helpers ---

func aesGCMEncrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
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
	// nonce is prepended to ciphertext
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func aesGCMDecrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ct, nil)
}
