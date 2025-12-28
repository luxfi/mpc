package mpc

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/viper"

	"github.com/luxfi/mpc/pkg/kms"
	"github.com/luxfi/mpc/pkg/kvstore"
	"github.com/luxfi/mpc/pkg/logger"
)

// KMSEnabledKVStore wraps a regular KVStore with KMS encryption
type KMSEnabledKVStore struct {
	kvstore.KVStore
	kmsClient *kms.KMSClient
	enabled   bool
	nodeID    string
}

// NewKMSEnabledKVStore creates a new KMS-enabled KV store
func NewKMSEnabledKVStore(store kvstore.KVStore, nodeID string) (*KMSEnabledKVStore, error) {
	// Try to initialize Lux KMS integration
	kmsConfig := kms.KMSConfig{
		ClientID:     viper.GetString("kms.client_id"),
		ClientSecret: viper.GetString("kms.client_secret"),
		ProjectID:    viper.GetString("kms.project_id"),
		Environment:  viper.GetString("kms.environment"),
		SecretPath:   viper.GetString("kms.secret_path"),
		SiteURL:      viper.GetString("kms.site_url"),
	}

	// If no project ID is set, check environment variable
	if kmsConfig.ProjectID == "" {
		kmsConfig.ProjectID = os.Getenv("KMS_PROJECT_ID")
	}

	// If still no project ID, disable KMS
	// In production, KMS is mandatory — unencrypted key share storage is fatal.
	environment := os.Getenv("ENVIRONMENT")
	if kmsConfig.ProjectID == "" {
		if environment != "" && environment != "development" {
			logger.Fatal("KMS project ID is required in production — refusing to store key shares unencrypted", nil)
		}
		logger.Warn("No Lux KMS project ID configured, falling back to regular storage (development only)")
		return &KMSEnabledKVStore{
			KVStore: store,
			enabled: false,
		}, nil
	}

	kmsClient, err := kms.NewKMSClient(kmsConfig)
	if err != nil {
		if environment != "" && environment != "development" {
			logger.Fatal("Failed to initialize Lux KMS in production — refusing to store key shares unencrypted", err)
		}
		logger.Warn("Failed to initialize Lux KMS integration, falling back to regular storage (development only)", "error", err)
		return &KMSEnabledKVStore{
			KVStore: store,
			enabled: false,
		}, nil
	}

	logger.Info("Lux KMS integration enabled for secure key storage")
	return &KMSEnabledKVStore{
		KVStore:   store,
		kmsClient: kmsClient,
		enabled:   true,
		nodeID:    nodeID,
	}, nil
}

// Put stores a value with KMS encryption if enabled
func (k *KMSEnabledKVStore) Put(key string, value []byte) error {
	if !k.enabled {
		// Fallback to regular storage
		return k.KVStore.Put(key, value)
	}

	// For MPC key shares, use KMS
	if isKeyShare(key) {
		// Detect key type from the share data
		keyType := "ecdsa" // Default

		// Try to parse the share to determine type
		var shareData map[string]interface{}
		if err := json.Unmarshal(value, &shareData); err == nil {
			if _, hasEDDSA := shareData["eddsa"]; hasEDDSA {
				keyType = "eddsa"
			}
		}

		// Store in Lux KMS
		ctx := context.Background()
		if err := k.kmsClient.StoreKeyShare(ctx, key, value); err != nil {
			environment := os.Getenv("ENVIRONMENT")
			if environment != "" && environment != "development" {
				logger.Fatal("Failed to store key share in Lux KMS (production) — refusing unencrypted fallback", err)
			}
			logger.Error("Failed to store key share in Lux KMS, falling back to regular storage (development only)", err, "walletID", key)
			return k.KVStore.Put(key, value)
		}

		// Store a reference in regular KVStore
		reference := map[string]string{
			"storage": "kms",
			"wallet":  key,
			"type":    keyType,
		}
		refData, _ := json.Marshal(reference)
		return k.KVStore.Put(key, refData)
	}

	// For non-key data, use regular storage
	return k.KVStore.Put(key, value)
}

// Get retrieves a value with KMS decryption if needed
func (k *KMSEnabledKVStore) Get(key string) ([]byte, error) {
	if !k.enabled {
		// Fallback to regular storage
		return k.KVStore.Get(key)
	}

	// First, get from regular storage
	data, err := k.KVStore.Get(key)
	if err != nil {
		return nil, err
	}

	// Check if this is a KMS reference
	var reference map[string]string
	if err := json.Unmarshal(data, &reference); err == nil {
		if reference["storage"] == "kms" {
			// Retrieve from Lux KMS
			ctx := context.Background()
			share, err := k.kmsClient.RetrieveKeyShare(ctx, key)
			if err != nil {
				logger.Error("Failed to retrieve key share from Lux KMS", err, "walletID", key)
				return nil, fmt.Errorf("failed to retrieve from Lux KMS: %w", err)
			}
			return share, nil
		}
	}

	// Regular data, return as-is
	return data, nil
}

// Delete removes a value and its KMS entry if applicable
func (k *KMSEnabledKVStore) Delete(key string) error {
	if k.enabled {
		// Try to get the reference first
		data, err := k.KVStore.Get(key)
		if err == nil {
			var reference map[string]string
			if err := json.Unmarshal(data, &reference); err == nil {
				if reference["storage"] == "kms" {
					// Delete the key share from Lux KMS
					ctx := context.Background()
					if delErr := k.kmsClient.DeleteKeyShare(ctx, key); delErr != nil {
						logger.Warn("Failed to delete key share from Lux KMS, continuing with local delete",
							"key", key,
							"err", delErr,
						)
					} else {
						logger.Info("Deleted key share from Lux KMS", "key", key)
					}
				}
			}
		}
	}

	// Delete from regular storage
	return k.KVStore.Delete(key)
}

// isKeyShare checks if a key represents an MPC key share that requires KMS encryption.
// Key shares are stored under org-scoped paths ("org:<orgID>:<walletID>") or with
// known key-type prefixes (frost:, bls:, sr25519:, tfhe:). Metadata keys that do not
// match these patterns pass through to regular storage unencrypted.
func isKeyShare(key string) bool {
	// Org-scoped keys are always key shares
	if strings.HasPrefix(key, "org:") {
		return true
	}
	// Known key-type prefixed shares
	for _, prefix := range []string{"frost:", "bls:", "sr25519:", "tfhe:"} {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	// Hex-encoded wallet IDs (32-char hex = 16 bytes, 64-char hex = 32 bytes)
	if len(key) == 32 || len(key) == 64 {
		allHex := true
		for _, c := range key {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				allHex = false
				break
			}
		}
		if allHex {
			return true
		}
	}
	return false
}
