package hsm

import (
	"fmt"
	"os"
	"strings"
)

// NewPasswordProvider creates a PasswordProvider based on the given type string.
// Supported types: "aws", "gcp", "azure", "env", "file".
//
// The config map is optional — if nil, configuration is read from environment
// variables specific to each provider:
//
//	aws:   AWS_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, ZAPDB_ENCRYPTED_PASSWORD
//	gcp:   GCP_PROJECT_ID, GCP_KMS_LOCATION, GCP_KMS_KEYRING, GCP_KMS_KEY, ZAPDB_ENCRYPTED_PASSWORD
//	azure: AZURE_VAULT_URL, AZURE_KEY_NAME, AZURE_KEY_VERSION, ZAPDB_ENCRYPTED_PASSWORD
//	env:   LUX_MPC_PASSWORD or ZAPDB_PASSWORD
//	file:  MPC_PASSWORD_FILE
//
// If providerType is empty, it defaults to "env" for backward compatibility.
func NewPasswordProvider(providerType string, config map[string]string) (PasswordProvider, error) {
	providerType = strings.TrimSpace(strings.ToLower(providerType))
	if providerType == "" {
		providerType = "env"
	}

	// Helper to get a config value with env var fallback
	get := func(key, envKey string) string {
		if config != nil {
			if v, ok := config[key]; ok && v != "" {
				return v
			}
		}
		return os.Getenv(envKey)
	}

	switch providerType {
	case "aws":
		return &AWSKMSProvider{
			KeyID:  get("key_id", "MPC_HSM_KEY_ID"),
			Region: get("region", "AWS_REGION"),
		}, nil

	case "gcp":
		return &GCPKMSProvider{
			ProjectID:   get("project_id", "GCP_PROJECT_ID"),
			LocationID:  get("location", "GCP_KMS_LOCATION"),
			KeyRingID:   get("key_ring", "GCP_KMS_KEYRING"),
			CryptoKeyID: get("crypto_key", "GCP_KMS_KEY"),
		}, nil

	case "azure":
		return &AzureKVProvider{
			VaultURL:   get("vault_url", "AZURE_VAULT_URL"),
			KeyName:    get("key_name", "AZURE_KEY_NAME"),
			KeyVersion: get("key_version", "AZURE_KEY_VERSION"),
		}, nil

	case "env":
		envVar := get("env_var", "")
		if envVar == "" {
			envVar = "LUX_MPC_PASSWORD"
		}
		return &EnvProvider{
			EnvVar: envVar,
		}, nil

	case "file":
		return &FileProvider{
			Path: get("path", "MPC_PASSWORD_FILE"),
		}, nil

	default:
		return nil, fmt.Errorf("hsm: unknown provider type %q (supported: aws, gcp, azure, env, file)", providerType)
	}
}
