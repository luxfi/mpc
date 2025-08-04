package kms

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	kmsgo "github.com/luxfi/kms-go"
	kmsmodels "github.com/luxfi/kms-go/packages/models"
	"github.com/luxfi/mpc/pkg/logger"
)

// KMSClient wraps the Lux KMS SDK for MPC key management
type KMSClient struct {
	client      kmsgo.KMSClientInterface
	projectID   string
	environment string
	secretPath  string
	siteURL     string
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

// NewKMSClient creates a new Lux KMS client for secure key operations
func NewKMSClient(config KMSConfig) (*KMSClient, error) {
	// Validate config
	if config.ProjectID == "" {
		return nil, fmt.Errorf("project ID is required")
	}

	// Set defaults
	if config.Environment == "" {
		config.Environment = "prod"
	}
	if config.SecretPath == "" {
		config.SecretPath = "/mpc"
	}
	if config.SiteURL == "" {
		// Check if running locally
		if _, err := os.Stat("/Users/z/work/lux/kms"); err == nil {
			config.SiteURL = "http://localhost:8080" // Local Lux KMS instance
		} else {
			config.SiteURL = "https://kms.lux.network"
		}
	}

	// Create KMS client configuration
	kmsConfig := kmsgo.Config{
		SiteUrl: config.SiteURL,
	}

	// Create client in a separate context
	ctx := context.Background()
	client := kmsgo.NewKMSClient(ctx, kmsConfig)

	// Authenticate based on available credentials
	if config.ClientID != "" && config.ClientSecret != "" {
		// Use Universal Auth (machine identity)
		auth := client.Auth()
		_, err := auth.UniversalAuthLogin(config.ClientID, config.ClientSecret)
		if err != nil {
			return nil, fmt.Errorf("failed to authenticate with universal auth: %w", err)
		}
	} else {
		// Use access token auth (fallback)
		accessToken := os.Getenv("KMS_ACCESS_TOKEN")
		if accessToken == "" {
			return nil, fmt.Errorf("no authentication method available: set KMS_ACCESS_TOKEN or provide universal auth credentials")
		}
		auth := client.Auth()
		auth.SetAccessToken(accessToken)
	}

	return &KMSClient{
		client:      client,
		projectID:   config.ProjectID,
		environment: config.Environment,
		secretPath:  config.SecretPath,
		siteURL:     config.SiteURL,
	}, nil
}

// StoreMPCKeyShare stores an MPC key share in Lux KMS
func (c *KMSClient) StoreMPCKeyShare(nodeID, walletID, keyType string, keyShare []byte) error {
	secretName := fmt.Sprintf("mpc_%s_%s_%s", nodeID, walletID, keyType)
	
	// Convert key share to JSON string for storage
	keyShareJSON, err := json.Marshal(keyShare)
	if err != nil {
		return fmt.Errorf("failed to marshal key share: %w", err)
	}

	_, err = c.client.Secrets().Create(kmsgo.CreateSecretOptions{
		ProjectId:       c.projectID,
		Environment:     c.environment,
		SecretPath:      c.secretPath,
		SecretKey:       secretName,
		SecretValue:     string(keyShareJSON),
		SecretComment:   fmt.Sprintf("MPC key share for node %s, wallet %s, type %s", nodeID, walletID, keyType),
		SecretType:      "shared",
	})

	if err != nil {
		// Try to update if already exists
		_, updateErr := c.client.Secrets().Update(kmsgo.UpdateSecretOptions{
			ProjectId:       c.projectID,
			Environment:     c.environment,
			SecretPath:      c.secretPath,
			SecretKey:       secretName,
			SecretValue:     string(keyShareJSON),
			SecretType:      "shared",
		})
		if updateErr != nil {
			return fmt.Errorf("failed to create/update secret: %w", err)
		}
	}

	logger.Info("Stored MPC key share in Lux KMS", "nodeID", nodeID, "walletID", walletID, "keyType", keyType)
	return nil
}

// RetrieveMPCKeyShare retrieves an MPC key share from Lux KMS
func (c *KMSClient) RetrieveMPCKeyShare(nodeID, walletID, keyType string) ([]byte, error) {
	secretName := fmt.Sprintf("mpc_%s_%s_%s", nodeID, walletID, keyType)
	
	secret, err := c.client.Secrets().Retrieve(kmsgo.RetrieveSecretOptions{
		ProjectId:   c.projectID,
		Environment: c.environment,
		SecretPath:  c.secretPath,
		SecretKey:   secretName,
		SecretType:  "shared",
	})

	if err != nil {
		return nil, fmt.Errorf("failed to retrieve secret: %w", err)
	}

	// Parse JSON key share
	var keyShare []byte
	if err := json.Unmarshal([]byte(secret.SecretValue), &keyShare); err != nil {
		return nil, fmt.Errorf("failed to unmarshal key share: %w", err)
	}

	return keyShare, nil
}

// StoreInitiatorKey stores the initiator private key in Lux KMS
func (c *KMSClient) StoreInitiatorKey(nodeID string, privateKey []byte) error {
	secretName := fmt.Sprintf("initiator_key_%s", nodeID)
	
	_, err := c.client.Secrets().Create(kmsgo.CreateSecretOptions{
		ProjectId:       c.projectID,
		Environment:     c.environment,
		SecretPath:      c.secretPath,
		SecretKey:       secretName,
		SecretValue:     fmt.Sprintf("%x", privateKey),
		SecretComment:   fmt.Sprintf("Initiator private key for node %s", nodeID),
		SecretType:      "shared",
	})

	if err != nil {
		// Try to update if already exists
		_, updateErr := c.client.Secrets().Update(kmsgo.UpdateSecretOptions{
			ProjectId:   c.projectID,
			Environment: c.environment,
			SecretPath:  c.secretPath,
			SecretKey:   secretName,
			SecretValue: fmt.Sprintf("%x", privateKey),
			SecretType:  "shared",
		})
		if updateErr != nil {
			return fmt.Errorf("failed to create/update initiator key: %w", err)
		}
	}

	return nil
}

// RetrieveInitiatorKey retrieves the initiator private key from Lux KMS
func (c *KMSClient) RetrieveInitiatorKey(nodeID string) ([]byte, error) {
	secretName := fmt.Sprintf("initiator_key_%s", nodeID)
	
	secret, err := c.client.Secrets().Retrieve(kmsgo.RetrieveSecretOptions{
		ProjectId:   c.projectID,
		Environment: c.environment,
		SecretPath:  c.secretPath,
		SecretKey:   secretName,
		SecretType:  "shared",
	})

	if err != nil {
		return nil, fmt.Errorf("failed to retrieve initiator key: %w", err)
	}

	// Parse hex string back to bytes
	var privateKey []byte
	if _, err := fmt.Sscanf(secret.SecretValue, "%x", &privateKey); err != nil {
		return nil, fmt.Errorf("failed to parse initiator key: %w", err)
	}

	return privateKey, nil
}

// ListKeys lists all MPC-related keys in Lux KMS
func (c *KMSClient) ListKeys() ([]string, error) {
	secrets, err := c.client.Secrets().List(kmsgo.ListSecretsOptions{
		ProjectId:          c.projectID,
		Environment:        c.environment,
		SecretPath:         c.secretPath,
		IncludeImports:     false,
		AttachToProcessEnv: false,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}

	var keys []string
	for _, secret := range secrets {
		keys = append(keys, secret.SecretKey)
	}

	return keys, nil
}

// DeleteKey deletes a key from Lux KMS
func (c *KMSClient) DeleteKey(secretName string) error {
	_, err := c.client.Secrets().Delete(kmsgo.DeleteSecretOptions{
		ProjectId:   c.projectID,
		Environment: c.environment,
		SecretPath:  c.secretPath,
		SecretKey:   secretName,
		SecretType:  "shared",
	})

	if err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	return nil
}