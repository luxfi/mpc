package approval

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
	"time"

	luxhsm "github.com/luxfi/hsm"
)

// AzureKeyVaultProvider produces ES256 (P-256) approval signatures via
// Azure Key Vault / Managed HSM. Mirrors AWSKMSProvider.
//
// Configuration:
//
//	vault_url — full Vault URL (e.g. "https://approvals.vault.azure.net").
//	            Optional; falls back to AZURE_VAULT_URL.
//
// Approver enrollment by Vault key name + cached SPKI public key.
type AzureKeyVaultProvider struct {
	signer luxhsm.Signer

	mu       sync.RWMutex
	identity map[string]azureKVEntry
}

type azureKVEntry struct {
	KeyName   string // Vault key name (or "{name}/{version}")
	PubKey    *ecdsa.PublicKey
	PubKeyDER []byte
}

func NewAzureKeyVault(config map[string]string) (ApprovalProvider, error) {
	vaultURL := ""
	if config != nil {
		vaultURL = config["vault_url"]
	}
	signer, err := luxhsm.NewSigner("azure", map[string]string{"vault_url": vaultURL})
	if err != nil {
		return nil, fmt.Errorf("approval/azure-keyvault: %w", err)
	}
	return &AzureKeyVaultProvider{
		signer:   signer,
		identity: make(map[string]azureKVEntry),
	}, nil
}

func (p *AzureKeyVaultProvider) Provider() string { return "azure-keyvault" }

func (p *AzureKeyVaultProvider) Enroll(approverID, keyName string, pubKeyDER []byte) error {
	pub, err := x509.ParsePKIXPublicKey(pubKeyDER)
	if err != nil {
		return fmt.Errorf("approval/azure-keyvault: parse public key: %w", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("approval/azure-keyvault: enrolled key is not ECDSA")
	}
	if ecPub.Curve != elliptic.P256() {
		return fmt.Errorf("approval/azure-keyvault: unsupported curve %s (want P-256)", ecPub.Curve.Params().Name)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.identity[approverID] = azureKVEntry{
		KeyName:   keyName,
		PubKey:    ecPub,
		PubKeyDER: pubKeyDER,
	}
	return nil
}

func (p *AzureKeyVaultProvider) EnrollPEM(approverID, keyName string, pemBytes []byte) error {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return errors.New("approval/azure-keyvault: invalid PEM")
	}
	return p.Enroll(approverID, keyName, block.Bytes)
}

func (p *AzureKeyVaultProvider) GetPublicIdentity(_ context.Context, approverID string) (PublicIdentity, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	entry, ok := p.identity[approverID]
	if !ok {
		return PublicIdentity{}, fmt.Errorf("approval/azure-keyvault: approver %q not enrolled", approverID)
	}
	return PublicIdentity{
		ApproverID: approverID,
		Provider:   p.Provider(),
		PublicKey:  entry.PubKeyDER,
		Algorithm:  AlgorithmECDSAP256,
	}, nil
}

func (p *AzureKeyVaultProvider) ApproveIntent(ctx context.Context, approverID string, intent CanonicalIntent) (ApprovalSignature, error) {
	p.mu.RLock()
	entry, ok := p.identity[approverID]
	p.mu.RUnlock()
	if !ok {
		return ApprovalSignature{}, fmt.Errorf("approval/azure-keyvault: approver %q not enrolled", approverID)
	}
	digest := intent.Digest()
	sig, err := p.signer.Sign(ctx, entry.KeyName, intent.Bytes())
	if err != nil {
		return ApprovalSignature{}, fmt.Errorf("approval/azure-keyvault: sign: %w", err)
	}
	// Azure ES256 returns raw r||s 64-byte signature. Convert to ASN.1 DER
	// for cross-provider verification consistency (all ECDSA verifiers use
	// VerifyASN1).
	derSig, err := ecdsaRawToASN1(sig)
	if err != nil {
		return ApprovalSignature{}, fmt.Errorf("approval/azure-keyvault: convert signature: %w", err)
	}
	return ApprovalSignature{
		ApproverID:   approverID,
		Provider:     p.Provider(),
		IntentDigest: digest,
		Signature:    derSig,
		Timestamp:    time.Now().UTC(),
		Algorithm:    AlgorithmECDSAP256,
	}, nil
}

func (p *AzureKeyVaultProvider) VerifyApproval(_ context.Context, intent CanonicalIntent, sig ApprovalSignature) (bool, error) {
	if sig.Provider != p.Provider() || sig.Algorithm != AlgorithmECDSAP256 {
		return false, nil
	}
	digest := intent.Digest()
	if digest != sig.IntentDigest {
		return false, nil
	}
	p.mu.RLock()
	entry, ok := p.identity[sig.ApproverID]
	p.mu.RUnlock()
	if !ok {
		return false, nil
	}
	h := sha256.Sum256(intent.Bytes())
	return ecdsa.VerifyASN1(entry.PubKey, h[:], sig.Signature), nil
}
