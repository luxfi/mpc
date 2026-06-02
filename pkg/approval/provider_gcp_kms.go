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

// GCPKMSProvider produces ECDSA-P256 approval signatures via Google Cloud
// KMS asymmetric keys. Mirrors AWSKMSProvider; key resource name format:
//
//	projects/{project}/locations/{location}/keyRings/{keyRing}/cryptoKeys/{key}/cryptoKeyVersions/{version}
type GCPKMSProvider struct {
	signer luxhsm.Signer

	mu       sync.RWMutex
	identity map[string]gcpKMSEntry
}

type gcpKMSEntry struct {
	KeyResourceName string
	PubKey          *ecdsa.PublicKey
	PubKeyDER       []byte
}

// NewGCPKMS constructs a GCP-KMS-backed ApprovalProvider. config currently
// has no required fields — credentials are picked up from
// GOOGLE_APPLICATION_CREDENTIALS via luxfi/hsm.
func NewGCPKMS(config map[string]string) (ApprovalProvider, error) {
	_ = config
	signer, err := luxhsm.NewSigner("gcp", nil)
	if err != nil {
		return nil, fmt.Errorf("approval/gcp-kms: %w", err)
	}
	return &GCPKMSProvider{
		signer:   signer,
		identity: make(map[string]gcpKMSEntry),
	}, nil
}

func (p *GCPKMSProvider) Provider() string { return "gcp-kms" }

// Enroll registers an approver's (key resource name + SPKI DER public key).
// In production, the operator pipeline calls `gcloud kms keys versions
// get-public-key` and feeds the result here.
func (p *GCPKMSProvider) Enroll(approverID, keyResourceName string, pubKeyDER []byte) error {
	pub, err := x509.ParsePKIXPublicKey(pubKeyDER)
	if err != nil {
		return fmt.Errorf("approval/gcp-kms: parse public key: %w", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("approval/gcp-kms: enrolled key is not ECDSA")
	}
	if ecPub.Curve != elliptic.P256() {
		return fmt.Errorf("approval/gcp-kms: unsupported curve %s (want P-256)", ecPub.Curve.Params().Name)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.identity[approverID] = gcpKMSEntry{
		KeyResourceName: keyResourceName,
		PubKey:          ecPub,
		PubKeyDER:       pubKeyDER,
	}
	return nil
}

// EnrollPEM accepts a PEM-encoded SPKI public key.
func (p *GCPKMSProvider) EnrollPEM(approverID, keyResourceName string, pemBytes []byte) error {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return errors.New("approval/gcp-kms: invalid PEM")
	}
	return p.Enroll(approverID, keyResourceName, block.Bytes)
}

func (p *GCPKMSProvider) GetPublicIdentity(_ context.Context, approverID string) (PublicIdentity, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	entry, ok := p.identity[approverID]
	if !ok {
		return PublicIdentity{}, fmt.Errorf("approval/gcp-kms: approver %q not enrolled", approverID)
	}
	return PublicIdentity{
		ApproverID: approverID,
		Provider:   p.Provider(),
		PublicKey:  entry.PubKeyDER,
		Algorithm:  AlgorithmECDSAP256,
	}, nil
}

func (p *GCPKMSProvider) ApproveIntent(ctx context.Context, approverID string, intent CanonicalIntent) (ApprovalSignature, error) {
	p.mu.RLock()
	entry, ok := p.identity[approverID]
	p.mu.RUnlock()
	if !ok {
		return ApprovalSignature{}, fmt.Errorf("approval/gcp-kms: approver %q not enrolled", approverID)
	}
	digest := intent.Digest()
	sig, err := p.signer.Sign(ctx, entry.KeyResourceName, intent.Bytes())
	if err != nil {
		return ApprovalSignature{}, fmt.Errorf("approval/gcp-kms: sign: %w", err)
	}
	return ApprovalSignature{
		ApproverID:   approverID,
		Provider:     p.Provider(),
		IntentDigest: digest,
		Signature:    sig,
		Timestamp:    time.Now().UTC(),
		Algorithm:    AlgorithmECDSAP256,
	}, nil
}

func (p *GCPKMSProvider) VerifyApproval(_ context.Context, intent CanonicalIntent, sig ApprovalSignature) (bool, error) {
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
