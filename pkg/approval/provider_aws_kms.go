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

// AWSKMSProvider produces ECDSA-P256 / secp256k1 approval signatures using
// AWS KMS asymmetric keys. The private key never leaves AWS HSM; we sign by
// calling AWS KMS Sign and verify locally against the cached public key.
//
// Configuration:
//
//	region — AWS region (e.g. "us-east-1"). Defaults to AWS_REGION env.
//
// Approver enrollment is explicit: callers must register each approver's
// (approverID -> KMS key ARN, P-256 public key, optional attestation)
// via Enroll. This avoids per-approval GetPublicKey calls and gives the
// caller (PaaS / KMSSecret CRD pipeline) a single place to provision keys.
type AWSKMSProvider struct {
	signer luxhsm.Signer

	mu       sync.RWMutex
	identity map[string]awsKMSEntry // approverID -> KMS key + cached pubkey
}

type awsKMSEntry struct {
	KeyARN    string
	PubKey    *ecdsa.PublicKey
	PubKeyDER []byte // SPKI DER for stable on-wire identity
}

// NewAWSKMS constructs an AWS-KMS-backed ApprovalProvider.
func NewAWSKMS(config map[string]string) (ApprovalProvider, error) {
	region := ""
	if config != nil {
		region = config["region"]
	}
	signer, err := luxhsm.NewSigner("aws", map[string]string{"region": region})
	if err != nil {
		return nil, fmt.Errorf("approval/aws-kms: %w", err)
	}
	return &AWSKMSProvider{
		signer:   signer,
		identity: make(map[string]awsKMSEntry),
	}, nil
}

func (p *AWSKMSProvider) Provider() string { return "aws-kms" }

// Enroll registers an approver's (KMS key ARN + DER-encoded SPKI public key).
// pubKeyDER is the SubjectPublicKeyInfo bytes returned by AWS KMS GetPublicKey;
// the provider parses it once and caches the *ecdsa.PublicKey.
//
// In production, this is called by the operator pipeline after `aws kms
// get-public-key` resolves to the executive's distinct KMS key.
func (p *AWSKMSProvider) Enroll(approverID, keyARN string, pubKeyDER []byte) error {
	pub, err := x509.ParsePKIXPublicKey(pubKeyDER)
	if err != nil {
		return fmt.Errorf("approval/aws-kms: parse public key: %w", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("approval/aws-kms: enrolled key is not ECDSA")
	}
	if ecPub.Curve != elliptic.P256() {
		return fmt.Errorf("approval/aws-kms: unsupported curve %s (want P-256)", ecPub.Curve.Params().Name)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.identity[approverID] = awsKMSEntry{
		KeyARN:    keyARN,
		PubKey:    ecPub,
		PubKeyDER: pubKeyDER,
	}
	return nil
}

// EnrollPEM is a convenience that accepts a PEM-encoded public key.
func (p *AWSKMSProvider) EnrollPEM(approverID, keyARN string, pemBytes []byte) error {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return errors.New("approval/aws-kms: invalid PEM")
	}
	return p.Enroll(approverID, keyARN, block.Bytes)
}

func (p *AWSKMSProvider) GetPublicIdentity(_ context.Context, approverID string) (PublicIdentity, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	entry, ok := p.identity[approverID]
	if !ok {
		return PublicIdentity{}, fmt.Errorf("approval/aws-kms: approver %q not enrolled", approverID)
	}
	return PublicIdentity{
		ApproverID: approverID,
		Provider:   p.Provider(),
		PublicKey:  entry.PubKeyDER,
		Algorithm:  AlgorithmECDSAP256,
	}, nil
}

func (p *AWSKMSProvider) ApproveIntent(ctx context.Context, approverID string, intent CanonicalIntent) (ApprovalSignature, error) {
	p.mu.RLock()
	entry, ok := p.identity[approverID]
	p.mu.RUnlock()
	if !ok {
		return ApprovalSignature{}, fmt.Errorf("approval/aws-kms: approver %q not enrolled", approverID)
	}
	digest := intent.Digest()
	// luxfi/hsm AWS Signer hashes the message itself (MessageType=DIGEST).
	// We pass digest[:] directly — the wrapper SHA-256s it again, which is
	// what AWS KMS expects when MessageType=DIGEST and the input IS already
	// the digest bytes. To avoid double-hash, pass the canonical Bytes()
	// pre-image and let AWS hash it once.
	sig, err := p.signer.Sign(ctx, entry.KeyARN, intent.Bytes())
	if err != nil {
		return ApprovalSignature{}, fmt.Errorf("approval/aws-kms: sign: %w", err)
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

func (p *AWSKMSProvider) VerifyApproval(_ context.Context, intent CanonicalIntent, sig ApprovalSignature) (bool, error) {
	if sig.Provider != p.Provider() {
		return false, nil
	}
	if sig.Algorithm != AlgorithmECDSAP256 {
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
	// Local verification — AWS KMS ECDSA_SHA_256 produces an ASN.1 DER signature
	// over SHA-256(message). intent.Bytes() is the message, digest is the SHA-256.
	h := sha256.Sum256(intent.Bytes())
	return ecdsa.VerifyASN1(entry.PubKey, h[:], sig.Signature), nil
}
