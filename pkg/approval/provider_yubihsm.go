// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

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

// YubiHSMProvider produces ECDSA-P256 approval signatures via a Yubico
// YubiHSM 2 device. The device is reached over the yubihsm-connector
// daemon (default http://127.0.0.1:12345) using the yubihsm-shell tool.
//
// Configuration:
//
//	connector_url — yubihsm-connector address (default "http://127.0.0.1:12345").
//	auth_key_id   — YubiHSM authentication object ID (decimal).
//	password      — session password (KMS-supplied).
//	algorithm     — signing algorithm ("ecdsa-sha256", "ed25519").
//
// Approver enrollment maps approverID -> YubiHSM object ID + cached SPKI
// public key. Object IDs are provisioned out-of-band with `yubihsm-shell
// put-asymmetric-key` (or generate-asymmetric-key for on-device key gen).
type YubiHSMProvider struct {
	signer luxhsm.Signer

	mu       sync.RWMutex
	identity map[string]yubihsmEntry
}

type yubihsmEntry struct {
	ObjectID  string // YubiHSM object ID ("12", "0x000c").
	PubKey    *ecdsa.PublicKey
	PubKeyDER []byte
}

// NewYubiHSM constructs a YubiHSMProvider. The underlying luxfi/hsm
// signer handles wire-protocol details (session auth, AES-CMAC, AES-CBC).
func NewYubiHSM(config map[string]string) (ApprovalProvider, error) {
	signer, err := luxhsm.NewSigner("yubihsm", config)
	if err != nil {
		return nil, fmt.Errorf("approval/yubihsm: %w", err)
	}
	return &YubiHSMProvider{
		signer:   signer,
		identity: make(map[string]yubihsmEntry),
	}, nil
}

func (p *YubiHSMProvider) Provider() string { return "yubihsm" }

// Enroll registers approverID -> objectID with a pinned PKIX-encoded
// ECDSA P-256 public key. The public key MUST be pulled from the
// YubiHSM at enrollment time (yubihsm-shell get-public-key) so the
// device cannot impersonate a different signer later.
func (p *YubiHSMProvider) Enroll(approverID, objectID string, pubKeyDER []byte) error {
	pub, err := x509.ParsePKIXPublicKey(pubKeyDER)
	if err != nil {
		return fmt.Errorf("approval/yubihsm: parse public key: %w", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("approval/yubihsm: enrolled key is not ECDSA")
	}
	if ecPub.Curve != elliptic.P256() {
		return fmt.Errorf("approval/yubihsm: unsupported curve %s (want P-256)", ecPub.Curve.Params().Name)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.identity[approverID] = yubihsmEntry{
		ObjectID:  objectID,
		PubKey:    ecPub,
		PubKeyDER: pubKeyDER,
	}
	return nil
}

// EnrollPEM accepts a PEM-encoded public key (typical output of
// `yubihsm-shell get-public-key --out-format=PEM`).
func (p *YubiHSMProvider) EnrollPEM(approverID, objectID string, pemBytes []byte) error {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return errors.New("approval/yubihsm: invalid PEM")
	}
	return p.Enroll(approverID, objectID, block.Bytes)
}

func (p *YubiHSMProvider) GetPublicIdentity(_ context.Context, approverID string) (PublicIdentity, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	entry, ok := p.identity[approverID]
	if !ok {
		return PublicIdentity{}, fmt.Errorf("approval/yubihsm: approver %q not enrolled", approverID)
	}
	return PublicIdentity{
		ApproverID: approverID,
		Provider:   p.Provider(),
		PublicKey:  entry.PubKeyDER,
		Algorithm:  AlgorithmECDSAP256,
	}, nil
}

func (p *YubiHSMProvider) ApproveIntent(ctx context.Context, approverID string, intent CanonicalIntent) (ApprovalSignature, error) {
	p.mu.RLock()
	entry, ok := p.identity[approverID]
	p.mu.RUnlock()
	if !ok {
		return ApprovalSignature{}, fmt.Errorf("approval/yubihsm: approver %q not enrolled", approverID)
	}
	digest := intent.Digest()
	sig, err := p.signer.Sign(ctx, entry.ObjectID, intent.Bytes())
	if err != nil {
		return ApprovalSignature{}, fmt.Errorf("approval/yubihsm: sign: %w", err)
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

func (p *YubiHSMProvider) VerifyApproval(_ context.Context, intent CanonicalIntent, sig ApprovalSignature) (bool, error) {
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
