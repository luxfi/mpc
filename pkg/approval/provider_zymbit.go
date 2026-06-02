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

// ZymbitProvider produces ECDSA-P256 approval signatures via Zymbit SCM
// (HSM6 / ZYMKEY) over the local REST API. Useful for on-prem, air-gapped,
// or edge approval ceremonies where the executive is co-located with the
// Zymbit device.
//
// Configuration:
//
//	api_addr — Zymbit REST API URL (default "http://localhost:6789").
//
// Approver enrollment maps approverID -> Zymbit slot ID + cached SPKI public
// key. Slots must be provisioned out-of-band on the Zymbit device.
type ZymbitProvider struct {
	signer luxhsm.Signer

	mu       sync.RWMutex
	identity map[string]zymbitEntry
}

type zymbitEntry struct {
	SlotID    string // Zymbit slot ("0", "1", ...)
	PubKey    *ecdsa.PublicKey
	PubKeyDER []byte
}

func NewZymbit(config map[string]string) (ApprovalProvider, error) {
	apiAddr := ""
	if config != nil {
		apiAddr = config["api_addr"]
	}
	signer, err := luxhsm.NewSigner("zymbit", map[string]string{"api_addr": apiAddr})
	if err != nil {
		return nil, fmt.Errorf("approval/zymbit: %w", err)
	}
	return &ZymbitProvider{
		signer:   signer,
		identity: make(map[string]zymbitEntry),
	}, nil
}

func (p *ZymbitProvider) Provider() string { return "zymbit" }

func (p *ZymbitProvider) Enroll(approverID, slotID string, pubKeyDER []byte) error {
	pub, err := x509.ParsePKIXPublicKey(pubKeyDER)
	if err != nil {
		return fmt.Errorf("approval/zymbit: parse public key: %w", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("approval/zymbit: enrolled key is not ECDSA")
	}
	if ecPub.Curve != elliptic.P256() {
		return fmt.Errorf("approval/zymbit: unsupported curve %s (want P-256)", ecPub.Curve.Params().Name)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.identity[approverID] = zymbitEntry{
		SlotID:    slotID,
		PubKey:    ecPub,
		PubKeyDER: pubKeyDER,
	}
	return nil
}

func (p *ZymbitProvider) EnrollPEM(approverID, slotID string, pemBytes []byte) error {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return errors.New("approval/zymbit: invalid PEM")
	}
	return p.Enroll(approverID, slotID, block.Bytes)
}

func (p *ZymbitProvider) GetPublicIdentity(_ context.Context, approverID string) (PublicIdentity, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	entry, ok := p.identity[approverID]
	if !ok {
		return PublicIdentity{}, fmt.Errorf("approval/zymbit: approver %q not enrolled", approverID)
	}
	return PublicIdentity{
		ApproverID: approverID,
		Provider:   p.Provider(),
		PublicKey:  entry.PubKeyDER,
		Algorithm:  AlgorithmECDSAP256,
	}, nil
}

func (p *ZymbitProvider) ApproveIntent(ctx context.Context, approverID string, intent CanonicalIntent) (ApprovalSignature, error) {
	p.mu.RLock()
	entry, ok := p.identity[approverID]
	p.mu.RUnlock()
	if !ok {
		return ApprovalSignature{}, fmt.Errorf("approval/zymbit: approver %q not enrolled", approverID)
	}
	digest := intent.Digest()
	sig, err := p.signer.Sign(ctx, entry.SlotID, intent.Bytes())
	if err != nil {
		return ApprovalSignature{}, fmt.Errorf("approval/zymbit: sign: %w", err)
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

func (p *ZymbitProvider) VerifyApproval(_ context.Context, intent CanonicalIntent, sig ApprovalSignature) (bool, error) {
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
