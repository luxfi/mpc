package approval

import (
	"context"
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/luxfi/crypto/mldsa"
)

// MLDSAProvider produces ML-DSA-65 (FIPS 204, NIST level 3) post-quantum
// approval signatures. Use for long-lived attestations where you need
// resistance to future quantum attacks (e.g. board-level approvals
// archived for 10+ years).
//
// We hold private keys in process memory, mirroring luxfi/hsm's MLDSASigner.
// For production HSM-backed PQ approvals, use AWS KMS (which now supports
// ML-DSA) and prefer the "aws-kms" provider with an ML-DSA configured key —
// or wait for hardware ML-DSA support in Zymbit/YubiHSM.
//
// Configuration: none. Mode is fixed at ML-DSA-65.
type MLDSAProvider struct {
	mu       sync.RWMutex
	identity map[string]mldsaEntry
}

type mldsaEntry struct {
	PrivKey  *mldsa.PrivateKey
	PubKey   *mldsa.PublicKey
	PubBytes []byte
}

func NewMLDSA(config map[string]string) (ApprovalProvider, error) {
	_ = config
	return &MLDSAProvider{
		identity: make(map[string]mldsaEntry),
	}, nil
}

func (p *MLDSAProvider) Provider() string { return "mldsa" }

// Enroll either generates a new ML-DSA-65 keypair for approverID (if
// privBytes is nil) or restores a known key from raw bytes.
func (p *MLDSAProvider) Enroll(approverID string, privBytes []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	var sk *mldsa.PrivateKey
	if len(privBytes) == 0 {
		generated, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
		if err != nil {
			return fmt.Errorf("approval/mldsa: keygen for %q: %w", approverID, err)
		}
		sk = generated
	} else {
		restored, err := mldsa.PrivateKeyFromBytes(mldsa.MLDSA65, privBytes)
		if err != nil {
			return fmt.Errorf("approval/mldsa: restore key for %q: %w", approverID, err)
		}
		sk = restored
	}
	p.identity[approverID] = mldsaEntry{
		PrivKey:  sk,
		PubKey:   sk.PublicKey,
		PubBytes: sk.PublicKey.Bytes(),
	}
	return nil
}

func (p *MLDSAProvider) GetPublicIdentity(_ context.Context, approverID string) (PublicIdentity, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	entry, ok := p.identity[approverID]
	if !ok {
		return PublicIdentity{}, fmt.Errorf("approval/mldsa: approver %q not enrolled", approverID)
	}
	return PublicIdentity{
		ApproverID: approverID,
		Provider:   p.Provider(),
		PublicKey:  entry.PubBytes,
		Algorithm:  AlgorithmMLDSA65,
	}, nil
}

func (p *MLDSAProvider) ApproveIntent(_ context.Context, approverID string, intent CanonicalIntent) (ApprovalSignature, error) {
	p.mu.RLock()
	entry, ok := p.identity[approverID]
	p.mu.RUnlock()
	if !ok {
		return ApprovalSignature{}, fmt.Errorf("approval/mldsa: approver %q not enrolled", approverID)
	}
	digest := intent.Digest()
	sig, err := entry.PrivKey.Sign(rand.Reader, intent.Bytes(), crypto.Hash(0))
	if err != nil {
		return ApprovalSignature{}, fmt.Errorf("approval/mldsa: sign: %w", err)
	}
	return ApprovalSignature{
		ApproverID:   approverID,
		Provider:     p.Provider(),
		IntentDigest: digest,
		Signature:    sig,
		Timestamp:    time.Now().UTC(),
		Algorithm:    AlgorithmMLDSA65,
	}, nil
}

func (p *MLDSAProvider) VerifyApproval(_ context.Context, intent CanonicalIntent, sig ApprovalSignature) (bool, error) {
	if sig.Provider != p.Provider() || sig.Algorithm != AlgorithmMLDSA65 {
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
	return entry.PubKey.VerifySignature(intent.Bytes(), sig.Signature), nil
}

// errMLDSAUnenrolled — kept for callers that want a clean sentinel for the
// "no such approver" case.
var errMLDSAUnenrolled = errors.New("approval/mldsa: approver not enrolled")
