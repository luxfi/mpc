package approval

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// LocalDevProvider holds Ed25519 keypairs in process memory. Test only.
//
// Two safety gates:
//
//  1. NewProvider("local-dev", ...) refuses to start when MPC_ENV=production.
//  2. Even if the factory check were bypassed, this provider refuses to call
//     ApproveIntent unless MPC_ENV=dev OR MPC_LOCAL_APPROVAL=true.
//
// Both gates are checked at call time as well as construction time — a
// process that flips MPC_ENV to "production" between construction and use
// MUST stop signing approvals.
type LocalDevProvider struct {
	mu   sync.RWMutex
	keys map[string]ed25519.PrivateKey // approverID -> private key
}

// NewLocalDev constructs a LocalDevProvider. config is currently ignored
// (Ed25519 has no algorithm choice). Future config keys may carry seed
// material for deterministic test vectors.
func NewLocalDev(config map[string]string) (ApprovalProvider, error) {
	_ = config
	if err := localDevAllowed(); err != nil {
		return nil, err
	}
	return &LocalDevProvider{
		keys: make(map[string]ed25519.PrivateKey),
	}, nil
}

func (p *LocalDevProvider) Provider() string { return "local-dev" }

// localDevAllowed returns nil iff this build/process is permitted to use
// software approval keys. Production deployments must always return non-nil.
func localDevAllowed() error {
	env := strings.ToLower(os.Getenv("MPC_ENV"))
	if env == "production" || env == "prod" {
		return errors.New("approval/local-dev: forbidden in production (MPC_ENV=" + env + ")")
	}
	flag := strings.ToLower(os.Getenv("MPC_LOCAL_APPROVAL"))
	if env == "dev" || env == "development" || env == "test" || env == "testing" || flag == "true" || flag == "1" {
		return nil
	}
	// Default-deny: if MPC_ENV is unset, require explicit opt-in.
	return errors.New("approval/local-dev: requires MPC_ENV=dev or MPC_LOCAL_APPROVAL=true")
}

// getOrCreateKey returns the Ed25519 key for approverID, generating a new
// one on first use. Tests may pre-seed via Enroll.
func (p *LocalDevProvider) getOrCreateKey(approverID string) (ed25519.PrivateKey, error) {
	p.mu.RLock()
	if k, ok := p.keys[approverID]; ok {
		p.mu.RUnlock()
		return k, nil
	}
	p.mu.RUnlock()

	p.mu.Lock()
	defer p.mu.Unlock()
	if k, ok := p.keys[approverID]; ok {
		return k, nil
	}
	_, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("approval/local-dev: keygen failed for %q: %w", approverID, err)
	}
	p.keys[approverID] = sk
	return sk, nil
}

// Enroll injects a pre-existing Ed25519 keypair for the given approverID.
// Tests use this to set up deterministic identities before approvals.
func (p *LocalDevProvider) Enroll(approverID string, sk ed25519.PrivateKey) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.keys[approverID] = sk
}

func (p *LocalDevProvider) GetPublicIdentity(_ context.Context, approverID string) (PublicIdentity, error) {
	if err := localDevAllowed(); err != nil {
		return PublicIdentity{}, err
	}
	sk, err := p.getOrCreateKey(approverID)
	if err != nil {
		return PublicIdentity{}, err
	}
	pk := sk.Public().(ed25519.PublicKey)
	return PublicIdentity{
		ApproverID: approverID,
		Provider:   p.Provider(),
		PublicKey:  []byte(pk),
		Algorithm:  AlgorithmEd25519,
	}, nil
}

func (p *LocalDevProvider) ApproveIntent(_ context.Context, approverID string, intent CanonicalIntent) (ApprovalSignature, error) {
	if err := localDevAllowed(); err != nil {
		return ApprovalSignature{}, err
	}
	sk, err := p.getOrCreateKey(approverID)
	if err != nil {
		return ApprovalSignature{}, err
	}
	digest := intent.Digest()
	sig := ed25519.Sign(sk, digest[:])
	return ApprovalSignature{
		ApproverID:   approverID,
		Provider:     p.Provider(),
		IntentDigest: digest,
		Signature:    sig,
		Timestamp:    time.Now().UTC(),
		Algorithm:    AlgorithmEd25519,
	}, nil
}

func (p *LocalDevProvider) VerifyApproval(_ context.Context, intent CanonicalIntent, sig ApprovalSignature) (bool, error) {
	// Cross-provider integrity: sig.Provider must claim local-dev, otherwise
	// reject — keep verifiers honest about which keyset they're checking.
	if sig.Provider != p.Provider() {
		return false, nil
	}
	if sig.Algorithm != AlgorithmEd25519 {
		return false, nil
	}
	digest := intent.Digest()
	if digest != sig.IntentDigest {
		return false, nil
	}
	p.mu.RLock()
	sk, ok := p.keys[sig.ApproverID]
	p.mu.RUnlock()
	if !ok {
		return false, nil
	}
	pk := sk.Public().(ed25519.PublicKey)
	return ed25519.Verify(pk, digest[:], sig.Signature), nil
}
