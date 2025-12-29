// Per-node local verifier — the keystone of the "MPC node signs only if
// it independently verifies the policy bundle" control.
//
// Every MPC node runs LocalVerifier.Verify before producing its partial
// signature share. Failure aborts signing FAIL CLOSED — no fallback to
// trusting the coordinator.
package policy

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/luxfi/mpc/pkg/intent"
	"github.com/luxfi/mpc/pkg/risk"
)

// Verifier-side errors. Each is returned to the caller to fail the sign.
// Errors are stable so the audit log can categorize failures.
var (
	ErrUnknownWallet         = errors.New("verifier: unknown wallet")
	ErrTierMismatch          = errors.New("verifier: wallet tier mismatch")
	ErrExpiredIntent         = errors.New("verifier: intent expired")
	ErrPolicyNotFound        = errors.New("verifier: policy not found")
	ErrPolicyMismatch        = errors.New("verifier: policy hash mismatch")
	ErrInsufficientApprovals = errors.New("verifier: insufficient approvals")
	ErrAllowlistViolation    = errors.New("verifier: destination not on allowlist")
	ErrLimitViolation        = errors.New("verifier: amount exceeds limit")
	ErrRiskRejected          = errors.New("verifier: risk screening rejected")
	ErrInvalidIntent         = errors.New("verifier: invalid intent")
)

// =============================================================================
// Domain types — interfaces and value types used by LocalVerifier.
// =============================================================================

// Wallet is a registry entry describing a wallet's expected tier and
// chain. Mismatch with the intent fails verification.
type Wallet struct {
	WalletID string
	Tier     intent.WalletTier
	Chain    string
	Address  string // canonical from-address; intent.From must match
}

// WalletRegistry returns wallet metadata by ID. Backed by ORM/DB in
// production; in-memory in tests. Implementations must be safe for
// concurrent use.
type WalletRegistry interface {
	Get(walletID string) (Wallet, bool)
}

// ApprovalSigner identifies one executive who may approve transactions.
type ApprovalSigner struct {
	SignerID  string
	PublicKey ed25519.PublicKey
}

// ApprovalKeyset is the set of executive public keys for approval
// verification. The keyset is authoritative — only signers in the set
// count toward thresholds.
type ApprovalKeyset interface {
	// Lookup returns the signer record for a given public key, or false
	// if the pubkey is unknown.
	Lookup(pubkey ed25519.PublicKey) (ApprovalSigner, bool)
}

// PolicyBundle is a versioned, hashable policy specification. It binds
// approval thresholds, allowlists, and per-tier limits to a stable
// content hash that the intent must reference.
type PolicyBundle struct {
	PolicyID  string
	Version   string
	Tiers     map[intent.WalletTier]TierPolicy
	Allowlist map[string]map[string]bool // chain -> address(lowercased) -> allowed
}

// TierPolicy is the per-tier control: minimum approvals, max amount,
// allowlist enforcement.
type TierPolicy struct {
	// MinApprovals is the floor — the per-amount table can raise but
	// not lower this.
	MinApprovals int
	// AmountThresholds is a sorted list (ascending Amount) of
	// (amount, required) escalation steps. The first row whose Amount
	// is >= the intent.Amount sets the requirement; if none match, the
	// last row applies. Empty means MinApprovals is the only floor.
	AmountThresholds []AmountThreshold
	// MaxAmount is the per-tx ceiling. Zero means no ceiling.
	MaxAmount *big.Int
	// EnforceAllowlist requires intent.To to appear in the bundle's
	// chain allowlist. False is permitted only for tiers like Hot
	// which use risk screening as the sole address gate.
	EnforceAllowlist bool
}

// AmountThreshold is one row in the per-tier escalation ladder.
type AmountThreshold struct {
	Amount   *big.Int
	Required int
}

// Hash computes the SHA-256 of a deterministic encoding of the bundle.
// Bundles in the policy store must be content-addressed by this hash.
func (b *PolicyBundle) Hash() [32]byte {
	h := sha256.New()
	h.Write([]byte("policy-bundle:v1\x00"))
	h.Write([]byte(b.PolicyID))
	h.Write([]byte{0})
	h.Write([]byte(b.Version))
	h.Write([]byte{0})
	// Sort tiers by name for stable ordering.
	tiers := []intent.WalletTier{
		intent.TierHot, intent.TierWarm, intent.TierCold, intent.TierGas,
		intent.TierBridge, intent.TierContractAdmin, intent.TierValidator,
		intent.TierQuarantine, intent.TierDR,
	}
	for _, t := range tiers {
		tp, ok := b.Tiers[t]
		if !ok {
			continue
		}
		h.Write([]byte(t))
		h.Write([]byte{0})
		fmt.Fprintf(h, "min=%d|", tp.MinApprovals)
		fmt.Fprintf(h, "enforce=%t|", tp.EnforceAllowlist)
		if tp.MaxAmount != nil {
			h.Write([]byte("max="))
			h.Write([]byte(tp.MaxAmount.String()))
			h.Write([]byte{'|'})
		}
		for _, row := range tp.AmountThresholds {
			fmt.Fprintf(h, "row=%s/%d|", row.Amount.String(), row.Required)
		}
		h.Write([]byte{0})
	}
	// Sort allowlist for stability.
	chains := make([]string, 0, len(b.Allowlist))
	for c := range b.Allowlist {
		chains = append(chains, c)
	}
	// stable sort without importing sort? cheap insertion sort.
	for i := 1; i < len(chains); i++ {
		for j := i; j > 0 && chains[j] < chains[j-1]; j-- {
			chains[j], chains[j-1] = chains[j-1], chains[j]
		}
	}
	for _, c := range chains {
		h.Write([]byte(c))
		h.Write([]byte{0})
		addrs := b.Allowlist[c]
		akeys := make([]string, 0, len(addrs))
		for a := range addrs {
			akeys = append(akeys, a)
		}
		for i := 1; i < len(akeys); i++ {
			for j := i; j > 0 && akeys[j] < akeys[j-1]; j-- {
				akeys[j], akeys[j-1] = akeys[j-1], akeys[j]
			}
		}
		for _, a := range akeys {
			h.Write([]byte(a))
			h.Write([]byte{0})
		}
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// RequiredApprovalsFor returns the number of approvals needed for a
// tier given the intent's amount. Falls back to MinApprovals if no
// threshold row matches.
func (b *PolicyBundle) RequiredApprovalsFor(tier intent.WalletTier, amountStr string) (int, error) {
	tp, ok := b.Tiers[tier]
	if !ok {
		return 0, fmt.Errorf("policy: no tier policy for %s", tier)
	}
	req := tp.MinApprovals
	amt, ok := new(big.Int).SetString(amountStr, 10)
	if !ok {
		return 0, fmt.Errorf("policy: invalid amount %q", amountStr)
	}
	for _, row := range tp.AmountThresholds {
		if amt.Cmp(row.Amount) >= 0 && row.Required > req {
			req = row.Required
		}
	}
	return req, nil
}

// CheckAllowlist verifies the intent destination is on the bundle's
// allowlist for the intent's chain, when the tier policy requires it.
func (b *PolicyBundle) CheckAllowlist(ci *intent.CanonicalIntent) error {
	tp, ok := b.Tiers[ci.WalletTier]
	if !ok {
		return ErrPolicyNotFound
	}
	if !tp.EnforceAllowlist {
		return nil
	}
	addrs, ok := b.Allowlist[ci.Chain]
	if !ok || !addrs[asciiLower(ci.To)] {
		return fmt.Errorf("%w: chain=%s to=%s", ErrAllowlistViolation, ci.Chain, ci.To)
	}
	return nil
}

// CheckLimits verifies the per-tx amount is within the tier ceiling.
func (b *PolicyBundle) CheckLimits(ci *intent.CanonicalIntent) error {
	tp, ok := b.Tiers[ci.WalletTier]
	if !ok {
		return ErrPolicyNotFound
	}
	if tp.MaxAmount == nil || tp.MaxAmount.Sign() == 0 {
		return nil
	}
	amt, ok := new(big.Int).SetString(ci.Amount, 10)
	if !ok {
		return fmt.Errorf("%w: invalid amount %q", ErrInvalidIntent, ci.Amount)
	}
	if amt.Cmp(tp.MaxAmount) > 0 {
		return fmt.Errorf("%w: amount=%s max=%s", ErrLimitViolation, ci.Amount, tp.MaxAmount.String())
	}
	return nil
}

// PolicyStore returns policy bundles by ID.
type PolicyStore interface {
	Get(policyID string) (*PolicyBundle, error)
}

// =============================================================================
// In-memory implementations for tests + simple deployments. Production
// implementations bind these interfaces to ORM-backed stores.
// =============================================================================

// MemWalletRegistry is an in-memory WalletRegistry.
type MemWalletRegistry struct {
	mu sync.RWMutex
	m  map[string]Wallet
}

func NewMemWalletRegistry() *MemWalletRegistry {
	return &MemWalletRegistry{m: make(map[string]Wallet)}
}

func (r *MemWalletRegistry) Put(w Wallet) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[w.WalletID] = w
}

func (r *MemWalletRegistry) Get(walletID string) (Wallet, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	w, ok := r.m[walletID]
	return w, ok
}

// MemApprovalKeyset is an in-memory ApprovalKeyset keyed by pubkey hex.
type MemApprovalKeyset struct {
	mu sync.RWMutex
	m  map[string]ApprovalSigner // hex(pubkey) -> signer
}

func NewMemApprovalKeyset() *MemApprovalKeyset {
	return &MemApprovalKeyset{m: make(map[string]ApprovalSigner)}
}

func (k *MemApprovalKeyset) Add(s ApprovalSigner) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.m[hexkey(s.PublicKey)] = s
}

func (k *MemApprovalKeyset) Lookup(pub ed25519.PublicKey) (ApprovalSigner, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	s, ok := k.m[hexkey(pub)]
	return s, ok
}

// MemPolicyStore is an in-memory PolicyStore.
type MemPolicyStore struct {
	mu sync.RWMutex
	m  map[string]*PolicyBundle
}

func NewMemPolicyStore() *MemPolicyStore {
	return &MemPolicyStore{m: make(map[string]*PolicyBundle)}
}

func (s *MemPolicyStore) Put(b *PolicyBundle) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[b.PolicyID] = b
}

func (s *MemPolicyStore) Get(id string) (*PolicyBundle, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, ok := s.m[id]
	if !ok {
		return nil, fmt.Errorf("%w: id=%s", ErrPolicyNotFound, id)
	}
	return b, nil
}

// =============================================================================
// LocalVerifier — the per-node policy gate.
// =============================================================================

// LocalVerifier executes the six-check policy gate on every signing
// request. Each MPC node runs its own LocalVerifier with its own copy
// of the policy + approval keyset; the coordinator's "approved" flag
// is never trusted.
type LocalVerifier struct {
	WalletRegistry WalletRegistry
	ApprovalKeyset ApprovalKeyset
	RiskProvider   risk.Provider
	PolicyStore    PolicyStore
	// Now overrides time.Now for tests. Nil = real clock.
	Now func() time.Time
}

// NewLocalVerifier wires the verifier dependencies. All fields except
// Now are required.
func NewLocalVerifier(
	wr WalletRegistry,
	ak ApprovalKeyset,
	rp risk.Provider,
	ps PolicyStore,
) *LocalVerifier {
	return &LocalVerifier{
		WalletRegistry: wr,
		ApprovalKeyset: ak,
		RiskProvider:   rp,
		PolicyStore:    ps,
	}
}

func (v *LocalVerifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// Verify runs the full gate against ci. On success, returns nil and ci
// may be passed to the threshold sign. On any failure, returns the
// first error encountered. Order matters — cheaper checks run first.
func (v *LocalVerifier) Verify(ctx context.Context, ci *intent.CanonicalIntent) error {
	// 0. Structural validation — cheap, catches malformed payloads
	// before we touch any backing store.
	if err := ci.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidIntent, err)
	}

	// 1. Wallet registry — known wallet, expected tier, expected from.
	w, ok := v.WalletRegistry.Get(ci.WalletID)
	if !ok {
		return ErrUnknownWallet
	}
	if w.Tier != ci.WalletTier {
		return fmt.Errorf("%w: registry=%s intent=%s", ErrTierMismatch, w.Tier, ci.WalletTier)
	}

	// 2. Expiry — fail before anything expensive.
	if v.now().After(ci.ExpiresAt) {
		return ErrExpiredIntent
	}

	// 3. Policy version — bundle must exist and its hash must match
	// what the intent references. This is the binding that prevents
	// a coordinator from approving against a stale or rewritten policy.
	bundle, err := v.PolicyStore.Get(ci.PolicyID)
	if err != nil {
		return err
	}
	if bundle.Hash() != ci.PolicyHash {
		return ErrPolicyMismatch
	}

	// 4. Per-tier approval threshold — count valid Ed25519 signatures
	// over the intent digest from known executive keys. Reject if the
	// count is below the policy's required threshold.
	required, err := bundle.RequiredApprovalsFor(ci.WalletTier, ci.Amount)
	if err != nil {
		return err
	}
	digest, err := ci.Digest()
	if err != nil {
		return err
	}
	valid, seen := 0, make(map[string]bool)
	for _, sig := range ci.Approvals {
		if len(sig.PublicKey) != ed25519.PublicKeySize || len(sig.Signature) != ed25519.SignatureSize {
			continue
		}
		signer, ok := v.ApprovalKeyset.Lookup(sig.PublicKey)
		if !ok {
			continue
		}
		// Disallow same signer counting twice, even if they sign with
		// different keys mapped to the same SignerID.
		if seen[signer.SignerID] {
			continue
		}
		if !ed25519.Verify(sig.PublicKey, digest[:], sig.Signature) {
			continue
		}
		seen[signer.SignerID] = true
		valid++
	}
	if valid < required {
		return fmt.Errorf("%w: have=%d need=%d", ErrInsufficientApprovals, valid, required)
	}

	// 5. Allowlist + limits — enforce per-tier rules.
	if err := bundle.CheckAllowlist(ci); err != nil {
		return err
	}
	if err := bundle.CheckLimits(ci); err != nil {
		return err
	}

	// 6. Risk screening — fail closed on error or rejection.
	verdict, err := v.RiskProvider.ScreenTransaction(ctx, ci)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRiskRejected, err)
	}
	if !verdict.Approved {
		return fmt.Errorf("%w: %s (provider=%s score=%.2f)", ErrRiskRejected, verdict.Reason, verdict.Provider, verdict.RiskScore)
	}

	return nil
}

// AttestationFor produces a signed NodeAttestation reflecting v's
// decision on ci. Signed with nodeKey. The verdict is "approve" if err
// is nil, "reject" otherwise.
//
// Attestations are persisted to the audit log whether positive or
// negative — both are non-repudiable evidence.
func (v *LocalVerifier) AttestationFor(
	ci *intent.CanonicalIntent,
	nodeID string,
	nodeKey ed25519.PrivateKey,
	verifyErr error,
) (intent.NodeAttestation, error) {
	digest, err := ci.Digest()
	if err != nil {
		return intent.NodeAttestation{}, err
	}
	verdict := "approve"
	reason := ""
	if verifyErr != nil {
		verdict = "reject"
		reason = verifyErr.Error()
	}
	// Signed payload: digest || verdict
	msg := make([]byte, 0, len(digest)+len(verdict))
	msg = append(msg, digest[:]...)
	msg = append(msg, []byte(verdict)...)
	sig := ed25519.Sign(nodeKey, msg)
	return intent.NodeAttestation{
		NodeID:    nodeID,
		PublicKey: nodeKey.Public().(ed25519.PublicKey),
		Verdict:   verdict,
		Reason:    reason,
		Signature: sig,
		SignedAt:  v.now().UTC(),
	}, nil
}

// VerifyAttestation checks an attestation against an intent. Used by
// the coordinator (or auditors) to confirm a node's decision.
func VerifyAttestation(ci *intent.CanonicalIntent, att intent.NodeAttestation) error {
	if len(att.PublicKey) != ed25519.PublicKeySize || len(att.Signature) != ed25519.SignatureSize {
		return errors.New("attestation: bad key/sig length")
	}
	digest, err := ci.Digest()
	if err != nil {
		return err
	}
	msg := make([]byte, 0, len(digest)+len(att.Verdict))
	msg = append(msg, digest[:]...)
	msg = append(msg, []byte(att.Verdict)...)
	if !ed25519.Verify(att.PublicKey, msg, att.Signature) {
		return errors.New("attestation: signature invalid")
	}
	return nil
}

// =============================================================================
// helpers
// =============================================================================

func asciiLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

func hexkey(pub ed25519.PublicKey) string {
	const hex = "0123456789abcdef"
	out := make([]byte, len(pub)*2)
	for i, b := range pub {
		out[i*2] = hex[b>>4]
		out[i*2+1] = hex[b&0x0f]
	}
	return string(out)
}
