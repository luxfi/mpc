// Registry — tiered wallet lookup + create + domain-separation enforcement.
//
// A Wallet here is the public-facing record: which Tier it belongs to,
// which MPC nodes hold its shares, and which cloud/HSM domains those nodes
// occupy. The actual key-share material lives in the underlying MPC nodes
// (not this package). The Registry's job is to ensure that the topology
// of node placement satisfies the Tier's `NodeDomainSeparation` invariant
// at create time and at every sign time.
//
// The "2-of-3 in same K8s = effectively 1-of-1" attack model is the
// reason this package exists at all.

package wallet

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// NodeBinding identifies one of the MPC nodes that holds a share of this
// wallet, plus the cloud/HSM/network domain it lives in. All five fields
// matter for domain separation. None may be empty.
type NodeBinding struct {
	NodeID        string `json:"nodeId"`
	CloudProvider string `json:"cloudProvider"` // aws | gcp | azure | colo | onprem
	Account       string `json:"account"`       // AWS account id, GCP project, etc.
	Region        string `json:"region"`
	HSMProvider   string `json:"hsmProvider"`   // aws-cloudhsm | gcp-cloud-hsm | azure-dedicated-hsm | thales-luna | yubihsm | zymbit | none
	HSMKeyID      string `json:"hsmKeyId,omitempty"`
}

// Wallet is the registry record for one tiered wallet.
type Wallet struct {
	ID          string            `json:"id"`
	OrgID       string            `json:"orgId"`
	Tier        Tier              `json:"tier"`
	Chain       string            `json:"chain"`       // CAIP-2: "eip155:1", "bip122:000000000019d6689c085ae165831e93", "solana:mainnet"
	Address     string            `json:"address"`
	GroupPubKey []byte            `json:"groupPubKey"`
	Threshold   ThresholdSpec     `json:"threshold"`
	Nodes       []NodeBinding     `json:"nodes"`
	PolicyID    string            `json:"policyId,omitempty"` // optional override of the tier-default policy
	CreatedAt   time.Time         `json:"createdAt"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// Registry is the read/write API for tiered wallets.
type Registry interface {
	Create(ctx context.Context, w Wallet) error
	Get(ctx context.Context, id string) (Wallet, error)
	List(ctx context.Context, orgID string, tier Tier) ([]Wallet, error)
	AssertDomainSeparation(ctx context.Context, w Wallet) error
}

// Validation errors. Stable strings — clients match on these.
var (
	ErrInvalidTier         = errors.New("invalid wallet tier")
	ErrThresholdMismatch   = errors.New("wallet threshold does not match tier policy")
	ErrInsufficientNodes   = errors.New("not enough nodes for tier threshold")
	ErrNodeFieldMissing    = errors.New("node binding has empty cloud/account/region/hsm")
	ErrDomainCollision     = errors.New("nodes share cloud+account or HSM provider")
	ErrInsufficientCloud   = errors.New("nodes do not span enough cloud providers for tier")
	ErrInsufficientHSM     = errors.New("nodes do not span enough HSM providers for tier")
	ErrWalletExists        = errors.New("wallet already exists")
	ErrWalletNotFound      = errors.New("wallet not found")
	ErrEmptyID             = errors.New("wallet id is required")
	ErrEmptyOrgID          = errors.New("wallet orgId is required")
	ErrEmptyAddress        = errors.New("wallet address is required")
	ErrEmptyChain          = errors.New("wallet chain is required")
)

// minDistinctCloudProviders is the spread requirement per tier. Cold and DR
// demand 3+ different clouds; bridge/contract-admin/quarantine demand 2+.
// Hot/warm need 2+ cloud OR 3+ accounts (handled in the spread check).
func minDistinctCloudProviders(t Tier) int {
	switch t {
	case TierCold, TierDR:
		return 3
	case TierBridge, TierContractAdmin, TierQuarantine:
		return 2
	case TierHot, TierWarm, TierValidator:
		return 2
	default:
		return 1
	}
}

// minDistinctHSMProviders is the per-tier requirement for distinct HSM
// vendors among the share-holding nodes. Cold + DR demand >=3 distinct HSM
// vendors so a single firmware bug can't compromise all shares.
func minDistinctHSMProviders(t Tier) int {
	switch t {
	case TierCold, TierDR:
		return 3
	case TierBridge, TierContractAdmin:
		return 2
	default:
		return 1
	}
}

// validateNodeBinding ensures every required field on a node is set.
func validateNodeBinding(n NodeBinding) error {
	if n.NodeID == "" || n.CloudProvider == "" || n.Account == "" ||
		n.Region == "" || n.HSMProvider == "" {
		return fmt.Errorf("%w: nodeId=%q cloud=%q account=%q region=%q hsm=%q",
			ErrNodeFieldMissing, n.NodeID, n.CloudProvider, n.Account, n.Region, n.HSMProvider)
	}
	return nil
}

// inMemoryRegistry is the canonical Registry implementation. It is safe
// for concurrent use. Persistence (if needed) is delegated to the API
// layer which writes through this registry into the ORM.
type inMemoryRegistry struct {
	mu      sync.RWMutex
	wallets map[string]Wallet
	usage   *UsageStore
}

// NewInMemoryRegistry returns a Registry that stores wallets in process
// memory. Suitable for tests and single-instance deployments. Multi-replica
// deployments wrap this with the API-layer ORM persistence (see
// pkg/api/handlers_wallet.go).
func NewInMemoryRegistry() Registry {
	return &inMemoryRegistry{
		wallets: make(map[string]Wallet),
		usage:   NewUsageStore(),
	}
}

// Create validates and stores the wallet. The Tier's policy threshold MUST
// match the wallet's declared threshold; this prevents a caller from
// declaring a "cold" wallet with a 1-of-1 threshold.
func (r *inMemoryRegistry) Create(ctx context.Context, w Wallet) error {
	if w.ID == "" {
		return ErrEmptyID
	}
	if w.OrgID == "" {
		return ErrEmptyOrgID
	}
	if w.Address == "" {
		return ErrEmptyAddress
	}
	if w.Chain == "" {
		return ErrEmptyChain
	}
	if !w.Tier.IsValid() {
		return fmt.Errorf("%w: %s", ErrInvalidTier, w.Tier)
	}
	policy := PolicyFor(w.Tier)
	if w.Threshold != policy.MPCThreshold {
		return fmt.Errorf("%w: tier=%s want %d-of-%d got %d-of-%d",
			ErrThresholdMismatch, w.Tier,
			policy.MPCThreshold.T, policy.MPCThreshold.N,
			w.Threshold.T, w.Threshold.N)
	}
	if len(w.Nodes) != w.Threshold.N {
		return fmt.Errorf("%w: tier=%s wants n=%d nodes, got %d",
			ErrInsufficientNodes, w.Tier, w.Threshold.N, len(w.Nodes))
	}
	for _, n := range w.Nodes {
		if err := validateNodeBinding(n); err != nil {
			return err
		}
	}
	if err := r.AssertDomainSeparation(ctx, w); err != nil {
		return err
	}

	if w.CreatedAt.IsZero() {
		w.CreatedAt = time.Now().UTC()
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.wallets[w.ID]; exists {
		return ErrWalletExists
	}
	r.wallets[w.ID] = w
	return nil
}

func (r *inMemoryRegistry) Get(ctx context.Context, id string) (Wallet, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	w, ok := r.wallets[id]
	if !ok {
		return Wallet{}, ErrWalletNotFound
	}
	return w, nil
}

func (r *inMemoryRegistry) List(ctx context.Context, orgID string, tier Tier) ([]Wallet, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Wallet, 0)
	for _, w := range r.wallets {
		if w.OrgID != orgID {
			continue
		}
		if tier != "" && w.Tier != tier {
			continue
		}
		out = append(out, w)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

// AssertDomainSeparation enforces, per the wallet's tier policy:
//
//  1. No two nodes share the same (CloudProvider, Account) tuple. This is
//     the "2-of-3 in the same AWS account" anti-pattern.
//  2. No two nodes share the same HSMProvider. A single HSM-vendor CVE
//     should never compromise the whole share set.
//  3. The set of node CloudProviders has size >= minDistinctCloudProviders(tier).
//  4. The set of node HSMProviders has size >= minDistinctHSMProviders(tier).
//
// For tiers where NodeDomainSeparation=false (gas-only), this is a no-op.
func (r *inMemoryRegistry) AssertDomainSeparation(ctx context.Context, w Wallet) error {
	policy := PolicyFor(w.Tier)
	if !policy.NodeDomainSeparation {
		return nil
	}

	type cloudKey struct{ provider, account string }
	seenCloudAccount := make(map[cloudKey]string)
	seenHSM := make(map[string]string)
	cloudProviders := make(map[string]struct{})
	hsmProviders := make(map[string]struct{})

	for _, n := range w.Nodes {
		ck := cloudKey{provider: n.CloudProvider, account: n.Account}
		if other, dup := seenCloudAccount[ck]; dup {
			return fmt.Errorf("%w: nodes %s and %s share %s/%s",
				ErrDomainCollision, other, n.NodeID, n.CloudProvider, n.Account)
		}
		seenCloudAccount[ck] = n.NodeID

		if other, dup := seenHSM[n.HSMProvider]; dup {
			return fmt.Errorf("%w: nodes %s and %s share HSM provider %s",
				ErrDomainCollision, other, n.NodeID, n.HSMProvider)
		}
		seenHSM[n.HSMProvider] = n.NodeID

		cloudProviders[n.CloudProvider] = struct{}{}
		hsmProviders[n.HSMProvider] = struct{}{}
	}

	if minC := minDistinctCloudProviders(w.Tier); len(cloudProviders) < minC {
		return fmt.Errorf("%w: tier=%s requires >=%d distinct cloud providers, got %d",
			ErrInsufficientCloud, w.Tier, minC, len(cloudProviders))
	}
	if minH := minDistinctHSMProviders(w.Tier); len(hsmProviders) < minH {
		return fmt.Errorf("%w: tier=%s requires >=%d distinct HSM providers, got %d",
			ErrInsufficientHSM, w.Tier, minH, len(hsmProviders))
	}
	return nil
}

// Usage exposes the velocity / daily counters for this registry's wallets.
// Returns nil if the registry was constructed without a UsageStore (which
// only happens through custom subclasses; the in-memory ctor always sets it).
func (r *inMemoryRegistry) Usage() *UsageStore { return r.usage }

// asInMemory casts a Registry to the canonical concrete type. Used by the
// API layer to access the UsageStore. Returns nil for non-canonical impls.
func asInMemory(r Registry) *inMemoryRegistry {
	if x, ok := r.(*inMemoryRegistry); ok {
		return x
	}
	return nil
}

// UsageOf returns the UsageStore behind r if r is the canonical impl,
// otherwise nil. The API layer uses this for the /v1/wallet/{id}/usage
// endpoint.
func UsageOf(r Registry) *UsageStore {
	if x := asInMemory(r); x != nil {
		return x.usage
	}
	return nil
}
