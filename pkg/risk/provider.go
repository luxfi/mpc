// Package risk provides transaction risk screening interfaces and
// implementations.
//
// Risk screening is a mandatory gate in the per-node verifier. A failure
// or rejection from the risk provider must abort signing.
package risk

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/luxfi/mpc/pkg/intent"
)

// Verdict is the outcome of a risk screening call.
type Verdict struct {
	Approved   bool      `json:"approved"`
	Reason     string    `json:"reason,omitempty"`
	RiskScore  float64   `json:"risk_score"` // 0..1, higher = riskier
	EvidenceID string    `json:"evidence_id"`
	Provider   string    `json:"provider"`
	Timestamp  time.Time `json:"timestamp"`
}

// Provider screens addresses and intents for risk. Every implementation
// must be safe for concurrent use.
type Provider interface {
	// ScreenAddress returns a verdict for a single address. Used at
	// wallet creation and for allowlist enforcement.
	ScreenAddress(ctx context.Context, chain, address string) (Verdict, error)

	// ScreenTransaction returns a verdict for a full intent. The provider
	// may consult the intent's amount, asset, chain, and destination.
	ScreenTransaction(ctx context.Context, ci *intent.CanonicalIntent) (Verdict, error)
}

// Errors a Provider may return.
var (
	ErrProviderUnavailable = errors.New("risk: provider unavailable")
	ErrNotImplemented      = errors.New("risk: provider not implemented")
)

// =============================================================================
// InternalAllowlistProvider — offline-first allowlist matcher.
// =============================================================================

// InternalAllowlistProvider implements Provider against an in-memory
// allowlist. Used as the default safety floor: if the destination is on
// the org's allowlist, the verdict is approve. If not, it is reject.
//
// This is the only provider that is guaranteed available — Chainalysis,
// TRM, and Elliptic require network calls and may fail open or closed
// depending on configuration.
type InternalAllowlistProvider struct {
	mu     sync.RWMutex
	allow  map[string]struct{} // key = chain || ":" || address (lowercased)
	denied map[string]struct{} // key = chain || ":" || address (lowercased)
}

// NewInternalAllowlistProvider returns a Provider with empty allow/deny
// lists. Populate via Allow/Deny before use.
func NewInternalAllowlistProvider() *InternalAllowlistProvider {
	return &InternalAllowlistProvider{
		allow:  make(map[string]struct{}),
		denied: make(map[string]struct{}),
	}
}

func (p *InternalAllowlistProvider) key(chain, addr string) string {
	return chain + ":" + lower(addr)
}

// Allow adds (chain, addr) to the allowlist.
func (p *InternalAllowlistProvider) Allow(chain, addr string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.allow[p.key(chain, addr)] = struct{}{}
}

// Deny adds (chain, addr) to the denylist. Denylist takes priority.
func (p *InternalAllowlistProvider) Deny(chain, addr string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.denied[p.key(chain, addr)] = struct{}{}
}

func (p *InternalAllowlistProvider) ScreenAddress(_ context.Context, chain, address string) (Verdict, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	k := p.key(chain, address)
	now := time.Now().UTC()
	if _, denied := p.denied[k]; denied {
		return Verdict{
			Approved:  false,
			Reason:    "address on internal denylist",
			RiskScore: 1.0,
			Provider:  "internal_allowlist",
			Timestamp: now,
		}, nil
	}
	if _, ok := p.allow[k]; ok {
		return Verdict{
			Approved:  true,
			RiskScore: 0,
			Provider:  "internal_allowlist",
			Timestamp: now,
		}, nil
	}
	return Verdict{
		Approved:  false,
		Reason:    "address not on internal allowlist",
		RiskScore: 1.0,
		Provider:  "internal_allowlist",
		Timestamp: now,
	}, nil
}

func (p *InternalAllowlistProvider) ScreenTransaction(ctx context.Context, ci *intent.CanonicalIntent) (Verdict, error) {
	return p.ScreenAddress(ctx, ci.Chain, ci.To)
}

// lower performs ASCII-lowercase. Addresses are case-insensitive on
// most chains; we normalize to avoid mismatches.
func lower(s string) string {
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

// =============================================================================
// CompositeProvider — AND/OR combinator over multiple providers.
// =============================================================================

// Mode controls how the CompositeProvider combines child verdicts.
type Mode int

const (
	// ModeAll requires every child provider to approve. The strictest
	// policy. Use this for highest-risk wallets (cold, validator).
	ModeAll Mode = iota
	// ModeAny approves if any child approves. Useful for fallthrough
	// when one provider is unreachable.
	ModeAny
)

// CompositeProvider chains multiple providers.
type CompositeProvider struct {
	mode      Mode
	providers []Provider
}

// NewCompositeProvider returns a Provider that delegates to each child.
func NewCompositeProvider(mode Mode, providers ...Provider) *CompositeProvider {
	return &CompositeProvider{mode: mode, providers: providers}
}

func (c *CompositeProvider) ScreenAddress(ctx context.Context, chain, address string) (Verdict, error) {
	return c.combine(func(p Provider) (Verdict, error) {
		return p.ScreenAddress(ctx, chain, address)
	})
}

func (c *CompositeProvider) ScreenTransaction(ctx context.Context, ci *intent.CanonicalIntent) (Verdict, error) {
	return c.combine(func(p Provider) (Verdict, error) {
		return p.ScreenTransaction(ctx, ci)
	})
}

func (c *CompositeProvider) combine(call func(Provider) (Verdict, error)) (Verdict, error) {
	if len(c.providers) == 0 {
		return Verdict{}, errors.New("risk: composite has no providers")
	}
	now := time.Now().UTC()
	switch c.mode {
	case ModeAll:
		// Every child must approve. Any error = reject.
		for _, p := range c.providers {
			v, err := call(p)
			if err != nil {
				return Verdict{
					Approved:  false,
					Reason:    "composite ModeAll: child error: " + err.Error(),
					Provider:  "composite",
					Timestamp: now,
				}, nil
			}
			if !v.Approved {
				v.Provider = "composite[" + v.Provider + "]"
				return v, nil
			}
		}
		return Verdict{Approved: true, Provider: "composite", Timestamp: now}, nil
	case ModeAny:
		var lastReason string
		for _, p := range c.providers {
			v, err := call(p)
			if err != nil {
				lastReason = err.Error()
				continue
			}
			if v.Approved {
				v.Provider = "composite[" + v.Provider + "]"
				return v, nil
			}
			lastReason = v.Reason
		}
		return Verdict{
			Approved:  false,
			Reason:    "composite ModeAny: no child approved (last: " + lastReason + ")",
			Provider:  "composite",
			Timestamp: now,
		}, nil
	default:
		return Verdict{}, errors.New("risk: unknown composite mode")
	}
}
