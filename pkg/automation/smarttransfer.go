// SmartTransfer: route a (asset, amount, destination) to the cheapest
// configured provider. Each provider quotes a Cost (in a normalized
// numéraire — by convention, basis points of the transferred amount).
// The lowest-cost provider wins; ties are broken by provider name for
// determinism.
//
// Providers may be:
//   - direct on-chain transfers per chain (one provider per chain)
//   - bridge routes (Lux Bridge, third-party bridges)
//   - off-chain settlement (transfer agency)
//
// SmartTransfer does not execute the transfer itself — it returns the
// chosen route. The caller wires the route into the existing /v1/mpc/sign
// or /v1/mpc/wallets/sweep path.

package automation

import (
	"context"
	"errors"
	"math/big"
	"sort"
	"sync"
	"time"
)

// Quote is one provider's offer for moving (asset, amount) to dest.
//
// Cost is in basis points of amount (10000 = 100%). 5 bps = 0.05% — fine
// for small amounts; for large transfers the absolute fee dominates and
// providers should report it precisely.
type Quote struct {
	Provider string `json:"provider"`
	Route    string `json:"route"`     // human-readable route description
	Asset    string `json:"asset"`
	Amount   string `json:"amount"`    // base-10 in smallest unit
	Dest     string `json:"dest"`
	Chain    string `json:"chain"`     // destination chain (CAIP-2)
	FeeBps   int64  `json:"feeBps"`    // total cost in basis points
	FeeAbs   string `json:"feeAbs"`    // absolute fee in smallest unit (informational)
	ETA      time.Duration `json:"eta"` // estimated time to settle
	ValidUntil time.Time `json:"validUntil"`
	Provider_  Provider `json:"-"`     // back-reference for execution
}

// TransferRequest is what SmartTransfer.Quote consumes.
type TransferRequest struct {
	OrgID  string   `json:"orgId"`
	Asset  string   `json:"asset"`
	Amount *big.Int `json:"amount"` // smallest unit
	From   string   `json:"from"`
	To     string   `json:"to"`
	Chain  string   `json:"chain"` // optional preferred chain hint
}

// Validate checks the required fields.
func (r TransferRequest) Validate() error {
	if r.OrgID == "" {
		return errors.New("automation: SmartTransfer needs orgId")
	}
	if r.Asset == "" || r.From == "" || r.To == "" {
		return errors.New("automation: SmartTransfer needs asset, from, to")
	}
	if r.Amount == nil || r.Amount.Sign() <= 0 {
		return errors.New("automation: SmartTransfer needs positive amount")
	}
	return nil
}

// Provider is one route source. Implementations include OnChainProvider,
// BridgeProvider, and (in production) per-third-party-bridge providers.
type Provider interface {
	Name() string
	// QuoteTransfer returns a Quote, or an error if this provider cannot
	// service the request. Errors are folded into "provider unavailable"
	// — they do not abort the multi-provider quote loop.
	QuoteTransfer(ctx context.Context, req TransferRequest) (Quote, error)
}

// SmartTransfer aggregates Provider implementations and picks the cheapest.
type SmartTransfer struct {
	mu        sync.RWMutex
	providers map[string]Provider
}

// NewSmartTransfer builds an empty router. Register providers via Add.
func NewSmartTransfer() *SmartTransfer {
	return &SmartTransfer{providers: make(map[string]Provider)}
}

// Add registers a provider. Replaces any existing provider with the same
// Name() — providers are unique by name.
func (s *SmartTransfer) Add(p Provider) {
	if p == nil {
		panic("automation: SmartTransfer.Add(nil)")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.providers[p.Name()] = p
}

// Remove deregisters a provider. Missing names are a no-op.
func (s *SmartTransfer) Remove(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.providers, name)
}

// Providers returns the registered provider names, sorted.
func (s *SmartTransfer) Providers() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.providers))
	for n := range s.providers {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Quote asks every provider for a quote and returns the full slate sorted
// by ascending FeeBps (cheapest first). Providers that error are dropped.
//
// Returns at least one quote on success. A request with zero providers
// returns an error.
func (s *SmartTransfer) Quote(ctx context.Context, req TransferRequest) ([]Quote, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	provs := make([]Provider, 0, len(s.providers))
	for _, p := range s.providers {
		provs = append(provs, p)
	}
	s.mu.RUnlock()
	if len(provs) == 0 {
		return nil, errors.New("automation: SmartTransfer has no providers")
	}
	out := make([]Quote, 0, len(provs))
	for _, p := range provs {
		q, err := p.QuoteTransfer(ctx, req)
		if err != nil {
			continue
		}
		q.Provider = p.Name()
		q.Provider_ = p
		out = append(out, q)
	}
	if len(out) == 0 {
		return nil, errors.New("automation: no provider could service the request")
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].FeeBps != out[j].FeeBps {
			return out[i].FeeBps < out[j].FeeBps
		}
		// Tiebreaker — lexicographic provider name for determinism.
		return out[i].Provider < out[j].Provider
	})
	return out, nil
}

// Best returns the single cheapest quote. Convenience wrapper around Quote.
func (s *SmartTransfer) Best(ctx context.Context, req TransferRequest) (Quote, error) {
	quotes, err := s.Quote(ctx, req)
	if err != nil {
		return Quote{}, err
	}
	return quotes[0], nil
}

// =============================================================================
// OnChainProvider — direct same-chain transfer. Cost = configured base bps.
// =============================================================================

// OnChainProvider quotes a direct same-chain transfer. It does not execute;
// callers feed the resulting Quote into their existing sign + broadcast
// path.
type OnChainProvider struct {
	chain  string
	bps    int64
	eta    time.Duration
}

// NewOnChainProvider constructs a provider for one chain. bps is the
// effective fee for routing this provider on this chain (gas + slippage
// ballparked); operators tune via configuration.
func NewOnChainProvider(chain string, bps int64, eta time.Duration) *OnChainProvider {
	return &OnChainProvider{chain: chain, bps: bps, eta: eta}
}

func (p *OnChainProvider) Name() string { return "onchain:" + p.chain }

func (p *OnChainProvider) QuoteTransfer(_ context.Context, req TransferRequest) (Quote, error) {
	if req.Chain != "" && req.Chain != p.chain {
		return Quote{}, errors.New("onchain: wrong chain")
	}
	feeAbs := new(big.Int).Mul(req.Amount, big.NewInt(p.bps))
	feeAbs.Quo(feeAbs, big.NewInt(10000))
	return Quote{
		Provider:   p.Name(),
		Route:      p.chain + " direct",
		Asset:      req.Asset,
		Amount:     req.Amount.String(),
		Dest:       req.To,
		Chain:      p.chain,
		FeeBps:     p.bps,
		FeeAbs:     feeAbs.String(),
		ETA:        p.eta,
		ValidUntil: time.Now().Add(60 * time.Second),
	}, nil
}

// =============================================================================
// BridgeProvider — cross-chain via Lux Bridge or any explicit route.
// =============================================================================

// BridgeProvider quotes a cross-chain transfer. RouteName is used in the
// quote's Route field for operator visibility.
type BridgeProvider struct {
	name      string
	bps       int64
	srcChain  string
	dstChain  string
	eta       time.Duration
}

// NewBridgeProvider constructs a bridge provider. The (src,dst) pair is
// part of the configuration — one provider instance per route direction.
func NewBridgeProvider(name string, src, dst string, bps int64, eta time.Duration) *BridgeProvider {
	return &BridgeProvider{name: name, bps: bps, srcChain: src, dstChain: dst, eta: eta}
}

func (p *BridgeProvider) Name() string { return "bridge:" + p.name }

func (p *BridgeProvider) QuoteTransfer(_ context.Context, req TransferRequest) (Quote, error) {
	if req.Chain != "" && req.Chain != p.dstChain {
		return Quote{}, errors.New("bridge: wrong destination chain")
	}
	feeAbs := new(big.Int).Mul(req.Amount, big.NewInt(p.bps))
	feeAbs.Quo(feeAbs, big.NewInt(10000))
	return Quote{
		Provider:   p.Name(),
		Route:      p.srcChain + " → " + p.dstChain + " via " + p.name,
		Asset:      req.Asset,
		Amount:     req.Amount.String(),
		Dest:       req.To,
		Chain:      p.dstChain,
		FeeBps:     p.bps,
		FeeAbs:     feeAbs.String(),
		ETA:        p.eta,
		ValidUntil: time.Now().Add(60 * time.Second),
	}, nil
}
