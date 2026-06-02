// GasStation: keep configured operational wallets topped up to a target
// balance whenever they fall under a configured floor. The reserve wallet
// is the source of funds; per-asset rules carry the floor, the target, and
// a hard cap on how much may flow per Tick.
//
// One reserve wallet per (orgId, chain). Multiple operational wallets per
// rule. Topup amount is min(target - balance, capPerTick). Below floor:
// schedule a topup. Above floor: do nothing.

package automation

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"time"
)

// ChainClient reads balances and broadcasts pre-signed transactions. The
// concrete implementation in production wraps an EVM RPC node, a Bitcoin
// node, etc. The package is agnostic.
type ChainClient interface {
	// Balance returns the current balance of address on chain (smallest
	// unit — wei for EVM, satoshi for BTC).
	Balance(ctx context.Context, chain, address string) (*big.Int, error)

	// SendValue builds, signs (via the Signer), and broadcasts a value
	// transfer of amount from→to on chain. Returns the tx hash. The
	// implementation chooses fee strategy.
	SendValue(ctx context.Context, chain, from, to string, amount *big.Int) (string, error)
}

// GasRule is one operational-wallet top-up rule.
type GasRule struct {
	OrgID         string   `json:"orgId"`
	Chain         string   `json:"chain"`
	ReserveWallet string   `json:"reserveWallet"` // address — source of funds
	TargetWallets []string `json:"targetWallets"` // addresses to top up
	Floor         *big.Int `json:"floor"`         // top up when balance < floor
	Target        *big.Int `json:"target"`        // top up to this level
	CapPerTick    *big.Int `json:"capPerTick"`    // never send more than this in a single topup
	Enabled       bool     `json:"enabled"`
}

// Validate enforces the invariants every rule must satisfy.
func (r GasRule) Validate() error {
	if r.OrgID == "" || r.Chain == "" {
		return errors.New("automation: GasRule needs orgId and chain")
	}
	if r.ReserveWallet == "" {
		return errors.New("automation: GasRule needs reserveWallet")
	}
	if len(r.TargetWallets) == 0 {
		return errors.New("automation: GasRule needs at least one target wallet")
	}
	if r.Floor == nil || r.Target == nil || r.CapPerTick == nil {
		return errors.New("automation: GasRule needs floor, target, and capPerTick")
	}
	if r.Floor.Sign() < 0 || r.Target.Sign() < 0 || r.CapPerTick.Sign() <= 0 {
		return errors.New("automation: GasRule values must be non-negative (cap > 0)")
	}
	if r.Target.Cmp(r.Floor) <= 0 {
		return errors.New("automation: GasRule target must exceed floor")
	}
	return nil
}

// TopupReceipt records what a Tick did for one address.
type TopupReceipt struct {
	Address    string    `json:"address"`
	BeforeWei  string    `json:"beforeWei"`
	AfterWei   string    `json:"afterWei,omitempty"`
	SentWei    string    `json:"sentWei"`
	TxHash     string    `json:"txHash"`
	SkipReason string    `json:"skipReason,omitempty"`
	OccurredAt time.Time `json:"occurredAt"`
}

// TickResult is the per-rule outcome of one GasStation tick.
type TickResult struct {
	OrgID    string         `json:"orgId"`
	Chain    string         `json:"chain"`
	Receipts []TopupReceipt `json:"receipts"`
}

// GasStation runs gas-station rules on demand or on a ticker.
type GasStation struct {
	client ChainClient

	mu    sync.RWMutex
	rules map[string]GasRule // key = orgId|chain|reserveWallet
}

// NewGasStation constructs an empty station. Rules are added via Set; the
// caller drives the loop with Tick (or starts Run for a periodic loop).
func NewGasStation(client ChainClient) *GasStation {
	if client == nil {
		panic("automation: GasStation requires a non-nil ChainClient")
	}
	return &GasStation{client: client, rules: make(map[string]GasRule)}
}

func ruleKey(orgID, chain, reserve string) string {
	return orgID + "|" + chain + "|" + reserve
}

// Set adds or replaces a rule. Validates before storing.
func (g *GasStation) Set(rule GasRule) error {
	if err := rule.Validate(); err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.rules[ruleKey(rule.OrgID, rule.Chain, rule.ReserveWallet)] = rule
	return nil
}

// Delete removes a rule. Missing keys are a no-op.
func (g *GasStation) Delete(orgID, chain, reserve string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.rules, ruleKey(orgID, chain, reserve))
}

// List returns rules sorted by (orgId, chain, reserve).
func (g *GasStation) List() []GasRule {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]GasRule, 0, len(g.rules))
	for _, r := range g.rules {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].OrgID != out[j].OrgID {
			return out[i].OrgID < out[j].OrgID
		}
		if out[i].Chain != out[j].Chain {
			return out[i].Chain < out[j].Chain
		}
		return out[i].ReserveWallet < out[j].ReserveWallet
	})
	return out
}

// Tick walks every enabled rule and tops up each target wallet whose
// balance is under the rule's floor. Returns one TickResult per rule.
//
// Errors per-target are folded into the receipt's SkipReason — the
// function only returns an error for systemic problems (no rules,
// context cancellation).
func (g *GasStation) Tick(ctx context.Context) ([]TickResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rules := g.List()
	if len(rules) == 0 {
		return nil, errors.New("automation: no gas-station rules configured")
	}
	out := make([]TickResult, 0, len(rules))
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		res := TickResult{OrgID: rule.OrgID, Chain: rule.Chain}
		for _, addr := range rule.TargetWallets {
			receipt := TopupReceipt{Address: addr, OccurredAt: time.Now().UTC()}
			bal, err := g.client.Balance(ctx, rule.Chain, addr)
			if err != nil {
				receipt.SkipReason = "balance: " + err.Error()
				res.Receipts = append(res.Receipts, receipt)
				continue
			}
			receipt.BeforeWei = bal.String()
			if bal.Cmp(rule.Floor) >= 0 {
				receipt.SkipReason = "above floor"
				receipt.SentWei = "0"
				res.Receipts = append(res.Receipts, receipt)
				continue
			}
			delta := new(big.Int).Sub(rule.Target, bal)
			if delta.Cmp(rule.CapPerTick) > 0 {
				delta = new(big.Int).Set(rule.CapPerTick)
			}
			tx, err := g.client.SendValue(ctx, rule.Chain, rule.ReserveWallet, addr, delta)
			if err != nil {
				receipt.SkipReason = "send: " + err.Error()
				receipt.SentWei = "0"
				res.Receipts = append(res.Receipts, receipt)
				continue
			}
			receipt.SentWei = delta.String()
			receipt.TxHash = tx
			res.Receipts = append(res.Receipts, receipt)
		}
		out = append(out, res)
	}
	return out, nil
}

// Run drives Tick on the given interval until ctx is cancelled. Each tick
// dispatches to handler with the result slice. Errors from Tick (other
// than context cancellation) are passed to handler with results=nil.
//
// One tick at a time — the loop does not overlap. Operators set the
// interval based on the chain's block time; 60s is a safe default for
// EVM L1, 600s for Bitcoin.
func (g *GasStation) Run(ctx context.Context, every time.Duration, handler func([]TickResult, error)) {
	if every <= 0 {
		panic("automation: GasStation.Run interval must be positive")
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			results, err := g.Tick(ctx)
			if handler != nil {
				handler(results, err)
			}
		}
	}
}

// String pretty-prints a TickResult for log lines.
func (r TickResult) String() string {
	return fmt.Sprintf("org=%s chain=%s receipts=%d", r.OrgID, r.Chain, len(r.Receipts))
}
