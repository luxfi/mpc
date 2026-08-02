// Velocity / daily / per-tx counters per wallet.
//
// One UsageStore covers every wallet in the process. Counters are kept in
// memory; restart loses them. The trade-off is intentional: the limits exist
// to slow down compromised paths, and restart is itself a security event.
// Cross-replica enforcement is the responsibility of the consensus layer
// (sibling LocalVerifier task), not this in-memory accounting.
//
// All amounts are math/big.Int — wei or smallest-unit. Strings sourced from
// TierPolicy fields ("inf", "0", "1000000000000000000") are parsed via
// parseLimit. "inf" means "no cap"; "0" means "no allowance".

package wallet

import (
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// limitInf is the sentinel parsed from TierPolicy strings of value "inf".
// Any value < limitInf passes the check; we represent it as nil to keep
// the comparison branch explicit.
type limit struct {
	value *big.Int // nil == unbounded
}

func (l limit) unbounded() bool { return l.value == nil }

// parseLimit parses a TierPolicy limit string ("inf", "0", "1000…") into
// a limit. Empty string is rejected — callers MUST set every field.
func parseLimit(s string) (limit, error) {
	if s == "" {
		return limit{}, errors.New("wallet: empty limit string")
	}
	if s == "inf" {
		return limit{value: nil}, nil
	}
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return limit{}, fmt.Errorf("wallet: invalid limit %q", s)
	}
	if v.Sign() < 0 {
		return limit{}, fmt.Errorf("wallet: negative limit %q", s)
	}
	return limit{value: v}, nil
}

// Errors stable for client matching.
var (
	ErrPerTxLimitExceeded = errors.New("per-transaction limit exceeded")
	ErrDailyLimitExceeded = errors.New("daily limit exceeded")
	ErrVelocityExceeded   = errors.New("velocity limit exceeded")
	ErrUsageWalletUnknown = errors.New("usage record not found")
)

// velocityHit is one previous successful charge in the velocity window.
type velocityHit struct {
	at     time.Time
	amount *big.Int
}

// counters holds the running totals for one wallet. Mutex is per-counter;
// the parent UsageStore takes its mu only for map mutation.
type counters struct {
	mu sync.Mutex

	// dailyDate is the UTC date this dailyAmount applies to. When the day
	// rolls over we reset.
	dailyDate   string
	dailyAmount *big.Int

	// velocity is a sliding window of successful charges. Pruned on every
	// access. Bounded by tier policy's VelocityWindow.
	velocity []velocityHit
}

func newCounters() *counters {
	return &counters{
		dailyAmount: new(big.Int),
		velocity:    make([]velocityHit, 0, 16),
	}
}

// UsageView is the snapshot returned to the API.
type UsageView struct {
	WalletID         string `json:"walletId"`
	DailyDate        string `json:"dailyDate"`
	DailyUsedWei     string `json:"dailyUsedWei"`
	DailyLimitWei    string `json:"dailyLimitWei"`
	DailyRemaining   string `json:"dailyRemainingWei"`
	VelocityWindow   string `json:"velocityWindow"`
	VelocityUsedWei  string `json:"velocityUsedWei"`
	VelocityLimitWei string `json:"velocityLimitWei"`
	PerTxLimitWei    string `json:"perTxLimitWei"`
	HitsInWindow     int    `json:"hitsInWindow"`
}

// UsageStore is the per-process velocity accounting layer.
type UsageStore struct {
	mu sync.Mutex
	m  map[string]*counters
}

// NewUsageStore constructs an empty store.
func NewUsageStore() *UsageStore {
	return &UsageStore{m: make(map[string]*counters)}
}

// for returns the counters for walletID, creating them on first access.
func (u *UsageStore) get(walletID string) *counters {
	u.mu.Lock()
	defer u.mu.Unlock()
	c, ok := u.m[walletID]
	if !ok {
		c = newCounters()
		u.m[walletID] = c
	}
	return c
}

// utcDate returns the YYYY-MM-DD string for t.UTC(). Used as the daily
// reset key — comparing dates instead of "midnight ago" avoids DST bugs.
func utcDate(t time.Time) string { return t.UTC().Format("2006-01-02") }

// CheckAndCharge returns nil if amount fits within the policy's per-tx,
// daily, and velocity limits AND records the charge. If any check fails,
// the counters are NOT mutated and the relevant Err* is returned.
//
// Atomicity: the counters mutex is held across read+modify, so a parallel
// caller cannot squeeze under the limit by racing.
func (u *UsageStore) CheckAndCharge(walletID string, amount *big.Int, policy TierPolicy, now time.Time) error {
	if amount == nil {
		return errors.New("wallet: nil amount")
	}
	if amount.Sign() < 0 {
		return errors.New("wallet: negative amount")
	}
	perTx, err := parseLimit(policy.PerTxLimitWei)
	if err != nil {
		return err
	}
	daily, err := parseLimit(policy.DailyLimitWei)
	if err != nil {
		return err
	}
	velLim, err := parseLimit(policy.VelocityLimitWei)
	if err != nil {
		return err
	}

	if !perTx.unbounded() && amount.Cmp(perTx.value) > 0 {
		return fmt.Errorf("%w: amount=%s limit=%s", ErrPerTxLimitExceeded, amount, perTx.value)
	}

	c := u.get(walletID)
	c.mu.Lock()
	defer c.mu.Unlock()

	// Daily: reset if UTC day changed.
	today := utcDate(now)
	if c.dailyDate != today {
		c.dailyDate = today
		c.dailyAmount = new(big.Int)
	}
	if !daily.unbounded() {
		next := new(big.Int).Add(c.dailyAmount, amount)
		if next.Cmp(daily.value) > 0 {
			return fmt.Errorf("%w: would-be=%s limit=%s", ErrDailyLimitExceeded, next, daily.value)
		}
	}

	// Velocity: prune everything outside the window.
	if policy.VelocityWindow > 0 {
		cutoff := now.Add(-policy.VelocityWindow)
		head := 0
		for ; head < len(c.velocity); head++ {
			if !c.velocity[head].at.Before(cutoff) {
				break
			}
		}
		c.velocity = c.velocity[head:]

		if !velLim.unbounded() {
			running := new(big.Int)
			for _, h := range c.velocity {
				running.Add(running, h.amount)
			}
			running.Add(running, amount)
			if running.Cmp(velLim.value) > 0 {
				return fmt.Errorf("%w: would-be=%s limit=%s window=%s",
					ErrVelocityExceeded, running, velLim.value, policy.VelocityWindow)
			}
		}
	}

	// Commit.
	c.dailyAmount = new(big.Int).Add(c.dailyAmount, amount)
	if policy.VelocityWindow > 0 {
		c.velocity = append(c.velocity, velocityHit{at: now, amount: new(big.Int).Set(amount)})
	}
	return nil
}

// View returns a snapshot of the wallet's counters relative to the given
// policy. Read-only; does not mutate. Time is now; a parallel daily reset
// is observed.
func (u *UsageStore) View(walletID string, policy TierPolicy, now time.Time) (UsageView, error) {
	daily, err := parseLimit(policy.DailyLimitWei)
	if err != nil {
		return UsageView{}, err
	}
	if _, err := parseLimit(policy.VelocityLimitWei); err != nil {
		return UsageView{}, err
	}

	c := u.get(walletID)
	c.mu.Lock()
	defer c.mu.Unlock()

	today := utcDate(now)
	if c.dailyDate != today {
		c.dailyDate = today
		c.dailyAmount = new(big.Int)
	}

	// Live prune for the view.
	if policy.VelocityWindow > 0 {
		cutoff := now.Add(-policy.VelocityWindow)
		head := 0
		for ; head < len(c.velocity); head++ {
			if !c.velocity[head].at.Before(cutoff) {
				break
			}
		}
		c.velocity = c.velocity[head:]
	}
	velUsed := new(big.Int)
	for _, h := range c.velocity {
		velUsed.Add(velUsed, h.amount)
	}

	dailyRemaining := "inf"
	if !daily.unbounded() {
		rem := new(big.Int).Sub(daily.value, c.dailyAmount)
		if rem.Sign() < 0 {
			rem.SetInt64(0)
		}
		dailyRemaining = rem.String()
	}

	return UsageView{
		WalletID:         walletID,
		DailyDate:        c.dailyDate,
		DailyUsedWei:     c.dailyAmount.String(),
		DailyLimitWei:    policy.DailyLimitWei,
		DailyRemaining:   dailyRemaining,
		VelocityWindow:   policy.VelocityWindow.String(),
		VelocityUsedWei:  velUsed.String(),
		VelocityLimitWei: policy.VelocityLimitWei,
		PerTxLimitWei:    policy.PerTxLimitWei,
		HitsInWindow:     len(c.velocity),
	}, nil
}

// Reset clears the counters for walletID. Used by tests.
func (u *UsageStore) Reset(walletID string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	delete(u.m, walletID)
}
