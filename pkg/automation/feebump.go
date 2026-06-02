// FeeBump: re-broadcast a stuck transaction at a higher effective fee.
//
// EVM (gas-priced chains): same nonce, raise gasPrice (or maxFeePerGas
// + maxPriorityFeePerGas for EIP-1559). Geth and most relays honor the
// higher-fee replacement when the bump exceeds 10%.
//
// Bitcoin (BIP-125 RBF): same input set, higher explicit fee, opt-in via
// nSequence < 0xfffffffe on every input. Replacement requires the new fee
// rate to exceed the old by at least the relay's incrementalRelayFee.
//
// FeeBump is a *plan* generator. It computes the new fee values and the
// delta evidence; the caller signs and broadcasts via the existing MPC
// path. We do not embed a chain client here — the same plan is used by
// the in-process scheduler and by external operators running tooling.

package automation

import (
	"errors"
	"math/big"
	"strings"
)

// EVMBumpInput is the existing fee state of a stuck EVM transaction.
type EVMBumpInput struct {
	GasPrice             *big.Int `json:"gasPrice,omitempty"`             // legacy
	MaxFeePerGas         *big.Int `json:"maxFeePerGas,omitempty"`         // 1559
	MaxPriorityFeePerGas *big.Int `json:"maxPriorityFeePerGas,omitempty"` // 1559
}

// EVMBumpPlan is what the caller signs and rebroadcasts with the same
// nonce. At least one of the legacy / 1559 sets is populated based on
// what the input carried.
type EVMBumpPlan struct {
	Mode                 string   `json:"mode"` // "legacy" | "eip1559"
	GasPrice             *big.Int `json:"gasPrice,omitempty"`
	MaxFeePerGas         *big.Int `json:"maxFeePerGas,omitempty"`
	MaxPriorityFeePerGas *big.Int `json:"maxPriorityFeePerGas,omitempty"`
	BumpFactorBps        int64    `json:"bumpFactorBps"` // applied bump in basis points
}

// EVMBump computes a fee-bumped plan from the current fee state.
//
// bumpBps applies to whichever fields are non-nil. Geth's default
// minimum is 1000 bps (10%); operators tune higher (e.g. 2500 = 25%) for
// volatile gas regimes. bumpBps must be > 0.
func EVMBump(in EVMBumpInput, bumpBps int64) (EVMBumpPlan, error) {
	if bumpBps <= 0 {
		return EVMBumpPlan{}, errors.New("automation: bumpBps must be positive")
	}
	plan := EVMBumpPlan{BumpFactorBps: bumpBps}

	// EIP-1559 path: both fields present.
	if in.MaxFeePerGas != nil && in.MaxPriorityFeePerGas != nil {
		plan.Mode = "eip1559"
		plan.MaxFeePerGas = applyBps(in.MaxFeePerGas, bumpBps)
		plan.MaxPriorityFeePerGas = applyBps(in.MaxPriorityFeePerGas, bumpBps)
		// Invariant: maxFeePerGas >= maxPriorityFeePerGas. EIP-1559
		// rejects otherwise. If the bump pushed priority above max,
		// raise max to match.
		if plan.MaxFeePerGas.Cmp(plan.MaxPriorityFeePerGas) < 0 {
			plan.MaxFeePerGas = new(big.Int).Set(plan.MaxPriorityFeePerGas)
		}
		return plan, nil
	}

	// Legacy path.
	if in.GasPrice != nil {
		plan.Mode = "legacy"
		plan.GasPrice = applyBps(in.GasPrice, bumpBps)
		return plan, nil
	}
	return EVMBumpPlan{}, errors.New("automation: EVMBump needs gasPrice or 1559 fee fields")
}

// BTCBumpInput is the existing fee state of a stuck Bitcoin transaction.
type BTCBumpInput struct {
	OldFeeSat       *big.Int `json:"oldFeeSat"`       // current absolute fee in satoshis
	VSize           int64    `json:"vSize"`           // virtual size (bytes); used to convert sat/vB
	MinFeeRateSatVB int64    `json:"minFeeRateSatVB"` // network minimum (mempool floor)
	IncrementSatVB  int64    `json:"incrementSatVB"`  // node's incrementalRelayFee, default 1
	Inputs          []string `json:"inputs"`          // outpoints — mirrored unchanged
	NSequenceMaxAll uint32   `json:"nSequenceMaxAll"` // every input's nSequence — must be <0xfffffffe for RBF
}

// BTCBumpPlan is the new fee + the inputs (unchanged) that the caller
// must sign into a replacement transaction.
type BTCBumpPlan struct {
	NewFeeSat       *big.Int `json:"newFeeSat"`
	NewFeeRateSatVB int64    `json:"newFeeRateSatVB"`
	Inputs          []string `json:"inputs"`
	BumpFactorBps   int64    `json:"bumpFactorBps"`
}

// BTCBump computes an RBF-compliant replacement fee.
//
// Rules:
//   - All inputs must already be RBF-flagged (nSequence < 0xfffffffe).
//   - New fee must exceed old fee by IncrementSatVB * vsize, at minimum.
//   - Resulting fee rate must be >= MinFeeRateSatVB.
//   - bumpBps applies on top — operators set this above the relay
//     increment to make the replacement attractive to miners.
func BTCBump(in BTCBumpInput, bumpBps int64) (BTCBumpPlan, error) {
	if bumpBps <= 0 {
		return BTCBumpPlan{}, errors.New("automation: bumpBps must be positive")
	}
	if in.OldFeeSat == nil || in.OldFeeSat.Sign() <= 0 {
		return BTCBumpPlan{}, errors.New("automation: BTCBump needs positive oldFeeSat")
	}
	if in.VSize <= 0 {
		return BTCBumpPlan{}, errors.New("automation: BTCBump needs positive vSize")
	}
	if in.NSequenceMaxAll >= 0xfffffffe {
		return BTCBumpPlan{}, errors.New("automation: BTCBump requires RBF-flagged inputs (nSequence < 0xfffffffe)")
	}
	inc := in.IncrementSatVB
	if inc <= 0 {
		inc = 1
	}

	// Floor: bump every input's required minimum (IncrementSatVB * vsize).
	floorBump := new(big.Int).Mul(big.NewInt(inc), big.NewInt(in.VSize))
	floorFee := new(big.Int).Add(in.OldFeeSat, floorBump)

	// Bump-factor candidate.
	bumpedFee := applyBps(in.OldFeeSat, bumpBps)
	newFee := bumpedFee
	if floorFee.Cmp(newFee) > 0 {
		newFee = floorFee
	}

	// Network minimum check.
	newFeeRate := new(big.Int).Quo(newFee, big.NewInt(in.VSize)).Int64()
	if newFeeRate < in.MinFeeRateSatVB {
		// Raise to the floor explicitly.
		newFeeRate = in.MinFeeRateSatVB
		newFee = new(big.Int).Mul(big.NewInt(newFeeRate), big.NewInt(in.VSize))
	}

	return BTCBumpPlan{
		NewFeeSat:       newFee,
		NewFeeRateSatVB: newFeeRate,
		Inputs:          append([]string(nil), in.Inputs...),
		BumpFactorBps:   bumpBps,
	}, nil
}

// applyBps returns base + base*bps/10000 — i.e. base scaled up by bps
// basis points. Used by both EVM and BTC paths.
func applyBps(base *big.Int, bps int64) *big.Int {
	delta := new(big.Int).Mul(base, big.NewInt(bps))
	delta.Quo(delta, big.NewInt(10000))
	out := new(big.Int).Add(base, delta)
	return out
}

// FormatPlan returns a one-line operator-friendly description of a plan.
// EVM: "legacy gasPrice 21->27 gwei (bump 2500bps)" or
// "eip1559 maxFee 30->37, prio 1->2 gwei (bump 2500bps)".
// BTC:  "rbf 1500->2200 sat (rate 6 sat/vB, bump 2500bps)".
func FormatPlan(plan interface{}) string {
	switch p := plan.(type) {
	case EVMBumpPlan:
		var b strings.Builder
		b.WriteString("evm-")
		b.WriteString(p.Mode)
		if p.GasPrice != nil {
			b.WriteString(" gasPrice=")
			b.WriteString(p.GasPrice.String())
		}
		if p.MaxFeePerGas != nil {
			b.WriteString(" maxFee=")
			b.WriteString(p.MaxFeePerGas.String())
		}
		if p.MaxPriorityFeePerGas != nil {
			b.WriteString(" priority=")
			b.WriteString(p.MaxPriorityFeePerGas.String())
		}
		return b.String()
	case BTCBumpPlan:
		var b strings.Builder
		b.WriteString("btc-rbf fee=")
		b.WriteString(p.NewFeeSat.String())
		return b.String()
	default:
		return "unknown plan"
	}
}
