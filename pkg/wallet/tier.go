// Package wallet implements the 9-tier wallet architecture.
//
// Each wallet belongs to exactly one Tier. The Tier determines:
//   - MPC threshold (t-of-n)
//   - Required human approvals (small / large amount)
//   - Allowlist requirement
//   - Per-tx + daily + velocity-window limits
//   - Timelock duration
//   - Airgap requirement
//   - Domain-separation requirement (nodes spread across cloud/account/HSM)
//   - KYT (know-your-transaction) requirement
//   - Auto-approval permission
//
// One Tier per wallet. One TierPolicy per Tier. Policies are
// canonical — overrides happen via per-wallet PolicyID, never by mutating
// the StandardTierPolicies map.
package wallet

import "time"

// Tier identifies the operational tier of a wallet.
type Tier string

const (
	TierHot           Tier = "hot"
	TierWarm          Tier = "warm"
	TierCold          Tier = "cold"
	TierGas           Tier = "gas"
	TierBridge        Tier = "bridge"
	TierContractAdmin Tier = "contract_admin"
	TierValidator     Tier = "validator"
	TierQuarantine    Tier = "quarantine"
	TierDR            Tier = "disaster_recovery"
)

// AllTiers is the canonical, ordered list of every supported tier.
// Iteration order matches the executive table (hot first, DR last).
var AllTiers = []Tier{
	TierHot,
	TierWarm,
	TierCold,
	TierGas,
	TierBridge,
	TierContractAdmin,
	TierValidator,
	TierQuarantine,
	TierDR,
}

// IsValid reports whether t is one of the 9 supported tiers.
func (t Tier) IsValid() bool {
	for _, x := range AllTiers {
		if x == t {
			return true
		}
	}
	return false
}

// ThresholdSpec is a t-of-n MPC threshold tuple. Both fields are
// mandatory; T must be in [1,N], N must be >= 1.
type ThresholdSpec struct {
	T int `json:"t"`
	N int `json:"n"`
}

// TierPolicy is the canonical rule set for a single tier. Every field is
// declared up-front — no defaults, no "zero means unlimited". A policy with
// DailyLimitWei="0" means no operations allowed; "" is invalid.
type TierPolicy struct {
	Tier                      Tier          `json:"tier"`
	MPCThreshold              ThresholdSpec `json:"mpcThreshold"`
	HumanApprovalsMin         int           `json:"humanApprovalsMin"`
	HumanApprovalsLargeAmount string        `json:"humanApprovalsLargeAmount"` // base-10 wei threshold; "" = no large-amount escalation
	HumanApprovalsLarge       int           `json:"humanApprovalsLarge"`       // count when value >= HumanApprovalsLargeAmount
	AllowlistRequired         bool          `json:"allowlistRequired"`
	DailyLimitWei             string        `json:"dailyLimitWei"` // base-10 wei; "0" = none, "inf" = unbounded
	PerTxLimitWei             string        `json:"perTxLimitWei"`
	VelocityWindow            time.Duration `json:"velocityWindow"`
	VelocityLimitWei          string        `json:"velocityLimitWei"`
	TimelockDuration          time.Duration `json:"timelockDuration"`
	AirgappedRequired         bool          `json:"airgappedRequired"`
	NodeDomainSeparation      bool          `json:"nodeDomainSeparation"`
	KYTRequired               bool          `json:"kytRequired"`
	AllowAutoApproval         bool          `json:"allowAutoApproval"`
}

// standardPolicies is the immutable canonical map. Built once at init().
// Callers that want overrides must clone via the StandardTierPolicies()
// accessor and store their own copy.
var standardPolicies map[Tier]TierPolicy

func init() {
	standardPolicies = map[Tier]TierPolicy{
		TierHot: {
			Tier:                      TierHot,
			MPCThreshold:              ThresholdSpec{T: 2, N: 3},
			HumanApprovalsMin:         0,
			HumanApprovalsLargeAmount: "1000000000000000000", // 1 ETH
			HumanApprovalsLarge:       1,
			AllowlistRequired:         true,
			DailyLimitWei:             "100000000000000000000", // 100 ETH
			PerTxLimitWei:             "10000000000000000000",  // 10 ETH
			VelocityWindow:            time.Hour,
			VelocityLimitWei:          "20000000000000000000", // 20 ETH/hr
			TimelockDuration:          0,
			AirgappedRequired:         false,
			NodeDomainSeparation:      true,
			KYTRequired:               true,
			AllowAutoApproval:         true,
		},
		TierWarm: {
			Tier:                      TierWarm,
			MPCThreshold:              ThresholdSpec{T: 2, N: 3},
			HumanApprovalsMin:         1,
			HumanApprovalsLargeAmount: "10000000000000000000", // 10 ETH
			HumanApprovalsLarge:       2,
			AllowlistRequired:         false,
			DailyLimitWei:             "1000000000000000000000", // 1000 ETH
			PerTxLimitWei:             "100000000000000000000",  // 100 ETH
			VelocityWindow:            time.Hour,
			VelocityLimitWei:          "200000000000000000000", // 200 ETH/hr
			TimelockDuration:          0,
			AirgappedRequired:         false,
			NodeDomainSeparation:      true,
			KYTRequired:               true,
			AllowAutoApproval:         false,
		},
		TierCold: {
			Tier:                      TierCold,
			MPCThreshold:              ThresholdSpec{T: 3, N: 5},
			HumanApprovalsMin:         2,
			HumanApprovalsLargeAmount: "100000000000000000000", // 100 ETH
			HumanApprovalsLarge:       3,
			AllowlistRequired:         false,
			DailyLimitWei:             "inf",
			PerTxLimitWei:             "inf",
			VelocityWindow:            24 * time.Hour,
			VelocityLimitWei:          "inf",
			TimelockDuration:          24 * time.Hour,
			AirgappedRequired:         true,
			NodeDomainSeparation:      true,
			KYTRequired:               true,
			AllowAutoApproval:         false,
		},
		TierGas: {
			Tier:                      TierGas,
			MPCThreshold:              ThresholdSpec{T: 2, N: 3},
			HumanApprovalsMin:         0,
			HumanApprovalsLargeAmount: "100000000000000000", // 0.1 ETH — anything bigger than gas is suspect
			HumanApprovalsLarge:       1,
			AllowlistRequired:         true,
			DailyLimitWei:             "1000000000000000000", // 1 ETH/day
			PerTxLimitWei:             "100000000000000000",  // 0.1 ETH/tx
			VelocityWindow:            time.Hour,
			VelocityLimitWei:          "200000000000000000", // 0.2 ETH/hr
			TimelockDuration:          0,
			AirgappedRequired:         false,
			NodeDomainSeparation:      false,
			KYTRequired:               false,
			AllowAutoApproval:         true,
		},
		TierBridge: {
			Tier:                      TierBridge,
			MPCThreshold:              ThresholdSpec{T: 2, N: 3},
			HumanApprovalsMin:         0,
			HumanApprovalsLargeAmount: "10000000000000000000", // 10 ETH per bridge route
			HumanApprovalsLarge:       2,
			AllowlistRequired:         true,
			DailyLimitWei:             "500000000000000000000", // 500 ETH
			PerTxLimitWei:             "50000000000000000000",  // 50 ETH
			VelocityWindow:            time.Hour,
			VelocityLimitWei:          "100000000000000000000", // 100 ETH/hr
			TimelockDuration:          0,
			AirgappedRequired:         false,
			NodeDomainSeparation:      true,
			KYTRequired:               true,
			AllowAutoApproval:         true,
		},
		TierContractAdmin: {
			Tier:                      TierContractAdmin,
			MPCThreshold:              ThresholdSpec{T: 3, N: 5},
			HumanApprovalsMin:         3,
			HumanApprovalsLargeAmount: "0",
			HumanApprovalsLarge:       3,
			AllowlistRequired:         false,
			DailyLimitWei:             "inf",
			PerTxLimitWei:             "inf",
			VelocityWindow:            24 * time.Hour,
			VelocityLimitWei:          "inf",
			TimelockDuration:          48 * time.Hour,
			AirgappedRequired:         false,
			NodeDomainSeparation:      true,
			KYTRequired:               false,
			AllowAutoApproval:         false,
		},
		TierValidator: {
			Tier:                      TierValidator,
			MPCThreshold:              ThresholdSpec{T: 2, N: 3},
			HumanApprovalsMin:         0,
			HumanApprovalsLargeAmount: "0",
			HumanApprovalsLarge:       0,
			AllowlistRequired:         true,
			DailyLimitWei:             "inf",
			PerTxLimitWei:             "inf",
			VelocityWindow:            time.Hour,
			VelocityLimitWei:          "inf",
			TimelockDuration:          0,
			AirgappedRequired:         false,
			NodeDomainSeparation:      true,
			KYTRequired:               false,
			AllowAutoApproval:         true,
		},
		TierQuarantine: {
			Tier:                      TierQuarantine,
			MPCThreshold:              ThresholdSpec{T: 3, N: 5},
			HumanApprovalsMin:         3,
			HumanApprovalsLargeAmount: "0",
			HumanApprovalsLarge:       3,
			AllowlistRequired:         false,
			DailyLimitWei:             "0",
			PerTxLimitWei:             "0",
			VelocityWindow:            24 * time.Hour,
			VelocityLimitWei:          "0",
			TimelockDuration:          72 * time.Hour,
			AirgappedRequired:         false,
			NodeDomainSeparation:      true,
			KYTRequired:               true,
			AllowAutoApproval:         false,
		},
		TierDR: {
			Tier:                      TierDR,
			MPCThreshold:              ThresholdSpec{T: 3, N: 5},
			HumanApprovalsMin:         3,
			HumanApprovalsLargeAmount: "0",
			HumanApprovalsLarge:       3,
			AllowlistRequired:         false,
			DailyLimitWei:             "inf",
			PerTxLimitWei:             "inf",
			VelocityWindow:            24 * time.Hour,
			VelocityLimitWei:          "inf",
			TimelockDuration:          7 * 24 * time.Hour,
			AirgappedRequired:         true,
			NodeDomainSeparation:      true,
			KYTRequired:               false,
			AllowAutoApproval:         false,
		},
	}
}

// StandardTierPolicies returns a defensive copy of the canonical policy map.
// Mutating the returned map does not affect future calls.
func StandardTierPolicies() map[Tier]TierPolicy {
	out := make(map[Tier]TierPolicy, len(standardPolicies))
	for k, v := range standardPolicies {
		out[k] = v
	}
	return out
}

// PolicyFor returns the canonical policy for tier t. Panics if t is invalid;
// callers MUST validate via Tier.IsValid before calling.
func PolicyFor(t Tier) TierPolicy {
	p, ok := standardPolicies[t]
	if !ok {
		panic("wallet: invalid tier " + string(t))
	}
	return p
}
