package api

import (
	"context"
	"encoding/json"
	"math/big"
	"sort"

	"github.com/hanzoai/orm"
	"github.com/luxfi/mpc/pkg/db"
)

type PolicyDecision struct {
	Action            string `json:"action"`
	Reason            string `json:"reason"`
	RequiredApprovers int    `json:"required_approvers"`
}

type PolicyConditions struct {
	MaxAmount        string   `json:"max_amount,omitempty"`
	AllowedChains    []string `json:"allowed_chains,omitempty"`
	AllowedAddresses []string `json:"allowed_addresses,omitempty"`
}

func evaluateTransaction(amount, chain, toAddress string, policies []*db.Policy) PolicyDecision {
	// Sort by priority descending
	sort.Slice(policies, func(i, j int) bool {
		return policies[i].Priority > policies[j].Priority
	})

	for _, policy := range policies {
		if !policy.Enabled {
			continue
		}

		var conditions PolicyConditions
		if err := json.Unmarshal(policy.Conditions, &conditions); err != nil {
			continue
		}

		if !matchesConditions(amount, chain, toAddress, conditions) {
			continue
		}

		switch policy.Action {
		case "deny":
			return PolicyDecision{Action: "deny", Reason: policy.Name}
		case "approve":
			return PolicyDecision{Action: "approve", Reason: policy.Name}
		case "require_approval":
			return PolicyDecision{
				Action:            "require_approval",
				Reason:            policy.Name,
				RequiredApprovers: policy.RequiredApprovers,
			}
		}
	}

	// Default: require approval with 1 admin
	return PolicyDecision{
		Action:            "require_approval",
		Reason:            "default policy",
		RequiredApprovers: 1,
	}
}

func matchesConditions(amount, chain, toAddress string, cond PolicyConditions) bool {
	if len(cond.AllowedChains) > 0 {
		found := false
		for _, c := range cond.AllowedChains {
			if c == chain {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if len(cond.AllowedAddresses) > 0 {
		found := false
		for _, a := range cond.AllowedAddresses {
			if a == toAddress {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if cond.MaxAmount != "" && amount != "" {
		max, ok1 := new(big.Float).SetString(cond.MaxAmount)
		val, ok2 := new(big.Float).SetString(amount)
		if ok1 && ok2 && val.Cmp(max) > 0 {
			return true
		}
	}

	return true
}

func (s *Server) loadPolicies(ctx context.Context, orgID string, vaultID *string) ([]*db.Policy, error) {
	q := orm.TypedQuery[db.Policy](s.db.ORM).
		Filter("orgId =", orgID).
		Filter("enabled =", true).
		Order("-priority")

	policies, err := q.GetAll(ctx)
	if err != nil {
		return nil, err
	}

	// Filter by vaultID if provided (include policies with no vaultID or matching vaultID)
	if vaultID != nil {
		var filtered []*db.Policy
		for _, p := range policies {
			if p.VaultID == nil || *p.VaultID == *vaultID {
				filtered = append(filtered, p)
			}
		}
		return filtered, nil
	}

	return policies, nil
}
