package api

import (
	"context"
	"encoding/json"
	"math/big"
	"sort"

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

func evaluateTransaction(amount, chain, toAddress string, policies []db.Policy) PolicyDecision {
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
			// Amount exceeds max — this condition triggers
			return true
		}
	}

	return true
}

func (s *Server) loadPolicies(ctx context.Context, orgID string, vaultID *string) ([]db.Policy, error) {
	query := `SELECT id, org_id, vault_id, name, priority, action, conditions,
	          required_approvers, approver_roles, enabled, created_at
	          FROM policies WHERE org_id = $1 AND enabled = true`
	args := []interface{}{orgID}

	if vaultID != nil {
		query += " AND (vault_id IS NULL OR vault_id = $2)"
		args = append(args, *vaultID)
	}
	query += " ORDER BY priority DESC"

	rows, err := s.db.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []db.Policy
	for rows.Next() {
		var p db.Policy
		if err := rows.Scan(&p.ID, &p.OrgID, &p.VaultID, &p.Name, &p.Priority,
			&p.Action, &p.Conditions, &p.RequiredApprovers, &p.ApproverRoles,
			&p.Enabled, &p.CreatedAt); err != nil {
			continue
		}
		policies = append(policies, p)
	}
	return policies, nil
}
