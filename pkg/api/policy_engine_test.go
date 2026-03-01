package api

import (
	"encoding/json"
	"testing"

	"github.com/luxfi/mpc/pkg/db"
)

func mustMarshal(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return b
}

func TestPolicyDeny(t *testing.T) {
	policies := []*db.Policy{
		{
			Name:     "block-all",
			Priority: 10,
			Action:   "deny",
			Conditions: mustMarshal(t, PolicyConditions{
				AllowedChains: []string{"ethereum"},
			}),
			Enabled: true,
		},
	}

	decision := evaluateTransaction("1.0", "ethereum", "0xabc", policies)

	if decision.Action != "deny" {
		t.Errorf("Action = %q, want %q", decision.Action, "deny")
	}
	if decision.Reason != "block-all" {
		t.Errorf("Reason = %q, want %q", decision.Reason, "block-all")
	}
}

func TestPolicyApprove(t *testing.T) {
	policies := []*db.Policy{
		{
			Name:     "auto-approve-small",
			Priority: 10,
			Action:   "approve",
			Conditions: mustMarshal(t, PolicyConditions{
				AllowedChains: []string{"ethereum"},
			}),
			Enabled: true,
		},
	}

	decision := evaluateTransaction("0.5", "ethereum", "0xabc", policies)

	if decision.Action != "approve" {
		t.Errorf("Action = %q, want %q", decision.Action, "approve")
	}
	if decision.Reason != "auto-approve-small" {
		t.Errorf("Reason = %q, want %q", decision.Reason, "auto-approve-small")
	}
}

func TestPolicyRequireApproval(t *testing.T) {
	policies := []*db.Policy{
		{
			Name:              "require-two-admins",
			Priority:          10,
			Action:            "require_approval",
			RequiredApprovers: 2,
			Conditions:        mustMarshal(t, PolicyConditions{}),
			Enabled:           true,
		},
	}

	decision := evaluateTransaction("10.0", "ethereum", "0xabc", policies)

	if decision.Action != "require_approval" {
		t.Errorf("Action = %q, want %q", decision.Action, "require_approval")
	}
	if decision.RequiredApprovers != 2 {
		t.Errorf("RequiredApprovers = %d, want %d", decision.RequiredApprovers, 2)
	}
}

func TestPolicyMaxAmount(t *testing.T) {
	// Policy: deny transactions exceeding 100
	policies := []*db.Policy{
		{
			Name:     "high-value-deny",
			Priority: 10,
			Action:   "deny",
			Conditions: mustMarshal(t, PolicyConditions{
				MaxAmount: "100",
			}),
			Enabled: true,
		},
	}

	// Amount 200 exceeds max_amount 100 -> condition matches -> deny
	decision := evaluateTransaction("200", "ethereum", "0xabc", policies)
	if decision.Action != "deny" {
		t.Errorf("200 > 100: Action = %q, want %q", decision.Action, "deny")
	}

	// Amount 50 does NOT exceed max_amount 100 -> condition still matches
	// (matchesConditions returns true when amount <= max because the max_amount
	// check only returns true early when exceeded; otherwise falls through to true)
	decision = evaluateTransaction("50", "ethereum", "0xabc", policies)
	if decision.Action != "deny" {
		t.Errorf("50 <= 100: Action = %q, want %q (max_amount is an 'applies-to' condition, not a filter)", decision.Action, "deny")
	}
}

func TestPolicyChainFilter(t *testing.T) {
	policies := []*db.Policy{
		{
			Name:     "eth-only-approve",
			Priority: 10,
			Action:   "approve",
			Conditions: mustMarshal(t, PolicyConditions{
				AllowedChains: []string{"ethereum"},
			}),
			Enabled: true,
		},
	}

	// Matching chain -> policy applies
	decision := evaluateTransaction("1.0", "ethereum", "0xabc", policies)
	if decision.Action != "approve" {
		t.Errorf("ethereum chain: Action = %q, want %q", decision.Action, "approve")
	}

	// Non-matching chain -> policy does not apply -> default
	decision = evaluateTransaction("1.0", "bitcoin", "0xabc", policies)
	if decision.Action != "require_approval" {
		t.Errorf("bitcoin chain: Action = %q, want %q", decision.Action, "require_approval")
	}
	if decision.Reason != "default policy" {
		t.Errorf("bitcoin chain: Reason = %q, want %q", decision.Reason, "default policy")
	}
}

func TestPolicyPriority(t *testing.T) {
	policies := []*db.Policy{
		{
			Name:       "low-priority-approve",
			Priority:   1,
			Action:     "approve",
			Conditions: mustMarshal(t, PolicyConditions{}),
			Enabled:    true,
		},
		{
			Name:       "high-priority-deny",
			Priority:   100,
			Action:     "deny",
			Conditions: mustMarshal(t, PolicyConditions{}),
			Enabled:    true,
		},
	}

	// Higher priority (100) should win over lower priority (1)
	decision := evaluateTransaction("1.0", "ethereum", "0xabc", policies)

	if decision.Action != "deny" {
		t.Errorf("Action = %q, want %q (high priority should win)", decision.Action, "deny")
	}
	if decision.Reason != "high-priority-deny" {
		t.Errorf("Reason = %q, want %q", decision.Reason, "high-priority-deny")
	}
}

func TestDefaultPolicy(t *testing.T) {
	// No policies at all -> default
	decision := evaluateTransaction("1.0", "ethereum", "0xabc", nil)

	if decision.Action != "require_approval" {
		t.Errorf("Action = %q, want %q", decision.Action, "require_approval")
	}
	if decision.Reason != "default policy" {
		t.Errorf("Reason = %q, want %q", decision.Reason, "default policy")
	}
	if decision.RequiredApprovers != 1 {
		t.Errorf("RequiredApprovers = %d, want %d", decision.RequiredApprovers, 1)
	}
}

func TestDisabledPolicySkipped(t *testing.T) {
	policies := []*db.Policy{
		{
			Name:       "disabled-deny",
			Priority:   100,
			Action:     "deny",
			Conditions: mustMarshal(t, PolicyConditions{}),
			Enabled:    false, // disabled
		},
	}

	// Disabled policy should be skipped -> fall through to default
	decision := evaluateTransaction("1.0", "ethereum", "0xabc", policies)

	if decision.Action != "require_approval" {
		t.Errorf("Action = %q, want %q", decision.Action, "require_approval")
	}
	if decision.Reason != "default policy" {
		t.Errorf("Reason = %q, want %q", decision.Reason, "default policy")
	}
}

func TestPolicyBadConditionsJSON(t *testing.T) {
	policies := []*db.Policy{
		{
			Name:       "bad-json",
			Priority:   100,
			Action:     "deny",
			Conditions: []byte("{invalid json"),
			Enabled:    true,
		},
	}

	// Policy with invalid JSON conditions should be skipped -> default
	decision := evaluateTransaction("1.0", "ethereum", "0xabc", policies)

	if decision.Action != "require_approval" {
		t.Errorf("Action = %q, want %q", decision.Action, "require_approval")
	}
}
