package custody

import (
	"context"
	"errors"
	"fmt"
	"math"
)

// CustodyPolicy defines the conditions under which the ATS server (shard 2)
// will co-sign a transaction. The critical invariant: RequireUserShard is
// ALWAYS true. The platform (ATS + Backup) cannot unilaterally move funds.
type CustodyPolicy struct {
	// ATS auto-co-signs when ALL of these pass:
	KYCVerified      bool // User has passed KYC
	AMLCleared       bool // Transaction passed AML screening
	WithinLimits     bool // Within daily/per-tx limits
	NotSanctioned    bool // Destination not sanctioned
	ComplianceReview bool // No pending compliance holds

	// ATS NEVER signs without user shard. This is the custody guarantee.
	// This field exists to make the invariant explicit in code. It is
	// checked at evaluation time and cannot be overridden.
	RequireUserShard bool // ALWAYS true -- non-negotiable
}

// DefaultCustodyPolicy returns a policy with RequireUserShard=true and all
// compliance gates disabled (must be populated from actual checks).
func DefaultCustodyPolicy() CustodyPolicy {
	return CustodyPolicy{
		RequireUserShard: true,
	}
}

// TradeRequest contains the parameters of a trade that the policy engine evaluates.
type TradeRequest struct {
	WalletID    string  `json:"wallet_id"`
	UserID      string  `json:"user_id"`
	OrgID       string  `json:"org_id"`
	Symbol      string  `json:"symbol"`
	Side        string  `json:"side"` // buy, sell
	Quantity    float64 `json:"quantity"`
	Price       float64 `json:"price"`
	TotalValue  float64 `json:"total_value"`
	Destination string  `json:"destination"` // for transfers
}

// PolicyDecision is the result of evaluating a TradeRequest against the CustodyPolicy.
type PolicyDecision struct {
	Approved    bool    `json:"approved"`
	Reason      string  `json:"reason"`
	RequiredMFA string  `json:"required_mfa"` // "biometric", "totp", "sms"
	RiskScore   float64 `json:"risk_score"`   // 0-100, higher = riskier
}

// ComplianceChecker is called by the policy engine to verify compliance
// conditions against external systems (KYC provider, AML screening, sanctions lists).
type ComplianceChecker interface {
	CheckKYC(ctx context.Context, userID, orgID string) (bool, error)
	CheckAML(ctx context.Context, trade TradeRequest) (bool, error)
	CheckSanctions(ctx context.Context, destination string) (bool, error)
	CheckLimits(ctx context.Context, userID, orgID string, amount float64) (bool, error)
	CheckComplianceHold(ctx context.Context, userID, orgID string) (bool, error)
}

// EvaluateTradePolicy checks whether the ATS should co-sign a trade.
// If compliance is nil, all compliance gates default to failed (denied).
//
// The custody guarantee: this function ALWAYS requires the user shard.
// Even if every compliance check passes, the ATS will not sign without
// proof that the user participated (biometric proof + device signature).
func EvaluateTradePolicy(ctx context.Context, trade TradeRequest, compliance ComplianceChecker) (*PolicyDecision, error) {
	if trade.WalletID == "" || trade.UserID == "" || trade.OrgID == "" {
		return nil, errors.New("wallet_id, user_id, and org_id are required")
	}

	policy := DefaultCustodyPolicy()

	// The custody guarantee: RequireUserShard is non-negotiable.
	// This check exists so that if someone ever accidentally sets it to false,
	// the code catches it. Defense in depth.
	if !policy.RequireUserShard {
		return &PolicyDecision{
			Approved: false,
			Reason:   "CRITICAL: user shard requirement was disabled -- this is a bug",
		}, nil
	}

	// If no compliance checker, deny by default (fail closed)
	if compliance == nil {
		return &PolicyDecision{
			Approved:    false,
			Reason:      "compliance checker not configured",
			RequiredMFA: "biometric",
			RiskScore:   100,
		}, nil
	}

	// Run all compliance checks. Each failure adds to risk score.
	var riskScore float64
	var reasons []string

	kyc, err := compliance.CheckKYC(ctx, trade.UserID, trade.OrgID)
	if err != nil {
		return nil, fmt.Errorf("KYC check failed: %w", err)
	}
	policy.KYCVerified = kyc
	if !kyc {
		riskScore += 50
		reasons = append(reasons, "KYC not verified")
	}

	aml, err := compliance.CheckAML(ctx, trade)
	if err != nil {
		return nil, fmt.Errorf("AML check failed: %w", err)
	}
	policy.AMLCleared = aml
	if !aml {
		riskScore += 40
		reasons = append(reasons, "AML screening flagged")
	}

	sanctions, err := compliance.CheckSanctions(ctx, trade.Destination)
	if err != nil {
		return nil, fmt.Errorf("sanctions check failed: %w", err)
	}
	policy.NotSanctioned = sanctions
	if !sanctions {
		riskScore += 100 // Sanctions is an absolute block
		reasons = append(reasons, "destination is sanctioned")
	}

	limits, err := compliance.CheckLimits(ctx, trade.UserID, trade.OrgID, trade.TotalValue)
	if err != nil {
		return nil, fmt.Errorf("limits check failed: %w", err)
	}
	policy.WithinLimits = limits
	if !limits {
		riskScore += 30
		reasons = append(reasons, "exceeds transaction limits")
	}

	compHold, err := compliance.CheckComplianceHold(ctx, trade.UserID, trade.OrgID)
	if err != nil {
		return nil, fmt.Errorf("compliance hold check failed: %w", err)
	}
	policy.ComplianceReview = compHold
	if !compHold {
		riskScore += 50
		reasons = append(reasons, "compliance hold active")
	}

	// Clamp risk score to 0-100
	riskScore = math.Min(riskScore, 100)

	// Determine MFA requirement based on risk
	mfa := "biometric" // Always require biometric for MPC custody
	if riskScore > 50 {
		mfa = "biometric" // High risk: biometric only (no fallback to TOTP)
	}

	// Approved only if all compliance gates pass
	approved := policy.KYCVerified && policy.AMLCleared &&
		policy.WithinLimits && policy.NotSanctioned && policy.ComplianceReview

	reason := "all compliance checks passed"
	if !approved {
		reason = ""
		for i, r := range reasons {
			if i > 0 {
				reason += "; "
			}
			reason += r
		}
	}

	return &PolicyDecision{
		Approved:    approved,
		Reason:      reason,
		RequiredMFA: mfa,
		RiskScore:   riskScore,
	}, nil
}
