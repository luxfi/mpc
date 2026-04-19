// R6 — treasury tier `requireRegulator: true` invariant.
//
// When a tier is configured with requireRegulator=true, a numeric quorum
// that does NOT include the regulator signer must NOT finalize the op.
// The handler must return 409 and revert the op to pending_approval so
// the regulator's approval can still land.
//
// Spec: ~/work/liquidity/openapi/mpc.yaml → TreasuryTier.requireRegulator.
// Handler: handlers_treasury.go handleTreasurySign regulator invariant.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/luxfi/mpc/pkg/db"
)

// seedRegulatorTreasury installs a treasury wallet + operation ready for the
// FINAL approver to land. ApprovedBy is pre-populated with `threshold-1`
// non-regulator signers so the next approval call tips numeric quorum.
// Returns (walletID, operationID, non-regulator signer-to-use-for-final-vote).
func seedRegulatorTreasury(
	t *testing.T, s *Server, orgID string, threshold int, requireRegulator bool,
) (string, string, string) {
	t.Helper()

	tw := orm.New[db.TreasuryWallet](s.db.ORM)
	tw.OrgID = orgID
	tw.Name = "regulator-treasury"
	tw.WalletID = "wallet-reg-1"
	tw.Chain = "evm"
	tw.Signers = []db.TreasurySigner{
		{Role: db.TreasurySignerCompliance, KeyRef: "u-compliance"},
		{Role: db.TreasurySignerTreasurer, KeyRef: "u-treasurer"},
		{Role: db.TreasurySignerPlatformHSM, KeyRef: expectedPlatformHSMKeyRef(orgID)},
		{Role: db.TreasurySignerBackupHSM, KeyRef: "u-backup-hsm"},
		{Role: db.TreasurySignerRegulator, KeyRef: "u-regulator"},
	}
	tw.Tiers = []db.TreasuryTier{
		{MaxValue: "inf", Threshold: threshold, RequireRegulator: requireRegulator},
	}
	tw.RegulatorShard = true
	tw.Status = "active"
	if err := tw.Create(); err != nil {
		t.Fatalf("seed treasury wallet: %v", err)
	}

	pol := orm.New[db.Policy](s.db.ORM)
	pol.OrgID = orgID
	pol.Kind = "treasury"
	pol.Name = "regulator-treasury-policy"
	pol.Priority = 1000
	pol.Action = "require_approval"
	pol.RequiredApprovers = threshold
	pol.Enabled = true
	pol.Conditions = []byte(`{}`)
	if err := pol.Create(); err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	tx := orm.New[db.Transaction](s.db.ORM)
	tx.OrgID = orgID
	wid := tw.WalletID
	tx.WalletID = &wid
	tx.TxType = "treasury_sign"
	tx.Chain = "evm"
	tx.Status = "pending_approval"
	initiator := "u-initiator"
	tx.InitiatedBy = &initiator
	// Seed N-1 approvals from NON-regulator signers. The caller of this
	// helper issues the threshold-tipping approval below; that call will
	// tip numeric quorum without including the regulator.
	tx.ApprovedBy = []string{"u-compliance", "u-treasurer"}
	// If threshold > 3 we'd need to seed more; the tests below use threshold=3
	// so ApprovedBy=2 is exactly threshold-1.
	if threshold != 3 {
		t.Fatalf("helper wired for threshold=3, got %d", threshold)
	}
	if err := tx.Create(); err != nil {
		t.Fatalf("seed operation: %v", err)
	}
	// The final vote will come from u-backup-hsm — a non-regulator signer.
	return wid, tx.Id(), "u-backup-hsm"
}

// postTreasurySign calls handleTreasurySign with the given principal and
// returns the HTTP response recorder.
func postTreasurySign(t *testing.T, s *Server, orgID, userID, opID string) *httptest.ResponseRecorder {
	t.Helper()
	body := map[string]string{"operationId": opID}
	buf := &bytes.Buffer{}
	_ = json.NewEncoder(buf).Encode(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/mpc/treasury/sign", buf)
	req.Header.Set("Content-Type", "application/json")
	reqCtx := context.WithValue(req.Context(), ctxOrgID, orgID)
	reqCtx = context.WithValue(reqCtx, ctxUserID, userID)
	reqCtx = context.WithValue(reqCtx, ctxRole, "signer")
	req = req.WithContext(reqCtx)
	rec := httptest.NewRecorder()
	s.handleTreasurySign(rec, req)
	return rec
}

// TestR6_RequireRegulator_QuorumWithoutRegulator_Rejected — the critical
// invariant. Tier has requireRegulator=true. The N-th approver (not the
// regulator) tips numeric quorum. Handler must return 409 and the op must
// revert to pending_approval so the regulator can still approve.
func TestR6_RequireRegulator_QuorumWithoutRegulator_Rejected(t *testing.T) {
	s := newTreasuryServer(t)
	orgID := "org-A"

	_, opID, finalSigner := seedRegulatorTreasury(t, s, orgID, 3, true)

	rec := postTreasurySign(t, s, orgID, finalSigner, opID)
	if rec.Code != http.StatusConflict {
		t.Fatalf("requireRegulator=true but quorum lacked regulator: expected 409, got %d body=%s",
			rec.Code, rec.Body.String())
	}

	// The op must be back in pending_approval (revertQuorumWithoutRegulator).
	fresh, err := orm.Get[db.Transaction](s.db.ORM, opID)
	if err != nil {
		t.Fatalf("reload op: %v", err)
	}
	if fresh.Status != "pending_approval" {
		t.Fatalf("op status after regulator-missing quorum = %q, want pending_approval", fresh.Status)
	}
	// ApprovedBy must STILL contain the N-th approver so that when the
	// regulator later approves, quorum is met correctly.
	foundFinal := false
	for _, id := range fresh.ApprovedBy {
		if id == finalSigner {
			foundFinal = true
		}
	}
	if !foundFinal {
		t.Fatalf("final signer %q missing from ApprovedBy %v", finalSigner, fresh.ApprovedBy)
	}
}

// TestR6_RequireRegulator_QuorumWithRegulator_Finalizes — the happy path.
// When the regulator is one of the approvers reaching quorum, finalization
// succeeds and the handler returns 200.
func TestR6_RequireRegulator_QuorumWithRegulator_Finalizes(t *testing.T) {
	s := newTreasuryServer(t)
	orgID := "org-A"

	_, opID, _ := seedRegulatorTreasury(t, s, orgID, 3, true)
	// Swap one of the seeded non-regulator approvers for the regulator so
	// the regulator is counted once quorum is reached — we need to do this
	// by hand because seedRegulatorTreasury wires the non-reg happy path.
	tx, err := orm.Get[db.Transaction](s.db.ORM, opID)
	if err != nil {
		t.Fatalf("reload op: %v", err)
	}
	tx.ApprovedBy = []string{"u-compliance", "u-regulator"}
	if err := tx.Update(); err != nil {
		t.Fatalf("update op: %v", err)
	}
	// Now u-treasurer tips quorum → regulator is already present.
	rec := postTreasurySign(t, s, orgID, "u-treasurer", opID)
	if rec.Code != http.StatusOK {
		t.Fatalf("regulator present at quorum: expected 200, got %d body=%s",
			rec.Code, rec.Body.String())
	}
	fresh, _ := orm.Get[db.Transaction](s.db.ORM, opID)
	if fresh.Status != "approved" {
		t.Fatalf("op status after regulator-included quorum = %q, want approved", fresh.Status)
	}
}

// TestR6_RequireRegulator_FalseTier_NoRegulatorNeeded — control case.
// requireRegulator=false → numeric quorum alone is sufficient, regardless
// of who approved.
func TestR6_RequireRegulator_FalseTier_NoRegulatorNeeded(t *testing.T) {
	s := newTreasuryServer(t)
	orgID := "org-A"

	_, opID, finalSigner := seedRegulatorTreasury(t, s, orgID, 3, false)
	rec := postTreasurySign(t, s, orgID, finalSigner, opID)
	if rec.Code != http.StatusOK {
		t.Fatalf("requireRegulator=false, numeric quorum: expected 200, got %d body=%s",
			rec.Code, rec.Body.String())
	}
	fresh, _ := orm.Get[db.Transaction](s.db.ORM, opID)
	if fresh.Status != "approved" {
		t.Fatalf("op status = %q, want approved", fresh.Status)
	}
}

// TestR6_ValidateTier_RejectsRequireRegulatorWithoutShard — belt-and-braces
// check that the create-time validator already refuses a tier with
// requireRegulator=true when the wallet has no regulator shard. This is
// enforced in validateTreasuryTiers but re-asserting locks the contract.
func TestR6_ValidateTier_RejectsRequireRegulatorWithoutShard(t *testing.T) {
	_, err := validateTreasuryTiers(
		[]treasuryTierInput{
			{MaxValue: "inf", Threshold: 3, RequireRegulator: true},
		},
		4, // 4 signers, no regulator shard
		false,
	)
	if err == nil {
		t.Fatal("validateTreasuryTiers: tier with requireRegulator=true must reject when regulatorShard=false")
	}
}
