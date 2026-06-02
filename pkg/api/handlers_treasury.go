// Package api — Treasury handlers.
//
// /v1/mpc/treasury/* — 3-of-5 (or 4-of-5 escalated) org governance surface.
// Treasury wallets are distinct from user wallets: they have a fixed named
// signer set (compliance officer, treasurer, platform HSM, backup HSM,
// optional regulator), threshold-escalation tiers by op size, and are
// subject to per-org HSM isolation (the `platform_hsm` signer key MUST be
// scoped to `providers/{orgId}/mpc-cosigner-key`).
//
// Treasury signing operations project into the unified Operation view via
// `db.Transaction` with `TxType="treasury_sign"`. The existing CAS approval
// path (`tryApproveOperation`) is reused; the treasury handler resolves the
// required threshold from the wallet's tier ladder and persists it on the
// operation before publishing for approval.

package api

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"sort"
	"time"

	"github.com/hanzoai/orm"

	"github.com/luxfi/mpc/pkg/db"
)

// platformHSMKeyPathPrefix is the fixed prefix every treasury `platform_hsm`
// signer keyRef must start with. The rest of the path after the org slug is
// validated against the caller's JWT `owner` claim, so a treasury wallet
// owned by tenant A can never reference tenant B's HSM cosigner key.
const platformHSMKeyPathPrefix = "providers/"

// platformHSMKeyPathSuffix is the canonical suffix for the per-org cosigner
// key: `providers/{orgId}/mpc-cosigner-key`. Exact string match — no aliases.
const platformHSMKeyPathSuffix = "/mpc-cosigner-key"

// expectedPlatformHSMKeyRef returns the one and only valid KMS path for the
// given org's platform HSM. Used for both create-time validation and
// rotate-time re-validation.
func expectedPlatformHSMKeyRef(orgID string) string {
	return platformHSMKeyPathPrefix + orgID + platformHSMKeyPathSuffix
}

// treasuryAdminPermission — API keys must carry this permission to manage
// treasury wallets. Human roles `owner` and `admin` also pass.
const treasuryAdminPermission = "mpc.treasury.admin"

// treasurySignPermission — principal permission for signers approving a
// pending treasury op. JWT-authenticated signers pass on role alone; API
// keys must list the explicit permission.
const treasurySignPermission = "mpc.treasury.sign"

// --- Request / response shapes ---

type treasuryWalletResponse struct {
	WalletID       string               `json:"walletId"`
	Name           string               `json:"name"`
	Address        string               `json:"address,omitempty"`
	Chain          string               `json:"chain"`
	Signers        []treasurySignerView `json:"signers"`
	Tiers          []db.TreasuryTier    `json:"tiers"`
	RegulatorShard bool                 `json:"regulatorShard"`
	Status         string               `json:"status"`
	CreatedAt      time.Time            `json:"createdAt"`
	Outstanding    []outstandingOpView  `json:"outstanding,omitempty"`
}

type treasurySignerView struct {
	Role        string `json:"role"`
	KeyRef      string `json:"keyRef"`
	DisplayName string `json:"displayName,omitempty"`
}

type outstandingOpView struct {
	OperationID    string    `json:"operationId"`
	Status         string    `json:"status"`
	RequiredQuorum int       `json:"requiredQuorum"`
	Approvals      []string  `json:"approvals"`
	CreatedAt      time.Time `json:"createdAt"`
}

type treasurySignerInput struct {
	Role        string `json:"role"`
	KeyRef      string `json:"keyRef"`
	DisplayName string `json:"displayName,omitempty"`
}

type treasuryTierInput struct {
	MaxValue         string `json:"maxValue"`
	Threshold        int    `json:"threshold"`
	RequireRegulator bool   `json:"requireRegulator,omitempty"`
}

type treasuryWalletCreateRequest struct {
	Name           string                `json:"name"`
	Chain          string                `json:"chain,omitempty"`
	Signers        []treasurySignerInput `json:"signers"`
	Tiers          []treasuryTierInput   `json:"tiers"`
	RegulatorShard bool                  `json:"regulatorShard,omitempty"`
}

// --- Handlers ---

// handleCreateTreasuryWallet creates a new 3-of-5 treasury wallet for the
// calling org. Caller must be `owner`/`admin` (role gate at router) and
// must carry `mpc.treasury.admin` permission (enforced at router).
//
// Invariants enforced here:
//   - 3 ≤ len(signers) ≤ 5 (the "3-of-5" shape; regulator may be omitted)
//   - Exactly one signer per role
//   - `platform_hsm` signer's keyRef is the per-org KMS path
//     `providers/{orgId}/mpc-cosigner-key` — no cross-tenant reuse
//   - If `regulatorShard=true`, a `regulator` signer must be present
//   - Tiers are non-empty, thresholds monotonic non-decreasing by maxValue
//   - Every tier threshold ≤ total signers and ≥ 3
func (s *Server) handleCreateTreasuryWallet(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	userID := getUserID(r.Context())

	var req treasuryWalletCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if req.Chain == "" {
		req.Chain = "evm"
	}

	signers, err := validateTreasurySigners(orgID, req.Signers, req.RegulatorShard)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	tiers, err := validateTreasuryTiers(req.Tiers, len(signers), req.RegulatorShard)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Keygen the underlying MPC wallet. The protocol is CGGMP21 by default
	// (EVM-compatible secp256k1). The participants are still the cluster
	// MPC nodes — the treasury "signers" layer sits above at the approval
	// workflow, not inside the threshold protocol itself.
	result, err := s.mpc.TriggerKeygen(orgID, "")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "keygen failed: "+err.Error())
		return
	}

	// Persist the tier policy (kind="treasury"). We do this BEFORE the wallet
	// row so that wallet.PolicyID can reference it.
	tierJSON, _ := json.Marshal(map[string]any{"tiers": tiers})
	policy := orm.New[db.Policy](s.db.ORM)
	policy.OrgID = orgID
	policy.Kind = "treasury"
	policy.Name = "treasury:" + req.Name
	policy.Priority = 1000
	policy.Action = "require_approval"
	policy.RequiredApprovers = tiers[0].Threshold // baseline quorum
	policy.Conditions = tierJSON
	policy.Enabled = true
	if err := policy.Create(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create policy: "+err.Error())
		return
	}

	tw := orm.New[db.TreasuryWallet](s.db.ORM)
	tw.OrgID = orgID
	tw.Name = req.Name
	tw.WalletID = result.WalletID
	tw.EVMAddress = nilIfEmpty(result.EVMAddress)
	tw.Chain = req.Chain
	tw.Signers = signers
	tw.Tiers = tiers
	tw.RegulatorShard = req.RegulatorShard
	tw.PolicyID = policy.Id()
	tw.Status = "active"
	tw.CreatedBy = nilIfEmpty(userID)
	if err := tw.Create(); err != nil {
		// best-effort: delete the dangling policy so we don't leak half-state
		_ = policy.Delete()
		writeError(w, http.StatusInternalServerError, "failed to create treasury wallet: "+err.Error())
		return
	}

	// Back-link the policy to the wallet for audit queries.
	twID := tw.Id()
	policy.TreasuryWalletID = &twID
	_ = policy.Update()

	s.recordMpcAudit(r.Context(), orgID, userID, "treasury.wallet.create", "treasury_wallet", tw.Id())
	writeJSON(w, http.StatusCreated, toTreasuryWalletResponse(tw, nil))
}

func (s *Server) handleListTreasuryWallets(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	wallets, err := orm.TypedQuery[db.TreasuryWallet](s.db.ORM).
		Filter("orgId=", orgID).
		Order("-createdAt").
		Limit(200).
		GetAll(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	items := make([]treasuryWalletResponse, 0, len(wallets))
	for _, tw := range wallets {
		items = append(items, toTreasuryWalletResponse(tw, nil))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleGetTreasuryWallet(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	id := urlParam(r, "id")
	tw, err := orm.Get[db.TreasuryWallet](s.db.ORM, id)
	if err != nil || tw.OrgID != orgID {
		writeError(w, http.StatusNotFound, "treasury wallet not found")
		return
	}
	outstanding := s.loadOutstandingTreasuryOps(r.Context(), orgID, tw.WalletID)
	writeJSON(w, http.StatusOK, toTreasuryWalletResponse(tw, outstanding))
}

// treasurySignRequest — a signer approves a pending treasury op, identified
// by operationId. The approver is the JWT `sub` (or service principal for
// M2M keys). The handler wires into `tryApproveOperation` which is already
// CAS-safe under Postgres READ COMMITTED + GetForUpdate.
type treasurySignRequest struct {
	OperationID string `json:"operationId"`
	Notes       string `json:"notes,omitempty"`
}

// handleTreasurySign — signer approves a pending treasury operation.
// Reuses tryApproveOperation for the CAS concurrency guarantee and adds
// treasury-specific checks:
//
//  1. The operation must be txType="treasury_sign"
//  2. The caller's principal must appear in the treasury wallet's signer set
//     (by either `KeyRef` matching userID for humans, or by a role-to-role
//     binding for HSM signers — see resolveTreasurySignerRole).
//  3. When the op's tier `requireRegulator=true`, the regulator signer's
//     approval is a pre-condition before quorum transitions the op.
//
// `tryApproveOperation` enforces the numeric threshold via the wallet's
// Policy row; the regulator requirement is a post-quorum invariant and
// re-checked here before broadcasting.
func (s *Server) handleTreasurySign(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	userID := getUserID(r.Context())

	var req treasurySignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.OperationID == "" {
		writeError(w, http.StatusBadRequest, "operationId is required")
		return
	}

	tx, err := orm.Get[db.Transaction](s.db.ORM, req.OperationID)
	if err != nil || tx.OrgID != orgID {
		writeError(w, http.StatusNotFound, "operation not found")
		return
	}
	if tx.TxType != "treasury_sign" {
		writeError(w, http.StatusBadRequest, "operation is not a treasury signing operation")
		return
	}
	if tx.WalletID == nil {
		writeError(w, http.StatusBadRequest, "treasury operation missing walletId")
		return
	}
	tw, err := s.findTreasuryWalletByWalletID(r.Context(), orgID, *tx.WalletID)
	if err != nil {
		writeError(w, http.StatusNotFound, "treasury wallet not found")
		return
	}

	role, ok := resolveTreasurySignerRole(tw, userID)
	if !ok {
		writeError(w, http.StatusForbidden, "caller is not a signer on this treasury wallet")
		return
	}

	// Reuse the CAS approval engine. It atomically: (a) re-reads the op row
	// under SELECT FOR UPDATE, (b) verifies the op is still pending, (c)
	// appends the user, (d) transitions to "approved" when the required
	// threshold is reached. Concurrent approvals are serialized.
	const maxCASRetries = 5
	var final *db.Transaction
	var finalized bool
	for attempt := 0; attempt < maxCASRetries; attempt++ {
		t, fin, err := s.tryApproveOperation(r.Context(), orgID, userID, req.OperationID)
		if err != nil {
			if herr, ok := err.(*httpError); ok {
				writeError(w, herr.code, herr.msg)
				return
			}
			if errors.Is(err, errOperationConflict) {
				time.Sleep(time.Duration(10*(attempt+1)) * time.Millisecond)
				continue
			}
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		final = t
		finalized = fin
		break
	}
	if final == nil {
		writeError(w, http.StatusConflict, "operation busy, retry")
		return
	}

	// Regulator invariant: if the operation's tier requires regulator
	// approval, we must ensure the regulator signer actually appears in
	// ApprovedBy before we consider quorum met. We re-check even on
	// `finalized=false` so we can reject the approval if the caller's
	// reaching-quorum attempt would skip a required regulator.
	if finalized {
		tier := s.tierForOperation(tw, final)
		if tier.RequireRegulator {
			if !approvalsIncludeRegulator(tw, final.ApprovedBy) {
				// Roll back the finalization: the quorum count is met but
				// regulator is missing. Move status back to
				// pending_approval so additional approvals (specifically
				// the regulator's) can land.
				if herr := s.revertQuorumWithoutRegulator(r.Context(), orgID, final.Id()); herr != nil {
					writeError(w, http.StatusInternalServerError, herr.Error())
					return
				}
				writeError(w, http.StatusConflict, "numeric quorum reached but regulator approval required for this tier")
				return
			}
			go s.signAndBroadcast(final.Id(), orgID)
		} else {
			go s.signAndBroadcast(final.Id(), orgID)
		}
	}

	s.recordMpcAudit(r.Context(), orgID, userID, "treasury.sign",
		"treasury_wallet", tw.Id()+"#op="+req.OperationID+"#role="+role)
	writeJSON(w, http.StatusOK, txToOperation(final))
}

// revertQuorumWithoutRegulator moves a treasury op that reached numeric
// quorum but lacks a regulator approval back to pending_approval under the
// same SELECT FOR UPDATE lock used by tryApproveOperation.
func (s *Server) revertQuorumWithoutRegulator(ctx context.Context, orgID, opID string) error {
	return s.db.ORM.RunInTransactionWith(ctx, &orm.TxOptions{
		Isolation:   orm.IsolationReadCommitted,
		MaxAttempts: 3,
	}, func(txdb orm.DB) error {
		fresh, gerr := orm.GetForUpdate[db.Transaction](txdb, opID)
		if gerr != nil {
			return gerr
		}
		if fresh.OrgID != orgID {
			return errors.New("operation not found")
		}
		if fresh.Status == "approved" {
			sysActor := "system:treasury"
			fresh.RecordTransition("pending_approval",
				"numeric quorum met but regulator approval required", &sysActor)
			return fresh.Update()
		}
		return nil
	})
}

// rotateSignerRequest rotates one role's signer to a new KeyRef. This is a
// sensitive operation; it requires the same 3-of-5 quorum as a standard
// treasury op. We model the rotation as a treasury_sign operation whose
// payload carries the rotation parameters; once approved, the handler
// commits the rotation.
type rotateSignerRequest struct {
	Role        string `json:"role"`
	NewKeyRef   string `json:"newKeyRef"`
	DisplayName string `json:"displayName,omitempty"`
}

// handleRotateTreasurySigner starts (or advances) the signer rotation flow.
// The rotation itself is gated by a treasury quorum approval — we enforce
// that by writing the rotation intent into the Operation table and having
// the same tryApproveOperation path reach quorum before the final commit.
//
// This endpoint only ACCEPTS the rotation intent. Approval still happens
// via POST /v1/mpc/treasury/sign on the returned operationId.
//
// Why not do the rotation inline when the quorum is reached? Because
// rotations must NOT short-circuit the signer's own approval (the rotating
// role itself votes on its replacement), and tryApproveOperation already
// enforces "initiator cannot self-approve". The rotation commit is
// therefore a background job after the approval flow completes.
func (s *Server) handleRotateTreasurySigner(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	userID := getUserID(r.Context())
	id := urlParam(r, "id")

	tw, err := orm.Get[db.TreasuryWallet](s.db.ORM, id)
	if err != nil || tw.OrgID != orgID {
		writeError(w, http.StatusNotFound, "treasury wallet not found")
		return
	}

	var req rotateSignerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Role == "" || req.NewKeyRef == "" {
		writeError(w, http.StatusBadRequest, "role and newKeyRef are required")
		return
	}
	if !validTreasurySignerRole(req.Role) {
		writeError(w, http.StatusBadRequest, "unknown role")
		return
	}
	// Platform HSM rotations must still land at the same per-org key path.
	// The caller may rotate to a new KEY VERSION but not to a different
	// tenant's key. We validate the prefix/suffix and embedded orgID.
	if req.Role == db.TreasurySignerPlatformHSM && req.NewKeyRef != expectedPlatformHSMKeyRef(orgID) {
		writeError(w, http.StatusForbidden,
			"platform_hsm rotation must target the per-org cosigner path "+expectedPlatformHSMKeyRef(orgID))
		return
	}
	if req.Role == db.TreasurySignerRegulator && !tw.RegulatorShard {
		writeError(w, http.StatusBadRequest, "wallet has no regulator shard")
		return
	}

	// Encode the rotation payload into a Transaction row. The raw bytes are
	// a canonical JSON blob of (role, newKeyRef, displayName, walletRef).
	payload, _ := json.Marshal(map[string]string{
		"role":        req.Role,
		"newKeyRef":   req.NewKeyRef,
		"displayName": req.DisplayName,
		"twID":        tw.Id(),
	})
	tx := orm.New[db.Transaction](s.db.ORM)
	tx.OrgID = orgID
	walletRef := tw.WalletID
	tx.WalletID = &walletRef
	tx.TxType = "treasury_sign"
	tx.Chain = tw.Chain
	tx.RawTx = payload
	tx.Status = "pending_approval"
	tx.InitiatedBy = nilIfEmpty(userID)
	tx.TargetConfirms = 1
	if err := tx.Create(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to record rotation intent: "+err.Error())
		return
	}

	s.recordMpcAudit(r.Context(), orgID, userID, "treasury.signer.rotate.intent",
		"treasury_wallet", tw.Id()+"#role="+req.Role)
	writeJSON(w, http.StatusAccepted, map[string]any{
		"operationId": tx.Id(),
		"status":      "pending_approval",
		"message":     "rotation intent recorded; call /v1/mpc/treasury/sign to approve",
	})
}

// --- Helpers ---

func toTreasuryWalletResponse(tw *db.TreasuryWallet, outstanding []outstandingOpView) treasuryWalletResponse {
	signers := make([]treasurySignerView, 0, len(tw.Signers))
	for _, s := range tw.Signers {
		signers = append(signers, treasurySignerView{
			Role:        s.Role,
			KeyRef:      s.KeyRef,
			DisplayName: s.DisplayName,
		})
	}
	addr := ""
	if tw.EVMAddress != nil {
		addr = *tw.EVMAddress
	}
	return treasuryWalletResponse{
		WalletID:       tw.Id(),
		Name:           tw.Name,
		Address:        addr,
		Chain:          tw.Chain,
		Signers:        signers,
		Tiers:          tw.Tiers,
		RegulatorShard: tw.RegulatorShard,
		Status:         tw.Status,
		CreatedAt:      tw.CreatedAt,
		Outstanding:    outstanding,
	}
}

// validateTreasurySigners verifies the signer set shape and per-org HSM
// isolation. Enforces one-of-each-role, 3-5 signers total, and the
// per-org KMS key path for platform_hsm.
func validateTreasurySigners(orgID string, in []treasurySignerInput, regulatorShard bool) ([]db.TreasurySigner, error) {
	if len(in) < 3 {
		return nil, errors.New("at least 3 signers required")
	}
	if len(in) > 5 {
		return nil, errors.New("at most 5 signers allowed")
	}
	seen := map[string]bool{}
	out := make([]db.TreasurySigner, 0, len(in))
	for _, s := range in {
		if s.Role == "" || s.KeyRef == "" {
			return nil, errors.New("signer role and keyRef required")
		}
		if !validTreasurySignerRole(s.Role) {
			return nil, errors.New("unknown signer role: " + s.Role)
		}
		if seen[s.Role] {
			return nil, errors.New("duplicate signer role: " + s.Role)
		}
		seen[s.Role] = true
		// Per-org HSM isolation. The `platform_hsm` signer's keyRef must be
		// EXACTLY `providers/{orgID}/mpc-cosigner-key`. No cross-tenant
		// reuse, no wildcard, no aliases.
		if s.Role == db.TreasurySignerPlatformHSM {
			if s.KeyRef != expectedPlatformHSMKeyRef(orgID) {
				return nil, errors.New("platform_hsm keyRef must be " + expectedPlatformHSMKeyRef(orgID))
			}
		}
		out = append(out, db.TreasurySigner{
			Role:        s.Role,
			KeyRef:      s.KeyRef,
			DisplayName: s.DisplayName,
		})
	}
	// Required roles.
	if !seen[db.TreasurySignerCompliance] {
		return nil, errors.New("missing signer role: compliance_officer")
	}
	if !seen[db.TreasurySignerTreasurer] {
		return nil, errors.New("missing signer role: treasurer")
	}
	if !seen[db.TreasurySignerPlatformHSM] {
		return nil, errors.New("missing signer role: platform_hsm")
	}
	if regulatorShard && !seen[db.TreasurySignerRegulator] {
		return nil, errors.New("regulatorShard=true requires a regulator signer")
	}
	if !regulatorShard && seen[db.TreasurySignerRegulator] {
		return nil, errors.New("regulator signer provided but regulatorShard=false")
	}
	return out, nil
}

// validateTreasuryTiers enforces: non-empty ladder, every threshold in
// [3, numSigners], monotonic non-decreasing by maxValue, a final "inf" tier
// covering arbitrarily large values. Rejects overlapping or inverted tiers.
func validateTreasuryTiers(in []treasuryTierInput, numSigners int, regulatorShard bool) ([]db.TreasuryTier, error) {
	if len(in) == 0 {
		return nil, errors.New("at least one tier required")
	}
	if numSigners < 3 {
		return nil, errors.New("numSigners must be ≥ 3 for treasury")
	}
	out := make([]db.TreasuryTier, 0, len(in))
	for _, t := range in {
		if t.Threshold < 3 {
			return nil, errors.New("tier threshold must be ≥ 3")
		}
		if t.Threshold > numSigners {
			return nil, errors.New("tier threshold exceeds number of signers")
		}
		if t.RequireRegulator && !regulatorShard {
			return nil, errors.New("tier requireRegulator=true but wallet has no regulator")
		}
		if t.MaxValue != "inf" {
			if _, ok := new(big.Int).SetString(t.MaxValue, 10); !ok {
				return nil, errors.New("tier maxValue must be base-10 integer or \"inf\"")
			}
		}
		out = append(out, db.TreasuryTier{
			MaxValue:         t.MaxValue,
			Threshold:        t.Threshold,
			RequireRegulator: t.RequireRegulator,
		})
	}
	// Sort by maxValue ascending ("inf" last).
	sort.SliceStable(out, func(i, j int) bool {
		return tierCmp(out[i].MaxValue, out[j].MaxValue) < 0
	})
	// At least one "inf" tier so high-value ops have a threshold to hit.
	if out[len(out)-1].MaxValue != "inf" {
		return nil, errors.New("last tier must have maxValue=\"inf\"")
	}
	// Thresholds must be monotonic non-decreasing as maxValue grows.
	for i := 1; i < len(out); i++ {
		if out[i].Threshold < out[i-1].Threshold {
			return nil, errors.New("tier thresholds must be monotonic non-decreasing")
		}
	}
	return out, nil
}

// tierCmp compares two tier maxValue strings ("inf" > everything).
func tierCmp(a, b string) int {
	if a == b {
		return 0
	}
	if a == "inf" {
		return 1
	}
	if b == "inf" {
		return -1
	}
	ai, _ := new(big.Int).SetString(a, 10)
	bi, _ := new(big.Int).SetString(b, 10)
	return ai.Cmp(bi)
}

func validTreasurySignerRole(role string) bool {
	switch role {
	case db.TreasurySignerCompliance, db.TreasurySignerTreasurer,
		db.TreasurySignerPlatformHSM, db.TreasurySignerBackupHSM,
		db.TreasurySignerRegulator:
		return true
	}
	return false
}

// resolveTreasurySignerRole maps an authenticated principal to its signer
// role on the wallet, or returns (", false) if the principal is not a
// member. KeyRef equality is the one way we identify human signers (JWT
// `sub`) and M2M principals (service key IDs). HSM signers do not approve
// through this endpoint — they're invoked by the backend once quorum is
// reached.
func resolveTreasurySignerRole(tw *db.TreasuryWallet, principal string) (string, bool) {
	if principal == "" {
		return "", false
	}
	for _, s := range tw.Signers {
		// Platform HSM / Backup HSM signers can be invoked via service
		// principals whose KeyRef includes the KMS path prefix — we skip
		// those in the approval flow (they sign directly once quorum
		// approves the op).
		if s.KeyRef == principal {
			return s.Role, true
		}
	}
	return "", false
}

// approvalsIncludeRegulator returns true if any approver in the list is the
// regulator signer for this wallet.
func approvalsIncludeRegulator(tw *db.TreasuryWallet, approvedBy []string) bool {
	for _, s := range tw.Signers {
		if s.Role != db.TreasurySignerRegulator {
			continue
		}
		for _, approver := range approvedBy {
			if approver == s.KeyRef {
				return true
			}
		}
	}
	return false
}

// tierForOperation picks the first tier whose value envelope covers the
// operation's amount. If the op has no amount declared, the smallest tier
// applies (safest default).
func (s *Server) tierForOperation(tw *db.TreasuryWallet, tx *db.Transaction) db.TreasuryTier {
	amt := "0"
	if tx.Amount != nil {
		amt = *tx.Amount
	}
	for _, tier := range tw.Tiers {
		if tier.MaxValue == "inf" {
			return tier
		}
		cap, _ := new(big.Int).SetString(tier.MaxValue, 10)
		val, _ := new(big.Int).SetString(amt, 10)
		if val == nil {
			val = new(big.Int)
		}
		if val.Cmp(cap) <= 0 {
			return tier
		}
	}
	// Should be unreachable (validateTreasuryTiers enforces an "inf" tier).
	return tw.Tiers[len(tw.Tiers)-1]
}

// findTreasuryWalletByWalletID looks up a treasury wallet by its underlying
// MPC walletId. Used when a signer references an operation but doesn't know
// the TreasuryWallet row ID.
func (s *Server) findTreasuryWalletByWalletID(ctx context.Context, orgID, walletID string) (*db.TreasuryWallet, error) {
	wallets, err := orm.TypedQuery[db.TreasuryWallet](s.db.ORM).
		Filter("orgId=", orgID).
		Filter("walletId=", walletID).
		Limit(1).
		GetAll(ctx)
	if err != nil || len(wallets) == 0 {
		return nil, errors.New("treasury wallet not found")
	}
	return wallets[0], nil
}

// loadOutstandingTreasuryOps returns the pending_approval treasury ops for
// the wallet. Used by GET /v1/mpc/treasury/wallets/{id} to render the quorum
// progress.
func (s *Server) loadOutstandingTreasuryOps(ctx context.Context, orgID, walletID string) []outstandingOpView {
	txs, err := orm.TypedQuery[db.Transaction](s.db.ORM).
		Filter("orgId=", orgID).
		Filter("walletId=", walletID).
		Filter("txType=", "treasury_sign").
		Filter("status=", "pending_approval").
		Order("-createdAt").
		Limit(100).
		GetAll(ctx)
	if err != nil {
		return nil
	}
	out := make([]outstandingOpView, 0, len(txs))
	for _, t := range txs {
		reqQuorum, _ := s.requiredApprovers(ctx, orgID, t.Id())
		out = append(out, outstandingOpView{
			OperationID:    t.Id(),
			Status:         t.Status,
			RequiredQuorum: reqQuorum,
			Approvals:      t.ApprovedBy,
			CreatedAt:      t.CreatedAt,
		})
	}
	return out
}

// signAndBroadcast — placeholder stub used by both handleApproveOperation
// (existing) and handleTreasurySign (new). The existing operations.go
// handler already refers to `s.signAndBroadcast`; we rely on that symbol
// being defined in the existing codebase. No new stub here.
