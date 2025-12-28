package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hanzoai/orm"

	"github.com/luxfi/mpc/pkg/db"
)

// --- /v1/mpc/operations ---
//
// Unified `Operation` view (sign/send/mint/burn/transfer/contract_call) over
// the existing `db.Transaction` table. No new operations table — one table,
// one view, `txType` becomes the discriminator.
//
// Status mapping between Transaction.Status and Operation.status:
//
//   pending_approval    → pending_approval
//   approved            → approved
//   signing, signed     → signed
//   rejected            → rejected
//   failed, reverted    → failed
//   expired             → expired
//   (everything else)   → signed  (as long as there's a signature)

type operationResponse struct {
	OperationID     string                 `json:"operationId"`
	WalletID        string                 `json:"walletId"`
	Kind            string                 `json:"kind"`
	Payload         map[string]interface{} `json:"payload,omitempty"`
	Status          string                 `json:"status"`
	Approvers       []string               `json:"approvers,omitempty"`
	Approvals       []operationApproval    `json:"approvals,omitempty"`
	RejectionReason string                 `json:"rejectionReason,omitempty"`
	Result          map[string]string      `json:"result,omitempty"`
	CreatedAt       time.Time              `json:"createdAt"`
	CompletedAt     *time.Time             `json:"completedAt,omitempty"`
}

type operationApproval struct {
	ApproverID string    `json:"approverId"`
	ApprovedAt time.Time `json:"approvedAt"`
	Notes      string    `json:"notes,omitempty"`
}

func txToOperation(t *db.Transaction) operationResponse {
	walletID := ""
	if t.WalletID != nil {
		walletID = *t.WalletID
	}
	kind := t.TxType
	if kind == "" {
		kind = "sign"
	}
	// Canonicalize kind → spec enum.
	switch kind {
	case "sweep":
		kind = "transfer"
	case "mint", "burn", "transfer", "send", "contract_call", "sign":
	default:
		kind = "sign"
	}
	status := mapTxStatus(t.Status)
	payload := map[string]interface{}{}
	if t.ToAddress != nil {
		payload["toAddress"] = *t.ToAddress
	}
	if t.Amount != nil {
		payload["amount"] = *t.Amount
	}
	if t.Token != nil {
		payload["token"] = *t.Token
	}
	if t.Chain != "" {
		payload["chain"] = t.Chain
	}
	if len(t.RawTx) > 0 {
		payload["rawTx"] = "0x" + hexString(t.RawTx)
	}
	approvals := make([]operationApproval, 0, len(t.ApprovedBy))
	for _, id := range t.ApprovedBy {
		approvals = append(approvals, operationApproval{
			ApproverID: id,
			ApprovedAt: t.UpdatedAt,
		})
	}
	result := map[string]string{}
	if t.SignatureR != nil && t.SignatureS != nil {
		result["signature"] = "0x" + *t.SignatureR + *t.SignatureS
	} else if t.SignatureEdDSA != nil {
		result["signature"] = *t.SignatureEdDSA
	}
	if t.TxHash != nil {
		result["txHash"] = *t.TxHash
	}
	rejection := ""
	if t.RejectionReason != nil {
		rejection = *t.RejectionReason
	}
	var completed *time.Time
	if t.SignedAt != nil {
		completed = t.SignedAt
	} else if t.FinalizedAt != nil {
		completed = t.FinalizedAt
	}
	return operationResponse{
		OperationID:     t.Id(),
		WalletID:        walletID,
		Kind:            kind,
		Payload:         payload,
		Status:          status,
		Approvers:       t.ApprovedBy,
		Approvals:       approvals,
		RejectionReason: rejection,
		Result:          result,
		CreatedAt:       t.CreatedAt,
		CompletedAt:     completed,
	}
}

func mapTxStatus(s string) string {
	switch s {
	case "pending_approval":
		return "pending_approval"
	case "approved":
		return "approved"
	case "signing", "signed", "broadcast", "confirming", "finalized":
		return "signed"
	case "rejected":
		return "rejected"
	case "failed", "reverted":
		return "failed"
	case "expired":
		return "expired"
	default:
		return s
	}
}

func hexString(b []byte) string {
	const alphabet = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = alphabet[v>>4]
		out[i*2+1] = alphabet[v&0x0f]
	}
	return string(out)
}

func (s *Server) handleListOperations(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())

	q := orm.TypedQuery[db.Transaction](s.db.ORM).
		Filter("orgId=", orgID).
		Order("-createdAt")

	walletID := r.URL.Query().Get("walletId")
	if walletID != "" {
		q = q.Filter("walletId=", walletID)
	}
	statusFilter := r.URL.Query().Get("status")
	if statusFilter != "" {
		// Spec statuses → Transaction statuses (best-effort).
		q = q.Filter("status=", reverseMapStatus(statusFilter))
	}

	perPage := parseIntDefault(r.URL.Query().Get("perPage"), 50)
	page := parseIntDefault(r.URL.Query().Get("page"), 1)
	q = q.Limit(perPage)

	txs, err := q.GetAll(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	items := make([]operationResponse, 0, len(txs))
	for _, t := range txs {
		items = append(items, txToOperation(t))
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items":      items,
		"page":       page,
		"totalItems": len(items),
	})
}

func reverseMapStatus(s string) string {
	switch s {
	case "signed":
		return "signed"
	case "pending_approval", "approved", "rejected", "failed", "expired":
		return s
	}
	return s
}

func (s *Server) handleGetOperation(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	opID := urlParam(r, "operationId")

	t, err := orm.Get[db.Transaction](s.db.ORM, opID)
	if err != nil || t.OrgID != orgID {
		writeError(w, http.StatusNotFound, "operation not found")
		return
	}
	writeJSON(w, http.StatusOK, txToOperation(t))
}

// handleApproveOperation enforces N-of-M approval per wallet policy.
// Approver identity is taken from the JWT `sub` (userID) — not from body.
func (s *Server) handleApproveOperation(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	userID := getUserID(r.Context())
	opID := urlParam(r, "operationId")

	var req struct {
		Notes string `json:"notes"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	t, err := orm.Get[db.Transaction](s.db.ORM, opID)
	if err != nil || t.OrgID != orgID {
		writeError(w, http.StatusNotFound, "operation not found")
		return
	}
	if t.Status != "pending_approval" {
		writeError(w, http.StatusConflict, "operation not in pending_approval state")
		return
	}
	for _, id := range t.ApprovedBy {
		if id == userID {
			writeError(w, http.StatusConflict, "already approved")
			return
		}
	}
	if t.InitiatedBy != nil && *t.InitiatedBy == userID && len(t.ApprovedBy) == 0 {
		writeError(w, http.StatusForbidden, "initiator cannot self-approve")
		return
	}

	// Required approvers — from wallet policy if any, else 1.
	required := 1
	if t.WalletID != nil {
		policies, _ := s.loadPolicies(r.Context(), orgID, nil)
		amt := ""
		if t.Amount != nil {
			amt = *t.Amount
		}
		to := ""
		if t.ToAddress != nil {
			to = *t.ToAddress
		}
		decision := evaluateTransaction(amt, t.Chain, to, policies)
		if decision.RequiredApprovers > required {
			required = decision.RequiredApprovers
		}
	}

	t.ApprovedBy = append(t.ApprovedBy, userID)
	if err := t.Update(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to approve operation")
		return
	}
	if len(t.ApprovedBy) < required {
		// Threshold not yet reached — remain pending_approval.
		s.recordMpcAudit(r.Context(), orgID, userID, "operation.approve", "operation", opID)
		writeJSON(w, http.StatusOK, txToOperation(t))
		return
	}
	detail := fmt.Sprintf("quorum reached: %d/%d approvals", len(t.ApprovedBy), required)
	t.RecordTransition("approved", detail, &userID)
	t.Update()
	go s.signAndBroadcast(opID, orgID)

	s.recordMpcAudit(r.Context(), orgID, userID, "operation.approve", "operation", opID)
	writeJSON(w, http.StatusOK, txToOperation(t))
}

func (s *Server) handleRejectOperation(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	userID := getUserID(r.Context())
	opID := urlParam(r, "operationId")

	var req struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Reason == "" {
		writeError(w, http.StatusBadRequest, "reason is required")
		return
	}

	t, err := orm.Get[db.Transaction](s.db.ORM, opID)
	if err != nil || t.OrgID != orgID {
		writeError(w, http.StatusNotFound, "operation not found")
		return
	}
	if t.Status != "pending_approval" {
		writeError(w, http.StatusConflict, "operation not in pending_approval state")
		return
	}
	t.RecordTransition("rejected", "rejected: "+req.Reason, &userID)
	t.RejectedBy = nilIfEmpty(userID)
	t.RejectionReason = nilIfEmpty(req.Reason)
	if err := t.Update(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to reject operation")
		return
	}
	s.recordMpcAudit(r.Context(), orgID, userID, "operation.reject", "operation", opID)
	writeJSON(w, http.StatusOK, txToOperation(t))
}

// --- /v1/mpc/audit ---

func (s *Server) handleMpcListAudit(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())

	q := orm.TypedQuery[db.AuditEntry](s.db.ORM).
		Filter("orgId=", orgID).
		Order("-createdAt")

	if walletID := r.URL.Query().Get("walletId"); walletID != "" {
		q = q.Filter("resourceId=", walletID)
	}
	if actor := r.URL.Query().Get("actorId"); actor != "" {
		q = q.Filter("userId=", actor)
	}
	if action := r.URL.Query().Get("action"); action != "" {
		q = q.Filter("action=", action)
	}
	perPage := parseIntDefault(r.URL.Query().Get("perPage"), 100)
	page := parseIntDefault(r.URL.Query().Get("page"), 1)
	q = q.Limit(perPage)

	entries, err := q.GetAll(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	items := make([]map[string]interface{}, 0, len(entries))
	for _, e := range entries {
		item := map[string]interface{}{
			"entryId":   e.Id(),
			"tenantId":  e.OrgID,
			"action":    e.Action,
			"timestamp": e.CreatedAt,
		}
		if e.UserID != nil {
			item["actorId"] = *e.UserID
		}
		if e.ResourceType != nil {
			item["subjectType"] = *e.ResourceType
		}
		if e.ResourceID != nil {
			item["subjectId"] = *e.ResourceID
		}
		if e.IPAddress != nil {
			item["ip"] = *e.IPAddress
		}
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items":      items,
		"page":       page,
		"totalItems": len(items),
	})
}

// --- /v1/mpc/policies — thin wrapper around existing policy handlers ---
//
// Spec shape:
//   GET    /v1/mpc/policies
//   POST   /v1/mpc/policies
//   GET    /v1/mpc/policies/{policyId}
//   PATCH  /v1/mpc/policies/{policyId}
//   DELETE /v1/mpc/policies/{policyId}
//
// We reuse the existing CRUD handlers (handleListPolicies, handleCreatePolicy,
// handleUpdatePolicy, handleDeletePolicy) and add a thin get-by-id.

func (s *Server) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	policyID := urlParam(r, "policyId")
	policy, err := orm.Get[db.Policy](s.db.ORM, policyID)
	if err != nil || policy.OrgID != orgID {
		writeError(w, http.StatusNotFound, "policy not found")
		return
	}
	writeJSON(w, http.StatusOK, policy)
}

func parseIntDefault(s string, def int) int {
	if s == "" {
		return def
	}
	i, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || i <= 0 {
		return def
	}
	return i
}
