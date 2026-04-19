package api

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"time"

	"github.com/hanzoai/orm"

	"github.com/luxfi/mpc/pkg/db"
)

// errSessionConflict is the sentinel for concurrent session mutation. Callers
// (consumeSessionForSign) map it to 409 retry logic.
var errSessionConflict = errors.New("session modified concurrently")

// --- Sessions: /v1/mpc/wallets/{id}/sessions ---
//
// A session is a time-bounded signing grant for an MPC wallet. The caller
// (user or service principal) may sign up to OperationLimit operations with
// cumulative value up to ValueLimit, until ExpiresAt. Enforcement happens in
// handleSignWithDefaultWallet / handleSignSettlement via consumeSessionForSign.

// sessionResponse is the JSON shape specified in mpc.yaml.
type sessionResponse struct {
	SessionID      string    `json:"sessionId"`
	WalletID       string    `json:"walletId"`
	GrantedTo      string    `json:"grantedTo,omitempty"`
	Scopes         []string  `json:"scopes,omitempty"`
	ValueLimit     *string   `json:"valueLimit,omitempty"`
	OperationLimit *int      `json:"operationLimit,omitempty"`
	Status         string    `json:"status"`
	CreatedAt      time.Time `json:"createdAt"`
	ExpiresAt      time.Time `json:"expiresAt"`
	RevokedAt      *time.Time `json:"revokedAt,omitempty"`
}

func toSessionResponse(s *db.Session) sessionResponse {
	return sessionResponse{
		SessionID:      s.Id(),
		WalletID:       s.WalletID,
		GrantedTo:      s.GrantedTo,
		Scopes:         s.Scopes,
		ValueLimit:     s.ValueLimit,
		OperationLimit: s.OperationLimit,
		Status:         effectiveSessionStatus(s),
		CreatedAt:      s.CreatedAt,
		ExpiresAt:      s.ExpiresAt,
		RevokedAt:      s.RevokedAt,
	}
}

// effectiveSessionStatus reports expired for any session whose wall-clock
// expiry or limits have elapsed. Stored `Status` is authoritative for
// revoked/pending_approval.
func effectiveSessionStatus(s *db.Session) string {
	if s.Status == "revoked" || s.Status == "pending_approval" {
		return s.Status
	}
	if time.Now().After(s.ExpiresAt) {
		return "expired"
	}
	if s.OperationLimit != nil && s.OperationsUsed >= *s.OperationLimit {
		return "expired"
	}
	return s.Status
}

func (s *Server) handleListWalletSessions(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	walletID := urlParam(r, "id")

	// Verify wallet ownership
	wallet, err := orm.Get[db.Wallet](s.db.ORM, walletID)
	if err != nil || wallet.OrgID != orgID {
		writeError(w, http.StatusNotFound, "wallet not found")
		return
	}

	q := orm.TypedQuery[db.Session](s.db.ORM).
		Filter("orgId=", orgID).
		Filter("walletId=", walletID).
		Order("-createdAt").
		Limit(200)

	sessions, err := q.GetAll(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	statusFilter := r.URL.Query().Get("status")
	items := make([]sessionResponse, 0, len(sessions))
	for _, sess := range sessions {
		resp := toSessionResponse(sess)
		if statusFilter != "" && resp.Status != statusFilter {
			continue
		}
		items = append(items, resp)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items})
}

func (s *Server) handleCreateWalletSession(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	userID := getUserID(r.Context())
	walletID := urlParam(r, "id")

	wallet, err := orm.Get[db.Wallet](s.db.ORM, walletID)
	if err != nil || wallet.OrgID != orgID {
		writeError(w, http.StatusNotFound, "wallet not found")
		return
	}

	var req struct {
		GrantedTo      string    `json:"grantedTo,omitempty"`
		Scopes         []string  `json:"scopes"`
		ValueLimit     *string   `json:"valueLimit,omitempty"`
		OperationLimit *int      `json:"operationLimit,omitempty"`
		ExpiresAt      time.Time `json:"expiresAt"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Scopes) == 0 {
		writeError(w, http.StatusBadRequest, "scopes is required")
		return
	}
	if req.ExpiresAt.IsZero() {
		writeError(w, http.StatusBadRequest, "expiresAt is required")
		return
	}
	if !req.ExpiresAt.After(time.Now()) {
		writeError(w, http.StatusBadRequest, "expiresAt must be in the future")
		return
	}
	for _, scope := range req.Scopes {
		switch scope {
		case "sign", "authorize", "read":
		default:
			writeError(w, http.StatusBadRequest, "unknown scope: "+scope)
			return
		}
	}
	if req.ValueLimit != nil {
		if _, ok := new(big.Int).SetString(*req.ValueLimit, 10); !ok {
			writeError(w, http.StatusBadRequest, "valueLimit must be a base-10 integer string")
			return
		}
	}

	// F24: Session grant creation policy gate. If the requested grant's
	// valueLimit exceeds what wallet-scoped policies would allow without
	// approval, the session starts in pending_approval state; otherwise
	// active. This prevents "roll your own unbounded signing grant" bypass
	// of the approval workflow.
	status := "active"
	if req.ValueLimit != nil {
		policies, _ := s.loadPolicies(r.Context(), orgID, nil)
		// Evaluate the hypothetical max-spend transaction. If policy would
		// require approval for this amount, the grant itself must be approved.
		decision := evaluateTransaction(*req.ValueLimit, "evm", "", policies)
		if decision.Action == "deny" {
			writeError(w, http.StatusForbidden, "requested session grant exceeds wallet policy: "+decision.Reason)
			return
		}
		if decision.Action == "require_approval" && decision.RequiredApprovers > 0 {
			status = "pending_approval"
		}
	}
	// Operation-count-only sessions with no ValueLimit must also require
	// approval if the count exceeds a per-wallet safety ceiling.
	if req.OperationLimit != nil && *req.OperationLimit > 1000 {
		status = "pending_approval"
	}

	sess := orm.New[db.Session](s.db.ORM)
	sess.OrgID = orgID
	sess.WalletID = walletID
	sess.GrantedTo = req.GrantedTo
	if sess.GrantedTo == "" {
		sess.GrantedTo = userID
	}
	sess.Scopes = req.Scopes
	sess.ValueLimit = req.ValueLimit
	sess.ValueAccum = "0"
	sess.OperationLimit = req.OperationLimit
	sess.OperationsUsed = 0
	sess.Status = status
	sess.ExpiresAt = req.ExpiresAt
	sess.CreatedBy = nilIfEmpty(userID)
	if err := sess.Create(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create session: "+err.Error())
		return
	}

	s.recordMpcAudit(r.Context(), orgID, userID, "session.create", "session", sess.Id())
	writeJSON(w, http.StatusCreated, toSessionResponse(sess))
}

func (s *Server) handleGetWalletSession(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	walletID := urlParam(r, "id")
	sessionID := urlParam(r, "sessionId")

	sess, err := orm.Get[db.Session](s.db.ORM, sessionID)
	if err != nil || sess.OrgID != orgID || sess.WalletID != walletID {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}
	writeJSON(w, http.StatusOK, toSessionResponse(sess))
}

func (s *Server) handleRevokeWalletSession(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	userID := getUserID(r.Context())
	walletID := urlParam(r, "id")
	sessionID := urlParam(r, "sessionId")

	sess, err := orm.Get[db.Session](s.db.ORM, sessionID)
	if err != nil || sess.OrgID != orgID || sess.WalletID != walletID {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}
	if sess.Status != "revoked" {
		now := time.Now()
		sess.Status = "revoked"
		sess.RevokedAt = &now
		sess.RevokedBy = nilIfEmpty(userID)
		if err := sess.Update(); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to revoke session")
			return
		}
		s.recordMpcAudit(r.Context(), orgID, userID, "session.revoke", "session", sessionID)
	}
	w.WriteHeader(http.StatusNoContent)
}

// consumeSessionForSign atomically validates and consumes a signing session:
//   - OperationsUsed++ and ValueAccum += value, under a row-level lock (R2-2).
//
// Under Postgres the row lock is acquired via SELECT FOR UPDATE inside a
// serializable tx. Concurrent consumers of the same session row block until
// the first tx commits, so no two callers ever observe the same pre-write
// OperationsUsed — the operationLimit is strictly respected. Under SQLite the
// driver-level write mutex already provides the same invariant.
//
// If `sessionID` is empty callers get a 403 — the handler requires an explicit
// session (F1).
func (s *Server) consumeSessionForSign(
	ctx context.Context,
	orgID, walletID, principal, sessionID, value string,
) (*db.Session, error) {
	if sessionID == "" {
		return nil, &httpError{code: http.StatusForbidden, msg: "sessionId is required"}
	}

	var sess *db.Session
	// R2-2: READ COMMITTED + SELECT FOR UPDATE. FOR UPDATE blocks concurrent
	// consumers on the row; when a waiter unblocks, READ COMMITTED re-reads
	// the row at the latest committed snapshot. Serializable would instead
	// abort the waiter with 40001 because its outer snapshot is stale, and
	// retrying into a fresh tx loses us the accumulated "I'm next in line"
	// ordering. READ COMMITTED + FOR UPDATE is the right primitive here.
	err := s.db.ORM.RunInTransactionWith(ctx, &orm.TxOptions{
		Isolation:   orm.IsolationReadCommitted,
		MaxAttempts: 3,
	}, func(tx orm.DB) error {
		fresh, gerr := orm.GetForUpdate[db.Session](tx, sessionID)
		if gerr != nil {
			return &httpError{code: http.StatusForbidden, msg: "session not found"}
		}
		if fresh.OrgID != orgID || fresh.WalletID != walletID {
			return &httpError{code: http.StatusForbidden, msg: "session mismatch"}
		}
		if fresh.Status == "revoked" {
			return &httpError{code: http.StatusForbidden, msg: "session revoked"}
		}
		if time.Now().After(fresh.ExpiresAt) {
			return &httpError{code: http.StatusForbidden, msg: "session expired"}
		}
		if fresh.GrantedTo != "" && fresh.GrantedTo != principal {
			return &httpError{code: http.StatusForbidden, msg: "session granted to different principal"}
		}
		// F25: sign scope required for sign/settlement.
		scopeOK := false
		for _, scope := range fresh.Scopes {
			if scope == "sign" {
				scopeOK = true
				break
			}
		}
		if !scopeOK {
			return &httpError{code: http.StatusForbidden, msg: "session does not grant sign scope"}
		}

		if fresh.OperationLimit != nil && fresh.OperationsUsed >= *fresh.OperationLimit {
			return &httpError{code: http.StatusForbidden, msg: "session operation limit reached"}
		}

		newAccum := fresh.ValueAccum
		if fresh.ValueLimit != nil && value != "" {
			limit, ok := new(big.Int).SetString(*fresh.ValueLimit, 10)
			used, _ := new(big.Int).SetString(fresh.ValueAccum, 10)
			if used == nil {
				used = new(big.Int)
			}
			amt, aok := new(big.Int).SetString(value, 10)
			if !ok || !aok {
				return &httpError{code: http.StatusForbidden, msg: "session value accounting error"}
			}
			next := new(big.Int).Add(used, amt)
			if next.Cmp(limit) > 0 {
				return &httpError{code: http.StatusForbidden, msg: "session value limit exceeded"}
			}
			newAccum = next.String()
		}

		fresh.OperationsUsed = fresh.OperationsUsed + 1
		fresh.ValueAccum = newAccum
		if uerr := fresh.Update(); uerr != nil {
			return uerr
		}
		sess = fresh
		return nil
	})
	if err != nil {
		if herr, ok := err.(*httpError); ok {
			return nil, herr
		}
		return nil, &httpError{code: http.StatusConflict, msg: "session busy, retry"}
	}
	return sess, nil
}

type httpError struct {
	code int
	msg  string
}

func (e *httpError) Error() string { return e.msg }

// writeHTTPError renders an *httpError onto the response writer. Passthrough
// for plain errors maps to 500.
func writeHTTPError(w http.ResponseWriter, err error) {
	if e, ok := err.(*httpError); ok {
		writeError(w, e.code, e.msg)
		return
	}
	writeError(w, http.StatusInternalServerError, err.Error())
}

// startSessionReaper periodically marks expired sessions as expired.
// This is the background sweep mandated by the MPC spec. F21 — loop
// pagination until no more results come back; surface Update errors via
// log so silent failures do not accumulate expired-but-still-active
// sessions in the DB.
func (s *Server) startSessionReaper(ctx context.Context, interval time.Duration) {
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.reapExpiredSessions(ctx)
			}
		}
	}()
}

// reapExpiredSessions is exported-shaped (lowercase only for package-private
// tests) so the test harness can drive a single pass without waiting for the
// ticker.
func (s *Server) reapExpiredSessions(ctx context.Context) int {
	const pageSize = 500
	now := time.Now()
	reaped := 0
	for {
		sessions, err := orm.TypedQuery[db.Session](s.db.ORM).
			Filter("status=", "active").
			Limit(pageSize).
			GetAll(ctx)
		if err != nil || len(sessions) == 0 {
			return reaped
		}
		pageReaped := 0
		for _, sess := range sessions {
			if now.After(sess.ExpiresAt) {
				sess.Status = "expired"
				if uerr := sess.Update(); uerr != nil {
					// Log-and-continue: one bad row must not block the sweep.
					s.logSessionReapError(sess.Id(), uerr)
					continue
				}
				pageReaped++
				reaped++
			}
		}
		// If this page produced no reaped sessions, stop — the remaining
		// active sessions are all in the future. Prevents infinite loop when
		// pageSize sessions are all still valid.
		if pageReaped == 0 {
			return reaped
		}
	}
}

func (s *Server) logSessionReapError(id string, err error) {
	// Best-effort audit of reap failures; do not block the sweep.
	e := orm.New[db.AuditEntry](s.db.ORM)
	e.Action = "session.reap.error"
	resType := "session"
	e.ResourceType = &resType
	e.ResourceID = &id
	msg := err.Error()
	e.Details = []byte(`{"error":` + jsonString(msg) + `}`)
	_ = e.Create()
}

// jsonString escapes a string for embedding in a JSON document.
func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
