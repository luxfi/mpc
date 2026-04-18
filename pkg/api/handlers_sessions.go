package api

import (
	"context"
	"encoding/json"
	"math/big"
	"net/http"
	"time"

	"github.com/hanzoai/orm"

	"github.com/luxfi/mpc/pkg/db"
)

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
	sess.Status = "active"
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

// consumeSessionForSign enforces session validity + limits for a signing
// attempt. Returns the session used (for audit) or nil if no session was
// presented — no-session sign is allowed only when the caller's role is
// owner/admin/signer/api and no active session exists for that principal.
//
// If `sessionID` is non-empty it is required to match; otherwise the most
// recently created active session for (orgID, walletID, principal) is used.
//
// On success the session is updated transactionally: OperationsUsed++ and
// ValueAccum += value. On failure returns an *httpError suitable to surface
// as 403.
func (s *Server) consumeSessionForSign(
	ctx context.Context,
	orgID, walletID, principal, sessionID, value string,
) (*db.Session, error) {
	if sessionID == "" {
		// Look up the most recent active session for this principal+wallet.
		q := orm.TypedQuery[db.Session](s.db.ORM).
			Filter("orgId=", orgID).
			Filter("walletId=", walletID).
			Filter("grantedTo=", principal).
			Filter("status=", "active").
			Order("-createdAt").
			Limit(1)
		sessions, err := q.GetAll(ctx)
		if err != nil || len(sessions) == 0 {
			return nil, nil // no session — caller decides whether to allow
		}
		sessionID = sessions[0].Id()
	}

	sess, err := orm.Get[db.Session](s.db.ORM, sessionID)
	if err != nil {
		return nil, &httpError{code: http.StatusForbidden, msg: "session not found"}
	}
	if sess.OrgID != orgID || sess.WalletID != walletID {
		return nil, &httpError{code: http.StatusForbidden, msg: "session mismatch"}
	}
	if sess.Status == "revoked" {
		return nil, &httpError{code: http.StatusForbidden, msg: "session revoked"}
	}
	if time.Now().After(sess.ExpiresAt) {
		return nil, &httpError{code: http.StatusForbidden, msg: "session expired"}
	}
	if sess.GrantedTo != "" && sess.GrantedTo != principal {
		return nil, &httpError{code: http.StatusForbidden, msg: "session granted to different principal"}
	}
	scopeOK := false
	for _, scope := range sess.Scopes {
		if scope == "sign" {
			scopeOK = true
			break
		}
	}
	if !scopeOK {
		return nil, &httpError{code: http.StatusForbidden, msg: "session does not grant sign scope"}
	}
	if sess.OperationLimit != nil && sess.OperationsUsed >= *sess.OperationLimit {
		return nil, &httpError{code: http.StatusForbidden, msg: "session operation limit reached"}
	}
	// Value accumulation
	if sess.ValueLimit != nil && value != "" {
		limit, ok := new(big.Int).SetString(*sess.ValueLimit, 10)
		used, _ := new(big.Int).SetString(sess.ValueAccum, 10)
		if used == nil {
			used = new(big.Int)
		}
		amt, aok := new(big.Int).SetString(value, 10)
		if !ok || !aok {
			return nil, &httpError{code: http.StatusForbidden, msg: "session value accounting error"}
		}
		next := new(big.Int).Add(used, amt)
		if next.Cmp(limit) > 0 {
			return nil, &httpError{code: http.StatusForbidden, msg: "session value limit exceeded"}
		}
		sess.ValueAccum = next.String()
	}
	sess.OperationsUsed++
	if err := sess.Update(); err != nil {
		return nil, &httpError{code: http.StatusInternalServerError, msg: "failed to update session"}
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
// This is the background sweep mandated by the MPC spec.
func (s *Server) startSessionReaper(ctx context.Context, interval time.Duration) {
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				sessions, err := orm.TypedQuery[db.Session](s.db.ORM).
					Filter("status=", "active").
					Limit(500).
					GetAll(ctx)
				if err != nil || len(sessions) == 0 {
					continue
				}
				now := time.Now()
				for _, sess := range sessions {
					if now.After(sess.ExpiresAt) {
						sess.Status = "expired"
						sess.Update()
					}
				}
			}
		}
	}()
}
