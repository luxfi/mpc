// Package api — approval endpoints.
//
// /v1/approval/* exposes the executive-approval flow defined in
// pkg/approval. Approvers (humans + programmatic keys) sign a
// CanonicalIntent OUT OF BAND from the MPC nodes. The bundle of
// approval signatures must accompany the intent before MPC quorum
// signing begins.
//
// One canonical surface — no `/api/` prefix, no v2.
package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/luxfi/mpc/pkg/approval"
)

// approvalSession tracks a pending approval bundle for a single intent.
// Sessions live in memory; on restart, callers must re-submit.
type approvalSession struct {
	ID         string
	OrgID      string
	IntentRaw  []byte // canonical intent bytes (caller-supplied)
	IntentHash [32]byte
	Approvers  []string
	Threshold  int
	CreatedAt  time.Time
	ExpiresAt  time.Time

	mu           sync.Mutex
	sigs         []approval.ApprovalSignature
	completed    bool
	rejected     bool
	rejectReason string
}

// approvalIntent satisfies approval.CanonicalIntent for the bytes the
// caller submitted. The digest is sha256(IntentRaw).
type approvalIntent struct {
	raw    []byte
	digest [32]byte
}

func (i *approvalIntent) Digest() [32]byte { return i.digest }
func (i *approvalIntent) Bytes() []byte    { return i.raw }

// ApprovalRegistry holds all approval providers + the orchestrator + the
// pending sessions. Wired into the Server in NewServer (see SetApproval).
type ApprovalRegistry struct {
	Providers    map[string]approval.ApprovalProvider
	Orchestrator *approval.Orchestrator

	mu       sync.Mutex
	sessions map[string]*approvalSession
}

// NewApprovalRegistry constructs an ApprovalRegistry from the given
// providers. Bindings (approver -> provider) are registered post-hoc with
// Orchestrator.Bind.
func NewApprovalRegistry(providers []approval.ApprovalProvider) *ApprovalRegistry {
	idx := make(map[string]approval.ApprovalProvider, len(providers))
	for _, p := range providers {
		idx[p.Provider()] = p
	}
	return &ApprovalRegistry{
		Providers:    idx,
		Orchestrator: approval.NewOrchestrator(providers),
		sessions:     make(map[string]*approvalSession),
	}
}

// SetApproval wires an ApprovalRegistry into the Server. Optional — when
// nil, /v1/approval/* returns 503.
func (s *Server) SetApproval(reg *ApprovalRegistry) {
	s.approval = reg
}

// approval handler entry points. Per task spec, mounted at /v1/approval/*
// (no /api/ prefix per house style).
//
// POST /v1/approval/intent              — submit intent for approval
// GET  /v1/approval/intent/{id}/status  — poll status
// POST /v1/approval/intent/{id}/cast    — single approver casts signature
// GET  /v1/approval/intent/{id}/bundle  — retrieve final bundle

type submitApprovalRequest struct {
	IntentBytes string   `json:"intent_bytes"` // base64 of canonical intent serialization
	Approvers   []string `json:"approvers"`    // required approver IDs
	Threshold   int      `json:"threshold"`
	TTLSeconds  int      `json:"ttl_seconds,omitempty"` // default 1800 (30m)
}

type submitApprovalResponse struct {
	SessionID  string    `json:"session_id"`
	IntentHash string    `json:"intent_hash"` // hex
	ExpiresAt  time.Time `json:"expires_at"`
}

func (s *Server) handleApprovalSubmit(w http.ResponseWriter, r *http.Request) {
	if s.approval == nil {
		writeError(w, http.StatusServiceUnavailable, "approval registry not configured")
		return
	}
	orgID := getOrgID(r.Context())
	if orgID == "" {
		writeError(w, http.StatusUnauthorized, "missing org")
		return
	}

	var req submitApprovalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	intentRaw, err := base64.StdEncoding.DecodeString(req.IntentBytes)
	if err != nil {
		// Tolerate raw URL-safe encoding too.
		if alt, alterr := base64.URLEncoding.DecodeString(req.IntentBytes); alterr == nil {
			intentRaw = alt
		} else {
			writeError(w, http.StatusBadRequest, "intent_bytes is not base64")
			return
		}
	}
	if len(intentRaw) == 0 {
		writeError(w, http.StatusBadRequest, "intent_bytes required")
		return
	}
	if len(req.Approvers) == 0 {
		writeError(w, http.StatusBadRequest, "approvers required")
		return
	}
	if req.Threshold <= 0 || req.Threshold > len(req.Approvers) {
		writeError(w, http.StatusBadRequest, "threshold must be > 0 and <= len(approvers)")
		return
	}
	ttl := 30 * time.Minute
	if req.TTLSeconds > 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}

	sess := &approvalSession{
		ID:         uuid.NewString(),
		OrgID:      orgID,
		IntentRaw:  intentRaw,
		IntentHash: sha256.Sum256(intentRaw),
		Approvers:  req.Approvers,
		Threshold:  req.Threshold,
		CreatedAt:  time.Now().UTC(),
		ExpiresAt:  time.Now().UTC().Add(ttl),
	}
	s.approval.mu.Lock()
	s.approval.sessions[sess.ID] = sess
	s.approval.mu.Unlock()

	writeJSON(w, http.StatusCreated, submitApprovalResponse{
		SessionID:  sess.ID,
		IntentHash: hex.EncodeToString(sess.IntentHash[:]),
		ExpiresAt:  sess.ExpiresAt,
	})
}

type approvalStatusResponse struct {
	SessionID    string                       `json:"session_id"`
	Status       string                       `json:"status"` // pending, approved, rejected, expired
	IntentHash   string                       `json:"intent_hash"`
	Threshold    int                          `json:"threshold"`
	Collected    int                          `json:"collected"`
	Approvers    []string                     `json:"approvers"`
	Approvals    []approval.ApprovalSignature `json:"approvals,omitempty"`
	RejectReason string                       `json:"reject_reason,omitempty"`
	ExpiresAt    time.Time                    `json:"expires_at"`
}

func (s *Server) handleApprovalStatus(w http.ResponseWriter, r *http.Request) {
	if s.approval == nil {
		writeError(w, http.StatusServiceUnavailable, "approval registry not configured")
		return
	}
	id := urlParam(r, "id")
	sess, ok := s.lookupApprovalSession(id, r.Context())
	if !ok {
		writeError(w, http.StatusNotFound, "approval session not found")
		return
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()

	status := "pending"
	switch {
	case sess.rejected:
		status = "rejected"
	case sess.completed:
		status = "approved"
	case time.Now().After(sess.ExpiresAt):
		status = "expired"
	}

	resp := approvalStatusResponse{
		SessionID:    sess.ID,
		Status:       status,
		IntentHash:   hex.EncodeToString(sess.IntentHash[:]),
		Threshold:    sess.Threshold,
		Collected:    len(sess.sigs),
		Approvers:    sess.Approvers,
		Approvals:    sess.sigs,
		RejectReason: sess.rejectReason,
		ExpiresAt:    sess.ExpiresAt,
	}
	writeJSON(w, http.StatusOK, resp)
}

type castApprovalRequest struct {
	ApproverID string `json:"approver_id"`
	Provider   string `json:"provider"`

	// One of the following payloads must be supplied, matching the named
	// provider. Other fields are ignored.

	// Generic: caller-produced ApprovalSignature (e.g. from Ledger Enterprise
	// already returned a complete signature). Server re-verifies before
	// accepting.
	Signature *approval.ApprovalSignature `json:"signature,omitempty"`

	// WebAuthn assertion bundle.
	WebAuthn *struct {
		ClientDataJSON string `json:"client_data_json"`
		AuthData       string `json:"auth_data"`
		Sig            string `json:"signature"`
	} `json:"webauthn,omitempty"`

	// Safe execution result (after on-chain Safe.execTransaction succeeded).
	Safe *struct {
		SafeTxHash string `json:"safe_tx_hash"` // 0x-prefixed hex
		ExecTxHash string `json:"exec_tx_hash"` // 0x-prefixed hex
	} `json:"safe,omitempty"`

	// Reject the approval (any approverID can reject; threshold collapses).
	Reject bool   `json:"reject,omitempty"`
	Reason string `json:"reason,omitempty"`
}

func (s *Server) handleApprovalCast(w http.ResponseWriter, r *http.Request) {
	if s.approval == nil {
		writeError(w, http.StatusServiceUnavailable, "approval registry not configured")
		return
	}
	id := urlParam(r, "id")
	sess, ok := s.lookupApprovalSession(id, r.Context())
	if !ok {
		writeError(w, http.StatusNotFound, "approval session not found")
		return
	}

	var req castApprovalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.ApproverID == "" || req.Provider == "" {
		writeError(w, http.StatusBadRequest, "approver_id and provider required")
		return
	}

	intent := &approvalIntent{raw: sess.IntentRaw, digest: sess.IntentHash}

	if req.Reject {
		sess.mu.Lock()
		sess.rejected = true
		if req.Reason != "" {
			sess.rejectReason = req.Reason
		}
		sess.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]string{"status": "rejected"})
		return
	}

	provider, ok := s.approval.Providers[req.Provider]
	if !ok {
		writeError(w, http.StatusBadRequest, "unknown provider: "+req.Provider)
		return
	}

	var sig approval.ApprovalSignature
	var verifyErr error
	switch req.Provider {
	case "webauthn":
		if req.WebAuthn == nil {
			writeError(w, http.StatusBadRequest, "webauthn assertion required for webauthn provider")
			return
		}
		wa, ok := provider.(*approval.WebAuthnProvider)
		if !ok {
			writeError(w, http.StatusInternalServerError, "webauthn provider type mismatch")
			return
		}
		// Issue a challenge bound to this intent, then complete.
		sessionID, _, err := wa.IssueChallenge(r.Context(), req.ApproverID, intent)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s, err := wa.SubmitAssertion(r.Context(), sessionID, req.WebAuthn.ClientDataJSON, req.WebAuthn.AuthData, req.WebAuthn.Sig)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		sig = s

	case "safe-multisig":
		if req.Safe == nil {
			writeError(w, http.StatusBadRequest, "safe execution result required for safe-multisig provider")
			return
		}
		safeTxHash, err := hexTo32(req.Safe.SafeTxHash)
		if err != nil {
			writeError(w, http.StatusBadRequest, "safe_tx_hash: "+err.Error())
			return
		}
		execTxHash, err := hexTo32(req.Safe.ExecTxHash)
		if err != nil {
			writeError(w, http.StatusBadRequest, "exec_tx_hash: "+err.Error())
			return
		}
		sp, ok := provider.(*approval.SafeMultisigProvider)
		if !ok {
			writeError(w, http.StatusInternalServerError, "safe provider type mismatch")
			return
		}
		sessionID, err := sp.IssueChallenge(r.Context(), req.ApproverID, intent)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s, err := sp.SubmitExecution(r.Context(), sessionID, safeTxHash, execTxHash)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		sig = s

	default:
		// Generic: the caller already executed ApproveIntent client-side
		// (e.g. Ledger Enterprise returned a complete signature). Verify
		// it server-side before accepting.
		if req.Signature == nil {
			// Attempt server-side ApproveIntent (works for in-memory
			// providers like local-dev / mldsa).
			signed, err := provider.ApproveIntent(r.Context(), req.ApproverID, intent)
			if err != nil {
				writeError(w, http.StatusBadRequest, "approve: "+err.Error())
				return
			}
			sig = signed
		} else {
			sig = *req.Signature
		}
	}

	ok, verifyErr = provider.VerifyApproval(r.Context(), intent, sig)
	if verifyErr != nil {
		writeError(w, http.StatusBadRequest, "verify: "+verifyErr.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusBadRequest, "signature verification failed")
		return
	}

	// Append + check threshold.
	sess.mu.Lock()
	defer sess.mu.Unlock()
	for _, existing := range sess.sigs {
		if existing.ApproverID == sig.ApproverID && existing.Provider == sig.Provider {
			writeError(w, http.StatusConflict, "approver already cast a signature")
			return
		}
	}
	sess.sigs = append(sess.sigs, sig)
	if len(sess.sigs) >= sess.Threshold {
		sess.completed = true
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    ifElseString(sess.completed, "approved", "pending"),
		"collected": len(sess.sigs),
		"threshold": sess.Threshold,
	})
}

func (s *Server) handleApprovalBundle(w http.ResponseWriter, r *http.Request) {
	if s.approval == nil {
		writeError(w, http.StatusServiceUnavailable, "approval registry not configured")
		return
	}
	id := urlParam(r, "id")
	sess, ok := s.lookupApprovalSession(id, r.Context())
	if !ok {
		writeError(w, http.StatusNotFound, "approval session not found")
		return
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if !sess.completed {
		writeError(w, http.StatusConflict, "approval threshold not yet met")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"session_id":  sess.ID,
		"intent_hash": hex.EncodeToString(sess.IntentHash[:]),
		"approvals":   sess.sigs,
	})
}

func (s *Server) lookupApprovalSession(id string, _ context.Context) (*approvalSession, bool) {
	if s.approval == nil {
		return nil, false
	}
	s.approval.mu.Lock()
	defer s.approval.mu.Unlock()
	sess, ok := s.approval.sessions[id]
	if !ok {
		return nil, false
	}
	return sess, true
}

// ifElseString is the obvious tiny helper that doesn't deserve its own file.
func ifElseString(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

func hexTo32(s string) ([32]byte, error) {
	var out [32]byte
	if len(s) == 66 && (s[:2] == "0x" || s[:2] == "0X") {
		s = s[2:]
	}
	if len(s) != 64 {
		return out, errors.New("hex must be 32 bytes (64 hex chars)")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("hex decode: %w", err)
	}
	copy(out[:], b)
	return out, nil
}
