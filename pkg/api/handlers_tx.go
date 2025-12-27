package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/hanzoai/orm"
	"github.com/luxfi/mpc/pkg/db"
)

func (s *Server) handleCreateTransaction(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	userID := getUserID(r.Context())

	var req struct {
		WalletID  string `json:"wallet_id"`
		TxType    string `json:"tx_type"`
		Chain     string `json:"chain"`
		ToAddress string `json:"to_address"`
		Amount    string `json:"amount"`
		Token     string `json:"token,omitempty"`
		RawTx     string `json:"raw_tx,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.WalletID == "" || req.Chain == "" || req.TxType == "" {
		writeError(w, http.StatusBadRequest, "wallet_id, tx_type, and chain are required")
		return
	}

	// Verify wallet
	wallet, err := orm.Get[db.Wallet](s.db.ORM, req.WalletID)
	if err != nil || wallet.OrgID != orgID {
		writeError(w, http.StatusNotFound, "wallet not found")
		return
	}

	// Run policy engine
	policies, err := s.loadPolicies(r.Context(), orgID, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load policies")
		return
	}

	decision := evaluateTransaction(req.Amount, req.Chain, req.ToAddress, policies)

	status := "pending_approval"
	if decision.Action == "approve" {
		status = "approved"
	} else if decision.Action == "deny" {
		writeError(w, http.StatusForbidden, "transaction denied by policy: "+decision.Reason)
		return
	}

	var rawTx []byte
	if req.RawTx != "" {
		rawTx, _ = hex.DecodeString(req.RawTx)
	}

	walletID := req.WalletID
	tx := orm.New[db.Transaction](s.db.ORM)
	tx.OrgID = orgID
	tx.WalletID = &walletID
	tx.TxType = req.TxType
	tx.Chain = req.Chain
	tx.ToAddress = nilIfEmpty(req.ToAddress)
	tx.Amount = nilIfEmpty(req.Amount)
	tx.Token = nilIfEmpty(req.Token)
	tx.RawTx = rawTx
	tx.Status = status
	tx.InitiatedBy = nilIfEmpty(userID)
	if err := tx.Create(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create transaction: "+err.Error())
		return
	}

	txID := tx.Id()
	if status == "approved" {
		go s.signAndBroadcast(txID, orgID)
	}

	s.fireWebhook(r.Context(), orgID, "tx.pending", tx)
	writeJSON(w, http.StatusCreated, tx)
}

func (s *Server) handleListTransactions(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	statusFilter := r.URL.Query().Get("status")
	chain := r.URL.Query().Get("chain")

	q := orm.TypedQuery[db.Transaction](s.db.ORM).
		Filter("orgId=", orgID).
		Order("-createdAt").
		Limit(100)

	if statusFilter != "" {
		q = q.Filter("status=", statusFilter)
	}
	if chain != "" {
		q = q.Filter("chain=", chain)
	}

	txs, err := q.GetAll(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if txs == nil {
		txs = []*db.Transaction{}
	}
	writeJSON(w, http.StatusOK, txs)
}

func (s *Server) handleGetTransaction(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	txID := urlParam(r, "id")

	tx, err := orm.Get[db.Transaction](s.db.ORM, txID)
	if err != nil || tx.OrgID != orgID {
		writeError(w, http.StatusNotFound, "transaction not found")
		return
	}

	writeJSON(w, http.StatusOK, tx)
}

func (s *Server) handleApproveTransaction(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	userID := getUserID(r.Context())
	txID := urlParam(r, "id")

	tx, err := orm.Get[db.Transaction](s.db.ORM, txID)
	if err != nil || tx.OrgID != orgID || tx.Status != "pending_approval" {
		writeError(w, http.StatusNotFound, "transaction not found or not pending approval")
		return
	}

	// Append approver
	tx.ApprovedBy = append(tx.ApprovedBy, userID)
	if err := tx.Update(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to approve transaction")
		return
	}

	policies, _ := s.loadPolicies(r.Context(), orgID, nil)
	requiredApprovers := 1
	for _, p := range policies {
		if p.RequiredApprovers > requiredApprovers {
			requiredApprovers = p.RequiredApprovers
		}
	}

	if len(tx.ApprovedBy) >= requiredApprovers {
		tx.Status = "approved"
		if err := tx.Update(); err == nil {
			go s.signAndBroadcast(txID, orgID)
		}
	}

	s.fireWebhook(r.Context(), orgID, "tx.approved", map[string]string{
		"tx_id":       txID,
		"approved_by": userID,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "approved"})
}

func (s *Server) handleRejectTransaction(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	userID := getUserID(r.Context())
	txID := urlParam(r, "id")

	var req struct {
		Reason string `json:"reason"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	tx, err := orm.Get[db.Transaction](s.db.ORM, txID)
	if err != nil || tx.OrgID != orgID || tx.Status != "pending_approval" {
		writeError(w, http.StatusNotFound, "transaction not found or not pending")
		return
	}

	tx.Status = "rejected"
	tx.RejectedBy = nilIfEmpty(userID)
	tx.RejectionReason = nilIfEmpty(req.Reason)
	if err := tx.Update(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to reject transaction")
		return
	}

	s.fireWebhook(r.Context(), orgID, "tx.rejected", map[string]string{
		"tx_id":  txID,
		"reason": req.Reason,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "rejected"})
}

func (s *Server) signAndBroadcast(txID, orgID string) {
	ctx := context.Background()

	tx, err := orm.Get[db.Transaction](s.db.ORM, txID)
	if err != nil {
		return
	}

	if tx.WalletID == nil {
		return
	}

	wallet, err := orm.Get[db.Wallet](s.db.ORM, *tx.WalletID)
	if err != nil {
		return
	}

	tx.Status = "signing"
	tx.Update()

	result, err := s.mpc.TriggerSign(wallet.WalletID, tx.RawTx)
	if err != nil {
		tx.Status = "failed"
		tx.Update()
		s.fireWebhook(ctx, orgID, "tx.failed", map[string]string{"tx_id": txID, "error": err.Error()})
		return
	}

	now := time.Now()
	tx.Status = "signed"
	tx.SignatureR = nilIfEmpty(result.R)
	tx.SignatureS = nilIfEmpty(result.S)
	tx.SignatureEdDSA = nilIfEmpty(result.Signature)
	tx.SignedAt = &now
	tx.Update()

	s.fireWebhook(ctx, orgID, "tx.signed", map[string]string{"tx_id": txID})
}
