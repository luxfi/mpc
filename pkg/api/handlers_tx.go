package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

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
	var walletOrgID string
	err := s.db.Pool.QueryRow(r.Context(),
		`SELECT org_id FROM wallets WHERE id = $1`, req.WalletID).Scan(&walletOrgID)
	if err != nil || walletOrgID != orgID {
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

	var tx db.Transaction
	err = s.db.Pool.QueryRow(r.Context(),
		`INSERT INTO transactions (org_id, wallet_id, tx_type, chain, to_address, amount, token, raw_tx, status, initiated_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		 RETURNING id, org_id, wallet_id, tx_type, chain, to_address, amount, token,
		 tx_hash, status, initiated_by, created_at`,
		orgID, req.WalletID, req.TxType, req.Chain, req.ToAddress, req.Amount,
		nilIfEmpty(req.Token), rawTx, status, userID).
		Scan(&tx.ID, &tx.OrgID, &tx.WalletID, &tx.TxType, &tx.Chain,
			&tx.ToAddress, &tx.Amount, &tx.Token, &tx.TxHash, &tx.Status,
			&tx.InitiatedBy, &tx.CreatedAt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create transaction: "+err.Error())
		return
	}

	if status == "approved" {
		go s.signAndBroadcast(tx.ID, orgID)
	}

	s.fireWebhook(r.Context(), orgID, "tx.pending", tx)
	writeJSON(w, http.StatusCreated, tx)
}

func (s *Server) handleListTransactions(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	statusFilter := r.URL.Query().Get("status")
	chain := r.URL.Query().Get("chain")

	query := `SELECT id, org_id, wallet_id, tx_type, chain, to_address, amount, token,
	          tx_hash, status, initiated_by, created_at, signed_at, broadcast_at
	          FROM transactions WHERE org_id = $1`
	args := []interface{}{orgID}
	idx := 2

	if statusFilter != "" {
		query += " AND status = $" + strconv.Itoa(idx)
		args = append(args, statusFilter)
		idx++
	}
	if chain != "" {
		query += " AND chain = $" + strconv.Itoa(idx)
		args = append(args, chain)
		idx++
	}
	query += " ORDER BY created_at DESC LIMIT 100"

	rows, err := s.db.Pool.Query(r.Context(), query, args...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	var txs []db.Transaction
	for rows.Next() {
		var tx db.Transaction
		if err := rows.Scan(&tx.ID, &tx.OrgID, &tx.WalletID, &tx.TxType, &tx.Chain,
			&tx.ToAddress, &tx.Amount, &tx.Token, &tx.TxHash, &tx.Status,
			&tx.InitiatedBy, &tx.CreatedAt, &tx.SignedAt, &tx.BroadcastAt); err != nil {
			continue
		}
		txs = append(txs, tx)
	}
	if txs == nil {
		txs = []db.Transaction{}
	}
	writeJSON(w, http.StatusOK, txs)
}

func (s *Server) handleGetTransaction(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	txID := urlParam(r, "id")

	var tx db.Transaction
	err := s.db.Pool.QueryRow(r.Context(),
		`SELECT id, org_id, wallet_id, tx_type, chain, to_address, amount, token,
		        tx_hash, signature_r, signature_s, signature_eddsa,
		        status, initiated_by, approved_by, rejected_by, rejection_reason,
		        created_at, signed_at, broadcast_at
		 FROM transactions WHERE id = $1 AND org_id = $2`, txID, orgID).
		Scan(&tx.ID, &tx.OrgID, &tx.WalletID, &tx.TxType, &tx.Chain,
			&tx.ToAddress, &tx.Amount, &tx.Token, &tx.TxHash,
			&tx.SignatureR, &tx.SignatureS, &tx.SignatureEdDSA,
			&tx.Status, &tx.InitiatedBy, &tx.ApprovedBy, &tx.RejectedBy, &tx.RejectionReason,
			&tx.CreatedAt, &tx.SignedAt, &tx.BroadcastAt)
	if err != nil {
		writeError(w, http.StatusNotFound, "transaction not found")
		return
	}

	writeJSON(w, http.StatusOK, tx)
}

func (s *Server) handleApproveTransaction(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	userID := getUserID(r.Context())
	txID := urlParam(r, "id")

	var status string
	var approvedBy []string
	err := s.db.Pool.QueryRow(r.Context(),
		`UPDATE transactions
		 SET approved_by = array_append(approved_by, $1::uuid)
		 WHERE id = $2 AND org_id = $3 AND status = 'pending_approval'
		 RETURNING status, approved_by`, userID, txID, orgID).
		Scan(&status, &approvedBy)
	if err != nil {
		writeError(w, http.StatusNotFound, "transaction not found or not pending approval")
		return
	}

	policies, _ := s.loadPolicies(r.Context(), orgID, nil)
	requiredApprovers := 1
	for _, p := range policies {
		if p.RequiredApprovers > requiredApprovers {
			requiredApprovers = p.RequiredApprovers
		}
	}

	if len(approvedBy) >= requiredApprovers {
		s.db.Pool.Exec(r.Context(),
			`UPDATE transactions SET status = 'approved' WHERE id = $1`, txID)
		go s.signAndBroadcast(txID, orgID)
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

	tag, err := s.db.Pool.Exec(r.Context(),
		`UPDATE transactions SET status = 'rejected', rejected_by = $1, rejection_reason = $2
		 WHERE id = $3 AND org_id = $4 AND status = 'pending_approval'`,
		userID, req.Reason, txID, orgID)
	if err != nil || tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "transaction not found or not pending")
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

	var walletDBID string
	var rawTx []byte
	err := s.db.Pool.QueryRow(ctx,
		`SELECT wallet_id, raw_tx FROM transactions WHERE id = $1`, txID).
		Scan(&walletDBID, &rawTx)
	if err != nil {
		return
	}

	var mpcWalletID string
	err = s.db.Pool.QueryRow(ctx,
		`SELECT wallet_id FROM wallets WHERE id = $1`, walletDBID).
		Scan(&mpcWalletID)
	if err != nil {
		return
	}

	s.db.Pool.Exec(ctx, `UPDATE transactions SET status = 'signing' WHERE id = $1`, txID)

	result, err := s.mpc.TriggerSign(mpcWalletID, rawTx)
	if err != nil {
		s.db.Pool.Exec(ctx, `UPDATE transactions SET status = 'failed' WHERE id = $1`, txID)
		s.fireWebhook(ctx, orgID, "tx.failed", map[string]string{"tx_id": txID, "error": err.Error()})
		return
	}

	now := time.Now()
	s.db.Pool.Exec(ctx,
		`UPDATE transactions SET status = 'signed', signature_r = $1, signature_s = $2,
		 signature_eddsa = $3, signed_at = $4 WHERE id = $5`,
		result.R, result.S, result.Signature, now, txID)

	s.fireWebhook(ctx, orgID, "tx.signed", map[string]string{"tx_id": txID})
}
