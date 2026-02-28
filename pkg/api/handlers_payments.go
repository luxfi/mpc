package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/luxfi/mpc/pkg/db"
)

func (s *Server) handleCreatePaymentRequest(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())

	var req struct {
		WalletID         *string `json:"wallet_id,omitempty"`
		MerchantName     *string `json:"merchant_name,omitempty"`
		RecipientAddress string  `json:"recipient_address"`
		Chain            string  `json:"chain"`
		Token            *string `json:"token,omitempty"`
		Amount           string  `json:"amount"`
		Memo             *string `json:"memo,omitempty"`
		ExpiresInHours   int     `json:"expires_in_hours,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.RecipientAddress == "" || req.Chain == "" || req.Amount == "" {
		writeError(w, http.StatusBadRequest, "recipient_address, chain, and amount are required")
		return
	}

	token := generateRequestToken()
	var expiresAt *time.Time
	if req.ExpiresInHours > 0 {
		t := time.Now().Add(time.Duration(req.ExpiresInHours) * time.Hour)
		expiresAt = &t
	}

	var pr db.PaymentRequest
	err := s.db.Pool.QueryRow(r.Context(),
		`INSERT INTO payment_requests (org_id, wallet_id, request_token, merchant_name,
		 recipient_address, chain, token, amount, memo, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		 RETURNING id, org_id, wallet_id, request_token, merchant_name,
		 recipient_address, chain, token, amount, memo, status, expires_at, created_at`,
		orgID, req.WalletID, token, req.MerchantName,
		req.RecipientAddress, req.Chain, req.Token, req.Amount, req.Memo, expiresAt).
		Scan(&pr.ID, &pr.OrgID, &pr.WalletID, &pr.RequestToken, &pr.MerchantName,
			&pr.RecipientAddress, &pr.Chain, &pr.Token, &pr.Amount, &pr.Memo,
			&pr.Status, &pr.ExpiresAt, &pr.CreatedAt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create payment request: "+err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"payment_request": pr,
		"payment_url":     "https://mpc.lux.network/pay/" + token,
	})
}

func (s *Server) handleListPaymentRequests(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	rows, err := s.db.Pool.Query(r.Context(),
		`SELECT id, org_id, wallet_id, request_token, merchant_name,
		        recipient_address, chain, token, amount, memo,
		        status, expires_at, paid_tx_id, created_at
		 FROM payment_requests WHERE org_id = $1 ORDER BY created_at DESC`, orgID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	var requests []db.PaymentRequest
	for rows.Next() {
		var pr db.PaymentRequest
		if err := rows.Scan(&pr.ID, &pr.OrgID, &pr.WalletID, &pr.RequestToken,
			&pr.MerchantName, &pr.RecipientAddress, &pr.Chain, &pr.Token,
			&pr.Amount, &pr.Memo, &pr.Status, &pr.ExpiresAt, &pr.PaidTxID,
			&pr.CreatedAt); err != nil {
			continue
		}
		requests = append(requests, pr)
	}
	if requests == nil {
		requests = []db.PaymentRequest{}
	}
	writeJSON(w, http.StatusOK, requests)
}

func (s *Server) handleGetPaymentRequest(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	prID := urlParam(r, "id")

	var pr db.PaymentRequest
	err := s.db.Pool.QueryRow(r.Context(),
		`SELECT id, org_id, wallet_id, request_token, merchant_name,
		        recipient_address, chain, token, amount, memo,
		        status, expires_at, paid_tx_id, created_at
		 FROM payment_requests WHERE id = $1 AND org_id = $2`, prID, orgID).
		Scan(&pr.ID, &pr.OrgID, &pr.WalletID, &pr.RequestToken,
			&pr.MerchantName, &pr.RecipientAddress, &pr.Chain, &pr.Token,
			&pr.Amount, &pr.Memo, &pr.Status, &pr.ExpiresAt, &pr.PaidTxID,
			&pr.CreatedAt)
	if err != nil {
		writeError(w, http.StatusNotFound, "payment request not found")
		return
	}
	writeJSON(w, http.StatusOK, pr)
}

func (s *Server) handlePayPaymentRequest(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	prID := urlParam(r, "id")

	var req struct {
		WalletID string `json:"wallet_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var pr db.PaymentRequest
	err := s.db.Pool.QueryRow(r.Context(),
		`SELECT id, recipient_address, chain, token, amount, status, expires_at
		 FROM payment_requests WHERE id = $1 AND org_id = $2`, prID, orgID).
		Scan(&pr.ID, &pr.RecipientAddress, &pr.Chain, &pr.Token, &pr.Amount,
			&pr.Status, &pr.ExpiresAt)
	if err != nil {
		writeError(w, http.StatusNotFound, "payment request not found")
		return
	}
	if pr.Status != "pending" {
		writeError(w, http.StatusBadRequest, "payment request is not pending")
		return
	}
	if pr.ExpiresAt != nil && pr.ExpiresAt.Before(time.Now()) {
		writeError(w, http.StatusBadRequest, "payment request has expired")
		return
	}

	tokenStr := ""
	if pr.Token != nil {
		tokenStr = *pr.Token
	}

	var txID string
	err = s.db.Pool.QueryRow(r.Context(),
		`INSERT INTO transactions (org_id, wallet_id, tx_type, chain, to_address, amount, token, status, initiated_by)
		 VALUES ($1, $2, 'payment', $3, $4, $5, $6, 'approved', $7)
		 RETURNING id`,
		orgID, req.WalletID, pr.Chain, pr.RecipientAddress, pr.Amount,
		nilIfEmpty(tokenStr), getUserID(r.Context())).Scan(&txID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create transaction")
		return
	}

	s.db.Pool.Exec(r.Context(),
		`UPDATE payment_requests SET status = 'paid', paid_tx_id = $1 WHERE id = $2`,
		txID, prID)

	go s.signAndBroadcast(txID, orgID)

	writeJSON(w, http.StatusOK, map[string]string{
		"status": "payment_initiated",
		"tx_id":  txID,
	})
}

// handlePublicPay serves the public payment page (no auth required)
func (s *Server) handlePublicPay(w http.ResponseWriter, r *http.Request) {
	token := urlParam(r, "token")

	var pr db.PaymentRequest
	err := s.db.Pool.QueryRow(r.Context(),
		`SELECT id, merchant_name, recipient_address, chain, token, amount, memo,
		        status, expires_at, created_at
		 FROM payment_requests WHERE request_token = $1`, token).
		Scan(&pr.ID, &pr.MerchantName, &pr.RecipientAddress, &pr.Chain,
			&pr.Token, &pr.Amount, &pr.Memo, &pr.Status, &pr.ExpiresAt, &pr.CreatedAt)
	if err != nil {
		writeError(w, http.StatusNotFound, "payment request not found")
		return
	}

	if pr.Status != "pending" {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status":  pr.Status,
			"message": "this payment request is no longer active",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"merchant_name":     pr.MerchantName,
		"recipient_address": pr.RecipientAddress,
		"chain":             pr.Chain,
		"token":             pr.Token,
		"amount":            pr.Amount,
		"memo":              pr.Memo,
		"expires_at":        pr.ExpiresAt,
	})
}

func generateRequestToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
