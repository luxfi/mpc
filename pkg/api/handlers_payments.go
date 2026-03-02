package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/hanzoai/orm"
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

	pr := orm.New[db.PaymentRequest](s.db.ORM)
	pr.OrgID = orgID
	pr.WalletID = req.WalletID
	pr.RequestToken = token
	pr.MerchantName = req.MerchantName
	pr.RecipientAddress = req.RecipientAddress
	pr.Chain = req.Chain
	pr.Token = req.Token
	pr.Amount = req.Amount
	pr.Memo = req.Memo
	pr.Status = "pending"
	pr.ExpiresAt = expiresAt
	if err := pr.Create(); err != nil {
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
	requests, err := orm.TypedQuery[db.PaymentRequest](s.db.ORM).
		Filter("orgId=", orgID).
		Order("-createdAt").
		GetAll(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if requests == nil {
		requests = []*db.PaymentRequest{}
	}
	writeJSON(w, http.StatusOK, requests)
}

func (s *Server) handleGetPaymentRequest(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	prID := urlParam(r, "id")

	pr, err := orm.Get[db.PaymentRequest](s.db.ORM, prID)
	if err != nil || pr.OrgID != orgID {
		writeError(w, http.StatusNotFound, "payment request not found")
		return
	}
	writeJSON(w, http.StatusOK, pr)
}

func (s *Server) handlePayPaymentRequest(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	userID := getUserID(r.Context())
	prID := urlParam(r, "id")

	var req struct {
		WalletID string `json:"wallet_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	pr, err := orm.Get[db.PaymentRequest](s.db.ORM, prID)
	if err != nil || pr.OrgID != orgID {
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

	walletID := req.WalletID
	tx := orm.New[db.Transaction](s.db.ORM)
	tx.OrgID = orgID
	tx.WalletID = &walletID
	tx.TxType = "payment"
	tx.Chain = pr.Chain
	tx.ToAddress = nilIfEmpty(pr.RecipientAddress)
	tx.Amount = nilIfEmpty(pr.Amount)
	tx.Token = pr.Token
	tx.Status = "approved"
	tx.InitiatedBy = nilIfEmpty(userID)
	if err := tx.Create(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create transaction")
		return
	}

	txID := tx.Id()
	paid := "paid"
	pr.Status = paid
	pr.PaidTxID = &txID
	pr.Update()

	go s.signAndBroadcast(txID, orgID)

	writeJSON(w, http.StatusOK, map[string]string{
		"status": "payment_initiated",
		"tx_id":  txID,
	})
}

// handlePublicPay serves the public payment page (no auth required)
func (s *Server) handlePublicPay(w http.ResponseWriter, r *http.Request) {
	token := urlParam(r, "token")

	pr, err := orm.TypedQuery[db.PaymentRequest](s.db.ORM).
		Filter("requestToken=", token).
		First()
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
