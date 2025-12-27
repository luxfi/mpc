package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/hanzoai/orm"
	"github.com/luxfi/mpc/pkg/db"
)

func (s *Server) handleListSubscriptions(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	subs, err := orm.TypedQuery[db.Subscription](s.db.ORM).
		Filter("orgId =", orgID).
		Order("-createdAt").
		GetAll(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if subs == nil {
		subs = []*db.Subscription{}
	}
	writeJSON(w, http.StatusOK, subs)
}

func (s *Server) handleCreateSubscription(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	userID := getUserID(r.Context())

	var req struct {
		WalletID         string  `json:"wallet_id"`
		Name             string  `json:"name"`
		ProviderName     *string `json:"provider_name,omitempty"`
		RecipientAddress string  `json:"recipient_address"`
		Chain            string  `json:"chain"`
		Token            *string `json:"token,omitempty"`
		Amount           string  `json:"amount"`
		Currency         string  `json:"currency"`
		Interval         string  `json:"interval"`
		RequireBalance   bool    `json:"require_balance"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" || req.RecipientAddress == "" || req.Chain == "" || req.Amount == "" || req.Interval == "" {
		writeError(w, http.StatusBadRequest, "name, recipient_address, chain, amount, and interval are required")
		return
	}
	if req.Currency == "" {
		req.Currency = "USD"
	}

	nextPayment := computeNextPayment(req.Interval)
	walletID := req.WalletID

	sub := orm.New[db.Subscription](s.db.ORM)
	sub.OrgID = orgID
	sub.WalletID = &walletID
	sub.Name = req.Name
	sub.ProviderName = req.ProviderName
	sub.RecipientAddress = req.RecipientAddress
	sub.Chain = req.Chain
	sub.Token = req.Token
	sub.Amount = req.Amount
	sub.Currency = req.Currency
	sub.Interval = req.Interval
	sub.NextPaymentAt = nextPayment
	sub.RequireBalance = req.RequireBalance
	sub.Status = "active"
	sub.MaxRetries = 3
	sub.CreatedBy = nilIfEmpty(userID)
	if err := sub.Create(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create subscription: "+err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, sub)
}

func (s *Server) handleGetSubscription(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	subID := urlParam(r, "id")

	sub, err := orm.Get[db.Subscription](s.db.ORM, subID)
	if err != nil || sub.OrgID != orgID {
		writeError(w, http.StatusNotFound, "subscription not found")
		return
	}
	writeJSON(w, http.StatusOK, sub)
}

func (s *Server) handleUpdateSubscription(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	subID := urlParam(r, "id")

	var req struct {
		Status *string `json:"status,omitempty"`
		Amount *string `json:"amount,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	sub, err := orm.Get[db.Subscription](s.db.ORM, subID)
	if err != nil || sub.OrgID != orgID {
		writeError(w, http.StatusNotFound, "subscription not found")
		return
	}

	if req.Status != nil {
		sub.Status = *req.Status
	}
	if req.Amount != nil {
		sub.Amount = *req.Amount
	}
	if err := sub.Update(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update subscription")
		return
	}
	writeJSON(w, http.StatusOK, sub)
}

func (s *Server) handleDeleteSubscription(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	userID := getUserID(r.Context())
	subID := urlParam(r, "id")

	sub, err := orm.Get[db.Subscription](s.db.ORM, subID)
	if err != nil || sub.OrgID != orgID || sub.Status == "cancelled" {
		writeError(w, http.StatusNotFound, "subscription not found")
		return
	}

	now := time.Now()
	sub.Status = "cancelled"
	sub.CancelledBy = nilIfEmpty(userID)
	sub.CancelledAt = &now
	if err := sub.Update(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to cancel subscription")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handlePayNow(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	userID := getUserID(r.Context())
	subID := urlParam(r, "id")

	sub, err := orm.Get[db.Subscription](s.db.ORM, subID)
	if err != nil || sub.OrgID != orgID || sub.Status != "active" {
		writeError(w, http.StatusNotFound, "subscription not found or not active")
		return
	}

	walletID := ""
	if sub.WalletID != nil {
		walletID = *sub.WalletID
	}

	tx := orm.New[db.Transaction](s.db.ORM)
	tx.OrgID = orgID
	if walletID != "" {
		tx.WalletID = &walletID
	}
	tx.TxType = "subscription_payment"
	tx.Chain = sub.Chain
	tx.ToAddress = nilIfEmpty(sub.RecipientAddress)
	tx.Amount = nilIfEmpty(sub.Amount)
	tx.Token = sub.Token
	tx.Status = "approved"
	tx.InitiatedBy = nilIfEmpty(userID)
	if err := tx.Create(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create payment transaction")
		return
	}

	txID := tx.Id()
	go s.signAndBroadcast(txID, orgID)

	writeJSON(w, http.StatusOK, map[string]string{
		"status": "payment_initiated",
		"tx_id":  txID,
	})
}

func computeNextPayment(interval string) time.Time {
	now := time.Now()
	switch interval {
	case "daily":
		return now.Add(24 * time.Hour)
	case "weekly":
		return now.Add(7 * 24 * time.Hour)
	case "monthly":
		return now.AddDate(0, 1, 0)
	case "yearly":
		return now.AddDate(1, 0, 0)
	default:
		return now.Add(30 * 24 * time.Hour)
	}
}
