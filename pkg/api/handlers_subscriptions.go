package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/luxfi/mpc/pkg/db"
)

func (s *Server) handleListSubscriptions(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	rows, err := s.db.Pool.Query(r.Context(),
		`SELECT id, org_id, wallet_id, name, provider_name, recipient_address,
		        chain, token, amount, currency, interval,
		        next_payment_at, last_payment_at, last_tx_id,
		        status, max_retries, retry_count, require_balance,
		        created_by, created_at
		 FROM subscriptions WHERE org_id = $1 ORDER BY created_at DESC`, orgID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	var subs []db.Subscription
	for rows.Next() {
		var sub db.Subscription
		if err := rows.Scan(&sub.ID, &sub.OrgID, &sub.WalletID, &sub.Name,
			&sub.ProviderName, &sub.RecipientAddress, &sub.Chain, &sub.Token,
			&sub.Amount, &sub.Currency, &sub.Interval,
			&sub.NextPaymentAt, &sub.LastPaymentAt, &sub.LastTxID,
			&sub.Status, &sub.MaxRetries, &sub.RetryCount, &sub.RequireBalance,
			&sub.CreatedBy, &sub.CreatedAt); err != nil {
			continue
		}
		subs = append(subs, sub)
	}
	if subs == nil {
		subs = []db.Subscription{}
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

	var sub db.Subscription
	err := s.db.Pool.QueryRow(r.Context(),
		`INSERT INTO subscriptions (org_id, wallet_id, name, provider_name, recipient_address,
		 chain, token, amount, currency, interval, next_payment_at, require_balance, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		 RETURNING id, org_id, wallet_id, name, provider_name, recipient_address,
		 chain, token, amount, currency, interval,
		 next_payment_at, last_payment_at, last_tx_id,
		 status, max_retries, retry_count, require_balance, created_by, created_at`,
		orgID, req.WalletID, req.Name, req.ProviderName, req.RecipientAddress,
		req.Chain, req.Token, req.Amount, req.Currency, req.Interval,
		nextPayment, req.RequireBalance, userID).
		Scan(&sub.ID, &sub.OrgID, &sub.WalletID, &sub.Name,
			&sub.ProviderName, &sub.RecipientAddress, &sub.Chain, &sub.Token,
			&sub.Amount, &sub.Currency, &sub.Interval,
			&sub.NextPaymentAt, &sub.LastPaymentAt, &sub.LastTxID,
			&sub.Status, &sub.MaxRetries, &sub.RetryCount, &sub.RequireBalance,
			&sub.CreatedBy, &sub.CreatedAt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create subscription: "+err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, sub)
}

func (s *Server) handleGetSubscription(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	subID := urlParam(r, "id")

	var sub db.Subscription
	err := s.db.Pool.QueryRow(r.Context(),
		`SELECT id, org_id, wallet_id, name, provider_name, recipient_address,
		        chain, token, amount, currency, interval,
		        next_payment_at, last_payment_at, last_tx_id,
		        status, max_retries, retry_count, require_balance,
		        created_by, created_at
		 FROM subscriptions WHERE id = $1 AND org_id = $2`, subID, orgID).
		Scan(&sub.ID, &sub.OrgID, &sub.WalletID, &sub.Name,
			&sub.ProviderName, &sub.RecipientAddress, &sub.Chain, &sub.Token,
			&sub.Amount, &sub.Currency, &sub.Interval,
			&sub.NextPaymentAt, &sub.LastPaymentAt, &sub.LastTxID,
			&sub.Status, &sub.MaxRetries, &sub.RetryCount, &sub.RequireBalance,
			&sub.CreatedBy, &sub.CreatedAt)
	if err != nil {
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

	var sub db.Subscription
	err := s.db.Pool.QueryRow(r.Context(),
		`UPDATE subscriptions SET
		 status = COALESCE($1, status),
		 amount = COALESCE($2, amount)
		 WHERE id = $3 AND org_id = $4
		 RETURNING id, org_id, wallet_id, name, provider_name, recipient_address,
		 chain, token, amount, currency, interval,
		 next_payment_at, last_payment_at, last_tx_id,
		 status, max_retries, retry_count, require_balance, created_by, created_at`,
		req.Status, req.Amount, subID, orgID).
		Scan(&sub.ID, &sub.OrgID, &sub.WalletID, &sub.Name,
			&sub.ProviderName, &sub.RecipientAddress, &sub.Chain, &sub.Token,
			&sub.Amount, &sub.Currency, &sub.Interval,
			&sub.NextPaymentAt, &sub.LastPaymentAt, &sub.LastTxID,
			&sub.Status, &sub.MaxRetries, &sub.RetryCount, &sub.RequireBalance,
			&sub.CreatedBy, &sub.CreatedAt)
	if err != nil {
		writeError(w, http.StatusNotFound, "subscription not found")
		return
	}
	writeJSON(w, http.StatusOK, sub)
}

func (s *Server) handleDeleteSubscription(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	userID := getUserID(r.Context())
	subID := urlParam(r, "id")

	now := time.Now()
	tag, err := s.db.Pool.Exec(r.Context(),
		`UPDATE subscriptions SET status = 'cancelled', cancelled_by = $1, cancelled_at = $2
		 WHERE id = $3 AND org_id = $4 AND status != 'cancelled'`,
		userID, now, subID, orgID)
	if err != nil || tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "subscription not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handlePayNow(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	subID := urlParam(r, "id")

	var walletID, recipientAddress, chain, amount string
	var token *string
	err := s.db.Pool.QueryRow(r.Context(),
		`SELECT wallet_id, recipient_address, chain, amount, token
		 FROM subscriptions WHERE id = $1 AND org_id = $2 AND status = 'active'`,
		subID, orgID).Scan(&walletID, &recipientAddress, &chain, &amount, &token)
	if err != nil {
		writeError(w, http.StatusNotFound, "subscription not found or not active")
		return
	}

	// Create transaction for immediate payment
	var txID string
	tokenStr := ""
	if token != nil {
		tokenStr = *token
	}
	err = s.db.Pool.QueryRow(r.Context(),
		`INSERT INTO transactions (org_id, wallet_id, tx_type, chain, to_address, amount, token, status, initiated_by)
		 VALUES ($1, $2, 'subscription_payment', $3, $4, $5, $6, 'approved', $7)
		 RETURNING id`,
		orgID, walletID, chain, recipientAddress, amount, nilIfEmpty(tokenStr),
		getUserID(r.Context())).Scan(&txID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create payment transaction")
		return
	}

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
