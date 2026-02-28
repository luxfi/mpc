package api

import (
	"context"
	"time"

	"github.com/luxfi/mpc/pkg/logger"
)

// StartScheduler runs a background goroutine that processes due subscriptions.
func (s *Server) StartScheduler(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	go func() {
		for {
			select {
			case <-ctx.Done():
				ticker.Stop()
				return
			case <-ticker.C:
				s.processDueSubscriptions(ctx)
			}
		}
	}()
}

func (s *Server) processDueSubscriptions(ctx context.Context) {
	rows, err := s.db.Pool.Query(ctx,
		`SELECT id, org_id, wallet_id, recipient_address, chain, token, amount,
		        interval, max_retries, retry_count, require_balance
		 FROM subscriptions
		 WHERE status = 'active' AND next_payment_at <= NOW()
		 LIMIT 50`)
	if err != nil {
		logger.Error("scheduler: failed to query due subscriptions", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var (
			id, orgID, walletID, recipientAddress, chain, amount, interval string
			token                                                          *string
			maxRetries, retryCount                                         int
			requireBalance                                                 bool
		)
		if err := rows.Scan(&id, &orgID, &walletID, &recipientAddress, &chain,
			&token, &amount, &interval, &maxRetries, &retryCount, &requireBalance); err != nil {
			continue
		}

		s.processSubscriptionPayment(ctx, id, orgID, walletID, recipientAddress,
			chain, token, amount, interval, maxRetries, retryCount, requireBalance)
	}
}

func (s *Server) processSubscriptionPayment(ctx context.Context,
	subID, orgID, walletID, recipientAddress, chain string,
	token *string, amount, interval string,
	maxRetries, retryCount int, requireBalance bool) {

	tokenStr := ""
	if token != nil {
		tokenStr = *token
	}

	// Create transaction
	var txID string
	err := s.db.Pool.QueryRow(ctx,
		`INSERT INTO transactions (org_id, wallet_id, tx_type, chain, to_address, amount, token, status)
		 VALUES ($1, $2, 'subscription_payment', $3, $4, $5, $6, 'approved')
		 RETURNING id`,
		orgID, walletID, chain, recipientAddress, amount, nilIfEmpty(tokenStr)).Scan(&txID)
	if err != nil {
		logger.Error("scheduler: failed to create payment tx", err)
		// Retry logic
		if retryCount < maxRetries {
			s.db.Pool.Exec(ctx,
				`UPDATE subscriptions SET retry_count = retry_count + 1,
				 next_payment_at = NOW() + interval '1 hour'
				 WHERE id = $1`, subID)
			s.fireWebhook(ctx, orgID, "subscription.insufficient_funds", map[string]string{"subscription_id": subID})
		} else {
			s.db.Pool.Exec(ctx,
				`UPDATE subscriptions SET status = 'failed' WHERE id = $1`, subID)
			s.fireWebhook(ctx, orgID, "subscription.failed", map[string]string{"subscription_id": subID})
		}
		return
	}

	// Sign and broadcast
	s.signAndBroadcast(txID, orgID)

	// Advance next payment
	nextPayment := computeNextPayment(interval)
	now := time.Now()
	s.db.Pool.Exec(ctx,
		`UPDATE subscriptions SET
		 next_payment_at = $1, last_payment_at = $2, last_tx_id = $3, retry_count = 0
		 WHERE id = $4`, nextPayment, now, txID, subID)

	s.fireWebhook(ctx, orgID, "subscription.paid", map[string]string{
		"subscription_id": subID,
		"tx_id":           txID,
	})
}
