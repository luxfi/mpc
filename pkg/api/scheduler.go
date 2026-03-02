package api

import (
	"context"
	"time"

	"github.com/hanzoai/orm"

	"github.com/luxfi/mpc/pkg/db"
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
	now := time.Now()
	subs, err := orm.TypedQuery[db.Subscription](s.db.ORM).
		Filter("status=", "active").
		Limit(50).
		GetAll(ctx)
	if err != nil {
		logger.Error("scheduler: failed to query due subscriptions", err)
		return
	}

	for _, sub := range subs {
		if sub.NextPaymentAt.After(now) {
			continue
		}
		s.processSubscriptionPayment(ctx, sub)
	}
}

func (s *Server) processSubscriptionPayment(ctx context.Context, sub *db.Subscription) {
	orgID := sub.OrgID
	subID := sub.Id()

	walletID := ""
	if sub.WalletID != nil {
		walletID = *sub.WalletID
	}
	tokenStr := ""
	if sub.Token != nil {
		tokenStr = *sub.Token
	}

	// Create transaction
	tx := orm.New[db.Transaction](s.db.ORM)
	tx.OrgID = orgID
	if walletID != "" {
		tx.WalletID = &walletID
	}
	tx.TxType = "subscription_payment"
	tx.Chain = sub.Chain
	tx.ToAddress = nilIfEmpty(sub.RecipientAddress)
	tx.Amount = nilIfEmpty(sub.Amount)
	tx.Token = nilIfEmpty(tokenStr)
	tx.Status = "approved"

	if err := tx.Create(); err != nil {
		logger.Error("scheduler: failed to create payment tx", err)
		// Retry logic
		if sub.RetryCount < sub.MaxRetries {
			sub.RetryCount++
			nextRetry := time.Now().Add(time.Hour)
			sub.NextPaymentAt = nextRetry
			sub.Update()
			s.fireWebhook(ctx, orgID, "subscription.insufficient_funds", map[string]string{"subscription_id": subID})
		} else {
			sub.Status = "failed"
			sub.Update()
			s.fireWebhook(ctx, orgID, "subscription.failed", map[string]string{"subscription_id": subID})
		}
		return
	}

	txID := tx.Id()

	// Sign and broadcast
	s.signAndBroadcast(txID, orgID)

	// Advance next payment
	nextPayment := computeNextPayment(sub.Interval)
	now := time.Now()
	sub.NextPaymentAt = nextPayment
	sub.LastPaymentAt = &now
	sub.LastTxID = &txID
	sub.RetryCount = 0
	sub.Update()

	s.fireWebhook(ctx, orgID, "subscription.paid", map[string]string{
		"subscription_id": subID,
		"tx_id":           txID,
	})
}
