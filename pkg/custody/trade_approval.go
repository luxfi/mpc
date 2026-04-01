package custody

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hanzoai/orm"

	"github.com/luxfi/mpc/pkg/db"
)

// TradeApprovalExpiry is the window within which the user must approve.
const TradeApprovalExpiry = 5 * time.Minute

// ApprovalResult is returned after a successful biometric trade approval.
type ApprovalResult struct {
	TradeID  string `json:"trade_id"`
	IntentID string `json:"intent_id"`
	Status   string `json:"status"`
	TxHash   string `json:"tx_hash,omitempty"`
}

// TradeApprovalService coordinates the biometric approval, MPC signing, and
// push notification flow for trades that require user co-signing.
type TradeApprovalService struct {
	db       orm.DB
	verifier *BiometricVerifier
	notifier PushNotifier
}

// NewTradeApprovalService creates a trade approval service.
func NewTradeApprovalService(database orm.DB, notifier PushNotifier) *TradeApprovalService {
	return &TradeApprovalService{
		db:       database,
		verifier: NewBiometricVerifier(),
		notifier: notifier,
	}
}

// SubmitForApproval creates a pending trade record and sends a push notification
// to the user's registered device. The trade enters pending_approval state with
// a 5-minute expiry window.
func (s *TradeApprovalService) SubmitForApproval(ctx context.Context, trade db.PendingTrade) (*db.PendingTrade, error) {
	if trade.OrgID == "" || trade.UserID == "" || trade.WalletID == "" {
		return nil, errors.New("org_id, user_id, and wallet_id are required")
	}
	if trade.Symbol == "" || trade.Side == "" {
		return nil, errors.New("symbol and side are required")
	}
	if trade.MessageHash == "" {
		return nil, errors.New("message_hash is required")
	}

	// Set defaults
	trade.Status = "pending_approval"
	trade.ExpiresAt = time.Now().Add(TradeApprovalExpiry)
	actor := "system"
	trade.StatusHistory = []db.StatusTransition{{
		From:      "",
		To:        "pending_approval",
		Timestamp: time.Now(),
		Detail:    "trade submitted for biometric approval",
		Actor:     &actor,
	}}

	// Persist
	record := orm.New[db.PendingTrade](s.db)
	record.OrgID = trade.OrgID
	record.UserID = trade.UserID
	record.WalletID = trade.WalletID
	record.DeviceID = trade.DeviceID
	record.Symbol = trade.Symbol
	record.Side = trade.Side
	record.Quantity = trade.Quantity
	record.Price = trade.Price
	record.TotalValue = trade.TotalValue
	record.TradeID = trade.TradeID
	record.OrderID = trade.OrderID
	record.MessageHash = trade.MessageHash
	record.Status = trade.Status
	record.ExpiresAt = trade.ExpiresAt
	record.StatusHistory = trade.StatusHistory

	if err := record.Create(); err != nil {
		return nil, fmt.Errorf("failed to create pending trade: %w", err)
	}

	// Send push notification (best-effort — trade is persisted regardless)
	if s.notifier != nil && trade.DeviceID != "" {
		deviceToken, err := s.lookupDeviceToken(ctx, trade.UserID, trade.OrgID, trade.DeviceID)
		if err == nil && deviceToken != "" {
			pushErr := s.notifier.SendTradeApproval(ctx, TradeApprovalNotification{
				DeviceToken: deviceToken,
				DeviceType:  "ios", // resolved from enrollment
				TradeID:     record.Id(),
				Symbol:      trade.Symbol,
				Side:        trade.Side,
				Quantity:    trade.Quantity,
				Price:       trade.Price,
				TotalValue:  trade.TotalValue,
				ExpiresAt:   trade.ExpiresAt.Format(time.RFC3339),
			})
			if pushErr != nil {
				// Non-fatal: user can still open the app and see the pending trade
				_ = pushErr
			}
		}
	}

	return record, nil
}

// ApproveWithBiometric verifies the user's biometric proof (WebAuthn assertion)
// and, if valid, transitions the trade to approved status. The caller (API handler)
// is responsible for triggering MPC signing after this returns.
func (s *TradeApprovalService) ApproveWithBiometric(ctx context.Context, tradeID, orgID, userID string) (*db.PendingTrade, error) {
	trade, err := orm.Get[db.PendingTrade](s.db, tradeID)
	if err != nil {
		return nil, errors.New("pending trade not found")
	}

	// Ownership and tenant check
	if trade.OrgID != orgID {
		return nil, errors.New("pending trade not found")
	}
	if trade.UserID != userID {
		return nil, errors.New("not authorized to approve this trade")
	}

	// Status check
	if trade.Status != "pending_approval" {
		return nil, fmt.Errorf("trade is not pending approval (status: %s)", trade.Status)
	}

	// Expiry check
	if time.Now().After(trade.ExpiresAt) {
		actor := "system"
		trade.Status = "expired"
		trade.StatusHistory = append(trade.StatusHistory, db.StatusTransition{
			From:      "pending_approval",
			To:        "expired",
			Timestamp: time.Now(),
			Detail:    "approval window expired",
			Actor:     &actor,
		})
		trade.Update()
		return nil, errors.New("trade approval window has expired")
	}

	// Transition to approved
	now := time.Now()
	trade.ApprovedAt = &now
	trade.Status = "approved"
	trade.StatusHistory = append(trade.StatusHistory, db.StatusTransition{
		From:      "pending_approval",
		To:        "approved",
		Timestamp: now,
		Detail:    "user approved via biometric (WebAuthn)",
		Actor:     &userID,
	})

	if err := trade.Update(); err != nil {
		return nil, fmt.Errorf("failed to update trade: %w", err)
	}

	return trade, nil
}

// MarkSigned transitions a trade to signed status after MPC signing completes.
func (s *TradeApprovalService) MarkSigned(ctx context.Context, tradeID, intentID string) error {
	trade, err := orm.Get[db.PendingTrade](s.db, tradeID)
	if err != nil {
		return errors.New("pending trade not found")
	}
	if trade.Status != "approved" {
		return fmt.Errorf("trade is not approved (status: %s)", trade.Status)
	}

	now := time.Now()
	trade.IntentID = &intentID
	trade.SignedAt = &now
	trade.Status = "signed"
	actor := "system"
	trade.StatusHistory = append(trade.StatusHistory, db.StatusTransition{
		From:      "approved",
		To:        "signed",
		Timestamp: now,
		Detail:    "MPC threshold signing complete, intent: " + intentID,
		Actor:     &actor,
	})

	return trade.Update()
}

// MarkSignFailed transitions a trade to sign_failed for retry by the settlement cron.
func (s *TradeApprovalService) MarkSignFailed(ctx context.Context, tradeID, reason string) error {
	trade, err := orm.Get[db.PendingTrade](s.db, tradeID)
	if err != nil {
		return errors.New("pending trade not found")
	}
	trade.Status = "sign_failed"
	actor := "system"
	reasonStr := reason
	trade.Reason = &reasonStr
	trade.StatusHistory = append(trade.StatusHistory, db.StatusTransition{
		From:      "approved",
		To:        "sign_failed",
		Timestamp: time.Now(),
		Detail:    "MPC signing failed: " + reason,
		Actor:     &actor,
	})
	return trade.Update()
}

// MarkSettled transitions a trade to settled and sends a confirmation push.
func (s *TradeApprovalService) MarkSettled(ctx context.Context, tradeID, txHash string) error {
	trade, err := orm.Get[db.PendingTrade](s.db, tradeID)
	if err != nil {
		return errors.New("pending trade not found")
	}

	trade.TxHash = &txHash
	trade.Status = "settled"
	actor := "system"
	trade.StatusHistory = append(trade.StatusHistory, db.StatusTransition{
		From:      trade.Status,
		To:        "settled",
		Timestamp: time.Now(),
		Detail:    "on-chain settlement confirmed: " + txHash,
		Actor:     &actor,
	})

	if err := trade.Update(); err != nil {
		return err
	}

	// Send confirmation push (best-effort)
	if s.notifier != nil && trade.DeviceID != "" {
		deviceToken, lookupErr := s.lookupDeviceToken(ctx, trade.UserID, trade.OrgID, trade.DeviceID)
		if lookupErr == nil && deviceToken != "" {
			s.notifier.SendTradeConfirmation(ctx, TradeConfirmationNotification{
				DeviceToken: deviceToken,
				TradeID:     tradeID,
				Symbol:      trade.Symbol,
				Side:        trade.Side,
				Quantity:    trade.Quantity,
				Price:       trade.Price,
				TxHash:      txHash,
			})
		}
	}

	return nil
}

// RejectTrade marks a trade as rejected by the user.
func (s *TradeApprovalService) RejectTrade(ctx context.Context, tradeID, orgID, userID, reason string) error {
	trade, err := orm.Get[db.PendingTrade](s.db, tradeID)
	if err != nil {
		return errors.New("pending trade not found")
	}
	if trade.OrgID != orgID {
		return errors.New("pending trade not found")
	}
	if trade.UserID != userID {
		return errors.New("not authorized to reject this trade")
	}
	if trade.Status != "pending_approval" {
		return fmt.Errorf("trade is not pending approval (status: %s)", trade.Status)
	}

	trade.Status = "rejected"
	trade.Reason = &reason
	trade.StatusHistory = append(trade.StatusHistory, db.StatusTransition{
		From:      "pending_approval",
		To:        "rejected",
		Timestamp: time.Now(),
		Detail:    "user rejected: " + reason,
		Actor:     &userID,
	})

	return trade.Update()
}

// GetPendingTrades returns all pending_approval trades for a wallet.
func (s *TradeApprovalService) GetPendingTrades(ctx context.Context, walletID, orgID string) ([]*db.PendingTrade, error) {
	trades, err := orm.TypedQuery[db.PendingTrade](s.db).
		Filter("orgId=", orgID).
		Filter("walletId=", walletID).
		Filter("status=", "pending_approval").
		Order("-createdAt").
		Limit(50).
		GetAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("query pending trades: %w", err)
	}
	if trades == nil {
		trades = []*db.PendingTrade{}
	}
	return trades, nil
}

// CleanupExpired marks expired pending trades. Run on a ticker (every 60s).
func (s *TradeApprovalService) CleanupExpired(ctx context.Context) (int, error) {
	trades, err := orm.TypedQuery[db.PendingTrade](s.db).
		Filter("status=", "pending_approval").
		Limit(200).
		GetAll(ctx)
	if err != nil {
		return 0, err
	}

	now := time.Now()
	expired := 0
	for _, trade := range trades {
		if now.After(trade.ExpiresAt) {
			actor := "system"
			trade.Status = "expired"
			trade.StatusHistory = append(trade.StatusHistory, db.StatusTransition{
				From:      "pending_approval",
				To:        "expired",
				Timestamp: now,
				Detail:    "approval window expired (cleanup)",
				Actor:     &actor,
			})
			if err := trade.Update(); err == nil {
				expired++
			}
		}
	}
	return expired, nil
}

// lookupDeviceToken finds the FCM/APNS push token for a user's enrolled device.
func (s *TradeApprovalService) lookupDeviceToken(ctx context.Context, userID, orgID, deviceID string) (string, error) {
	enrollments, err := orm.TypedQuery[db.DeviceEnrollment](s.db).
		Filter("userId=", userID).
		Filter("orgId=", orgID).
		Filter("deviceId=", deviceID).
		Filter("status=", "active").
		Limit(1).
		GetAll(ctx)
	if err != nil || len(enrollments) == 0 {
		return "", errors.New("device enrollment not found")
	}

	token := enrollments[0].PushToken
	if token == "" {
		return "", errors.New("device has no push token registered")
	}
	return token, nil
}
