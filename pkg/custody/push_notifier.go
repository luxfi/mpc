package custody

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// PushNotifier sends push notifications to user devices for trade approval
// and confirmation. Implementations must be safe for concurrent use.
type PushNotifier interface {
	// SendTradeApproval sends a push notification asking the user to approve a trade.
	// The notification should deep-link to the trade approval screen in the mobile app.
	SendTradeApproval(ctx context.Context, req TradeApprovalNotification) error
	// SendTradeConfirmation sends a confirmation push after a trade is approved and settled.
	SendTradeConfirmation(ctx context.Context, req TradeConfirmationNotification) error
}

// TradeApprovalNotification contains the data for a trade approval push.
type TradeApprovalNotification struct {
	DeviceToken string `json:"device_token"` // FCM token or APNS device token
	DeviceType  string `json:"device_type"`  // ios, android
	TradeID     string `json:"trade_id"`
	Symbol      string `json:"symbol"`
	Side        string `json:"side"` // buy, sell
	Quantity    string `json:"quantity"`
	Price       string `json:"price"`
	TotalValue  string `json:"total_value"`
	ExpiresAt   string `json:"expires_at"` // ISO 8601
}

// TradeConfirmationNotification contains the data for a trade confirmation push.
type TradeConfirmationNotification struct {
	DeviceToken string `json:"device_token"`
	DeviceType  string `json:"device_type"`
	TradeID     string `json:"trade_id"`
	Symbol      string `json:"symbol"`
	Side        string `json:"side"`
	Quantity    string `json:"quantity"`
	Price       string `json:"price"`
	TxHash      string `json:"tx_hash"`
}

// FCMNotifier sends push notifications via Firebase Cloud Messaging (v1 API).
type FCMNotifier struct {
	serverKey  string
	httpClient *http.Client
}

// NewFCMNotifier creates a new FCM push notifier.
// serverKey is the Firebase Cloud Messaging server key.
func NewFCMNotifier(serverKey string) *FCMNotifier {
	return &FCMNotifier{
		serverKey: serverKey,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (f *FCMNotifier) SendTradeApproval(ctx context.Context, req TradeApprovalNotification) error {
	if f.serverKey == "" {
		return errors.New("FCM server key not configured")
	}
	if req.DeviceToken == "" {
		return errors.New("device token is empty")
	}

	sideLabel := "Buy"
	if req.Side == "sell" {
		sideLabel = "Sell"
	}

	payload := map[string]interface{}{
		"to": req.DeviceToken,
		"notification": map[string]string{
			"title": fmt.Sprintf("Approve Trade: %s %s", sideLabel, req.Symbol),
			"body":  fmt.Sprintf("%s %s %s @ $%s — tap to approve with Face ID", sideLabel, req.Quantity, req.Symbol, req.Price),
		},
		"data": map[string]string{
			"type":        "trade_approval",
			"trade_id":    req.TradeID,
			"symbol":      req.Symbol,
			"side":        req.Side,
			"quantity":    req.Quantity,
			"price":       req.Price,
			"total_value": req.TotalValue,
			"expires_at":  req.ExpiresAt,
			"action":      "trade_approve",
		},
		"priority": "high",
		"android": map[string]interface{}{
			"priority": "high",
		},
		"apns": map[string]interface{}{
			"headers": map[string]string{
				"apns-priority":  "10",
				"apns-push-type": "alert",
			},
		},
	}

	return f.send(ctx, payload)
}

func (f *FCMNotifier) SendTradeConfirmation(ctx context.Context, req TradeConfirmationNotification) error {
	if f.serverKey == "" {
		return errors.New("FCM server key not configured")
	}
	if req.DeviceToken == "" {
		return errors.New("device token is empty")
	}

	sideLabel := "Bought"
	if req.Side == "sell" {
		sideLabel = "Sold"
	}

	payload := map[string]interface{}{
		"to": req.DeviceToken,
		"notification": map[string]string{
			"title": fmt.Sprintf("Trade Confirmed: %s", req.Symbol),
			"body":  fmt.Sprintf("%s %s %s @ $%s — settled on-chain", sideLabel, req.Quantity, req.Symbol, req.Price),
		},
		"data": map[string]string{
			"type":     "trade_confirmation",
			"trade_id": req.TradeID,
			"symbol":   req.Symbol,
			"side":     req.Side,
			"tx_hash":  req.TxHash,
			"action":   "trade_confirmed",
		},
	}

	return f.send(ctx, payload)
}

func (f *FCMNotifier) send(ctx context.Context, payload map[string]interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal FCM payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://fcm.googleapis.com/fcm/send", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create FCM request: %w", err)
	}
	req.Header.Set("Authorization", "key="+f.serverKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("FCM request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("FCM returned status %d", resp.StatusCode)
	}
	return nil
}

// MultiNotifier sends push notifications to all registered devices for a user.
// It tries all notifiers and returns the first error (if any).
type MultiNotifier struct {
	fcm *FCMNotifier
}

// NewMultiNotifier creates a notifier that dispatches to FCM.
// APNS is handled via FCM's cross-platform delivery for iOS when using FCM tokens.
func NewMultiNotifier(fcmServerKey string) *MultiNotifier {
	var fcm *FCMNotifier
	if fcmServerKey != "" {
		fcm = NewFCMNotifier(fcmServerKey)
	}
	return &MultiNotifier{fcm: fcm}
}

func (m *MultiNotifier) SendTradeApproval(ctx context.Context, req TradeApprovalNotification) error {
	if m.fcm == nil {
		return errors.New("no push notifier configured")
	}
	return m.fcm.SendTradeApproval(ctx, req)
}

func (m *MultiNotifier) SendTradeConfirmation(ctx context.Context, req TradeConfirmationNotification) error {
	if m.fcm == nil {
		return errors.New("no push notifier configured")
	}
	return m.fcm.SendTradeConfirmation(ctx, req)
}
