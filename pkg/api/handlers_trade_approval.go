package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"time"

	"crypto/ecdsa"
	"crypto/elliptic"

	"github.com/hanzoai/orm"

	"github.com/luxfi/mpc/pkg/db"
)

// handleTradeSubmit accepts a trade from the ATS and creates a pending approval.
// The user gets a push notification on their registered device.
// POST /v1/trade/submit
func (s *Server) handleTradeSubmit(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())

	if s.tradeApproval == nil {
		writeError(w, http.StatusServiceUnavailable, "trade approval service not configured")
		return
	}

	var req struct {
		UserID      string `json:"user_id"`
		WalletID    string `json:"wallet_id"`
		DeviceID    string `json:"device_id"`
		Symbol      string `json:"symbol"`
		Side        string `json:"side"` // buy, sell
		Quantity    string `json:"quantity"`
		Price       string `json:"price"`
		TotalValue  string `json:"total_value"`
		TradeID     string `json:"trade_id"`
		OrderID     string `json:"order_id"`
		MessageHash string `json:"message_hash"` // hex-encoded tx data to sign
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.UserID == "" || req.WalletID == "" || req.Symbol == "" || req.Side == "" || req.MessageHash == "" {
		writeError(w, http.StatusBadRequest, "user_id, wallet_id, symbol, side, and message_hash are required")
		return
	}
	if req.Side != "buy" && req.Side != "sell" {
		writeError(w, http.StatusBadRequest, "side must be buy or sell")
		return
	}

	// Verify caller is authorized to submit trades for this user.
	// API key callers must have "trade:submit" permission. JWT callers must
	// either be the user themselves or have "admin" role.
	callerRole := getRole(r.Context())
	callerID := getUserID(r.Context())
	if callerRole == "api" {
		if !hasPermission(r.Context(), "trade:submit") {
			writeError(w, http.StatusForbidden, "api key missing permission: trade:submit")
			return
		}
	} else if callerID != req.UserID && callerRole != "admin" {
		writeError(w, http.StatusForbidden, "cannot submit trades for other users")
		return
	}

	// Verify wallet belongs to this org
	wallet, err := orm.Get[db.Wallet](s.db.ORM, req.WalletID)
	if err != nil || wallet.OrgID != orgID {
		writeError(w, http.StatusNotFound, "wallet not found")
		return
	}

	trade := db.PendingTrade{
		OrgID:       orgID,
		UserID:      req.UserID,
		WalletID:    req.WalletID,
		DeviceID:    req.DeviceID,
		Symbol:      req.Symbol,
		Side:        req.Side,
		Quantity:    req.Quantity,
		Price:       req.Price,
		TotalValue:  req.TotalValue,
		TradeID:     req.TradeID,
		OrderID:     req.OrderID,
		MessageHash: req.MessageHash,
	}

	result, err := s.tradeApproval.SubmitForApproval(r.Context(), trade)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to submit trade: "+err.Error())
		return
	}

	s.fireWebhook(r.Context(), orgID, "trade.submitted", map[string]string{
		"trade_id":  result.Id(),
		"wallet_id": req.WalletID,
		"user_id":   req.UserID,
		"symbol":    req.Symbol,
		"side":      req.Side,
	})

	writeJSON(w, http.StatusCreated, result)
}

// handleTradeApprove verifies a WebAuthn assertion (biometric) and approves the trade.
// After approval, triggers MPC signing via the intent flow.
// POST /v1/trade/approve
func (s *Server) handleTradeApprove(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	userID := getUserID(r.Context())

	if s.tradeApproval == nil {
		writeError(w, http.StatusServiceUnavailable, "trade approval service not configured")
		return
	}

	var req struct {
		TradeID  string `json:"trade_id"`
		ID       string `json:"id"`    // WebAuthn credential ID
		RawID    string `json:"rawId"` // base64url
		Type     string `json:"type"`  // "public-key"
		Response struct {
			AuthenticatorData string `json:"authenticatorData"`
			ClientDataJSON    string `json:"clientDataJSON"`
			Signature         string `json:"signature"`
			UserHandle        string `json:"userHandle"`
		} `json:"response"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.TradeID == "" || req.ID == "" {
		writeError(w, http.StatusBadRequest, "trade_id and credential id are required")
		return
	}

	// Verify WebAuthn assertion: the challenge must be SHA256(trade_id) to bind
	// the biometric approval to this specific trade.
	creds, err := orm.TypedQuery[db.WebAuthnCredential](s.db.ORM).
		Filter("userId=", userID).
		Filter("orgId=", orgID).
		Filter("webAuthnId=", req.ID).
		Filter("status=", "active").
		Limit(1).
		GetAll(r.Context())
	if err != nil || len(creds) == 0 {
		writeError(w, http.StatusUnauthorized, "no matching registered credential")
		return
	}

	// Verify clientDataJSON challenge matches SHA256(trade_id)
	clientData, err := base64.URLEncoding.DecodeString(req.Response.ClientDataJSON)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid clientDataJSON")
		return
	}
	var cd struct {
		Challenge string `json:"challenge"`
		Origin    string `json:"origin"`
		Type      string `json:"type"`
	}
	if err := json.Unmarshal(clientData, &cd); err != nil {
		writeError(w, http.StatusBadRequest, "invalid clientDataJSON structure")
		return
	}
	expectedChallenge := sha256.Sum256([]byte(req.TradeID))
	expectedChallengeB64 := base64.URLEncoding.EncodeToString(expectedChallenge[:])
	if cd.Challenge != expectedChallengeB64 {
		writeError(w, http.StatusBadRequest, "challenge does not match trade")
		return
	}

	// Verify ES256 signature against stored public key
	authData, _ := base64.URLEncoding.DecodeString(req.Response.AuthenticatorData)
	sig, _ := base64.URLEncoding.DecodeString(req.Response.Signature)
	clientDataHash := sha256.Sum256(clientData)
	signedData := append(authData, clientDataHash[:]...)
	signedHash := sha256.Sum256(signedData)

	// Always verify signature. Reject if key can't parse.
	pubKeyBytes, decErr := base64.StdEncoding.DecodeString(creds[0].PublicKey)
	if decErr != nil || len(pubKeyBytes) < 65 || pubKeyBytes[0] != 0x04 {
		writeError(w, http.StatusUnauthorized, "stored credential has invalid public key; re-register the WebAuthn credential")
		return
	}
	{
		x := new(big.Int).SetBytes(pubKeyBytes[1:33])
		y := new(big.Int).SetBytes(pubKeyBytes[33:65])
		pubKey := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
		if !ecdsa.VerifyASN1(pubKey, signedHash[:], sig) {
			writeError(w, http.StatusUnauthorized, "invalid biometric signature")
			return
		}
	}

	// Validate origin
	if !s.webauthnOrigins[cd.Origin] {
		writeError(w, http.StatusBadRequest, "origin mismatch: "+cd.Origin+" is not an allowed WebAuthn origin")
		return
	}

	// Biometric verified — approve the trade
	trade, err := s.tradeApproval.ApproveWithBiometric(r.Context(), req.TradeID, orgID, userID)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}

	// MPC signing with error handling. On failure, mark trade as
	// sign_failed so the settlement retry cron can pick it up.
	go func() {
		ctx := context.Background()
		result, signErr := s.mpc.TriggerSign(orgID, trade.WalletID, []byte(trade.MessageHash))
		if signErr != nil {
			s.tradeApproval.MarkSignFailed(ctx, trade.Id(), signErr.Error())
			s.fireWebhook(ctx, orgID, "trade.sign_failed", map[string]string{
				"trade_id": trade.Id(),
				"error":    signErr.Error(),
			})
			return
		}
		intent := orm.New[db.Intent](s.db.ORM)
		intent.OrgID = orgID
		intent.WalletID = trade.WalletID
		intent.IntentType = trade.Side
		intent.Chain = "lux"
		intent.Amount = trade.TotalValue
		intent.IntentHash = trade.MessageHash
		sigStr := result.Signature
		intent.Signature = &sigStr
		intent.Status = "signed"
		if createErr := intent.Create(); createErr != nil {
			s.tradeApproval.MarkSignFailed(ctx, trade.Id(), "intent create failed: "+createErr.Error())
			return
		}
		s.tradeApproval.MarkSigned(ctx, trade.Id(), intent.Id())
		// Audit log the MPC signing event
		s.writeSigningAuditLog(ctx, orgID, trade.WalletID, trade.MessageHash, intent.Id(), "trade_approve")
		s.fireWebhook(ctx, orgID, "trade.signed", map[string]string{
			"trade_id":  trade.Id(),
			"intent_id": intent.Id(),
		})
	}()

	s.fireWebhook(r.Context(), orgID, "trade.approved", map[string]string{
		"trade_id":    req.TradeID,
		"approved_by": userID,
		"method":      "webauthn_biometric",
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":          "approved",
		"trade_id":        trade.Id(),
		"biometric":       true,
		"signing_started": true,
	})
}

// handleTradeReject rejects a pending trade.
// POST /v1/trade/reject
func (s *Server) handleTradeReject(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	userID := getUserID(r.Context())

	if s.tradeApproval == nil {
		writeError(w, http.StatusServiceUnavailable, "trade approval service not configured")
		return
	}

	var req struct {
		TradeID string `json:"trade_id"`
		Reason  string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.TradeID == "" {
		writeError(w, http.StatusBadRequest, "trade_id is required")
		return
	}
	if req.Reason == "" {
		req.Reason = "user rejected"
	}

	if err := s.tradeApproval.RejectTrade(r.Context(), req.TradeID, orgID, userID, req.Reason); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}

	s.fireWebhook(r.Context(), orgID, "trade.rejected", map[string]string{
		"trade_id":    req.TradeID,
		"rejected_by": userID,
		"reason":      req.Reason,
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "rejected", "trade_id": req.TradeID})
}

// handlePendingTrades lists pending trade approvals for a wallet.
// GET /v1/trade/pending?wallet_id=xxx
func (s *Server) handlePendingTrades(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())

	if s.tradeApproval == nil {
		writeError(w, http.StatusServiceUnavailable, "trade approval service not configured")
		return
	}

	walletID := r.URL.Query().Get("wallet_id")
	if walletID == "" {
		writeError(w, http.StatusBadRequest, "wallet_id query parameter is required")
		return
	}

	// Verify wallet belongs to this org
	wallet, err := orm.Get[db.Wallet](s.db.ORM, walletID)
	if err != nil || wallet.OrgID != orgID {
		writeError(w, http.StatusNotFound, "wallet not found")
		return
	}

	trades, err := s.tradeApproval.GetPendingTrades(r.Context(), walletID, orgID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list pending trades")
		return
	}

	writeJSON(w, http.StatusOK, trades)
}

// StartTradeReaper launches a background goroutine that periodically marks
// expired pending trades. Trades have a 5-minute approval window.
func (s *Server) StartTradeReaper(ctx context.Context, interval time.Duration) {
	if interval == 0 {
		interval = 60 * time.Second
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if s.tradeApproval != nil {
					s.tradeApproval.CleanupExpired(ctx)
				}
			}
		}
	}()
}
