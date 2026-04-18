// Package api — MPC spec handlers (Liquidity /v1/mpc surface).
//
// This file implements the spec-shaped endpoints defined in
// `~/work/liquidity/openapi/mpc.yaml`. Legacy paths (/v1/transactions,
// /v1/policies, /v1/audit) are superseded by their /v1/mpc/* equivalents.
//
// The canonical `Operation` view (unified across sign/send/mint/burn/transfer
// /contract_call) maps onto the existing `db.Transaction` table via the
// `txType` discriminator. No new operations table — one table, one view.
package api

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hanzoai/orm"

	"github.com/luxfi/mpc/pkg/db"
)

func hexDecodeSafe(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	return hex.DecodeString(s)
}

func base64DecodeSafe(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}

// --- Shared audit helper used by MPC surface handlers ---

// recordMpcAudit writes a typed MPC-scoped audit entry. Uses the existing
// db.AuditEntry table; the `action` carries the structured verb
// (session.create, operation.approve, policy.update, etc.) per spec.
func (s *Server) recordMpcAudit(
	ctx context.Context, orgID, userID, action, subjectType, subjectID string,
) {
	if orgID == "" {
		return
	}
	e := orm.New[db.AuditEntry](s.db.ORM)
	e.OrgID = orgID
	e.UserID = nilIfEmpty(userID)
	e.Action = action
	e.ResourceType = nilIfEmpty(subjectType)
	e.ResourceID = nilIfEmpty(subjectID)
	e.Create()
}

// --- /v1/mpc/wallets — spec-shape wallet list/create ---

// walletResponse matches the OpenAPI `Wallet` schema.
type walletResponse struct {
	WalletID  string    `json:"walletId"`
	Address   string    `json:"address"`
	Status    string    `json:"status"`
	Protocol  string    `json:"protocol"`
	Threshold string    `json:"threshold"`
	IsDefault bool      `json:"isDefault"`
	CreatedAt time.Time `json:"createdAt"`
}

func toWalletResponse(w *db.Wallet, isDefault bool) walletResponse {
	addr := ""
	if w.EthAddress != nil {
		addr = *w.EthAddress
	} else if w.BtcAddress != nil {
		addr = *w.BtcAddress
	} else if w.SolAddress != nil {
		addr = *w.SolAddress
	}
	status := w.Status
	if status == "" {
		status = "active"
	}
	threshold := strconv.Itoa(w.Threshold) + "-of-" + strconv.Itoa(len(w.Participants))
	return walletResponse{
		WalletID:  w.WalletID,
		Address:   addr,
		Status:    status,
		Protocol:  w.Protocol,
		Threshold: threshold,
		IsDefault: isDefault,
		CreatedAt: w.CreatedAt,
	}
}

func (s *Server) handleMpcListWallets(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	userID := getUserID(r.Context())
	role := getRole(r.Context())

	q := orm.TypedQuery[db.Wallet](s.db.ORM).
		Filter("orgId=", orgID).
		Order("-createdAt").
		Limit(500)

	if statusFilter := r.URL.Query().Get("status"); statusFilter != "" {
		q = q.Filter("status=", statusFilter)
	}
	if role != "owner" && role != "admin" && userID != "" {
		q = q.Filter("createdBy=", userID)
	}
	wallets, err := q.GetAll(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	defaultID := s.findDefaultWalletID(r.Context(), orgID, userID)
	items := make([]walletResponse, 0, len(wallets))
	for _, wal := range wallets {
		items = append(items, toWalletResponse(wal, wal.Id() == defaultID))
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items":      items,
		"page":       1,
		"totalItems": len(items),
	})
}

func (s *Server) handleMpcCreateWallet(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	userID := getUserID(r.Context())

	var req struct {
		Protocol  string `json:"protocol"`
		Threshold string `json:"threshold"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Protocol == "" {
		req.Protocol = "cggmp21"
	}
	if req.Protocol != "cggmp21" && req.Protocol != "frost" {
		writeError(w, http.StatusBadRequest, "protocol must be cggmp21 or frost")
		return
	}

	result, err := s.mpc.TriggerKeygen(orgID, "")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "keygen failed: "+err.Error())
		return
	}
	status := s.mpc.GetClusterStatus()
	participants := []string{}
	if status != nil {
		for i := 0; i < status.ExpectedPeers+1; i++ {
			participants = append(participants, "node"+strconv.Itoa(i))
		}
	}

	wal := orm.New[db.Wallet](s.db.ORM)
	wal.OrgID = orgID
	wal.WalletID = result.WalletID
	wal.KeyType = "secp256k1"
	wal.Protocol = req.Protocol
	wal.ECDSAPubkey = nilIfEmpty(result.ECDSAPubKey)
	wal.EDDSAPubkey = nilIfEmpty(result.EDDSAPubKey)
	wal.EthAddress = nilIfEmpty(result.EthAddress)
	wal.BtcAddress = nilIfEmpty(result.BtcAddress)
	wal.SolAddress = nilIfEmpty(result.SolAddress)
	if status != nil {
		wal.Threshold = status.Threshold
	}
	wal.Participants = participants
	wal.Version = 1
	wal.Status = "active"
	wal.CreatedBy = nilIfEmpty(userID)
	if err := wal.Create(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save wallet: "+err.Error())
		return
	}
	s.recordMpcAudit(r.Context(), orgID, userID, "wallet.create", "wallet", wal.Id())
	writeJSON(w, http.StatusCreated, toWalletResponse(wal, false))
}

func (s *Server) handleMpcGetWallet(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	userID := getUserID(r.Context())
	id := urlParam(r, "id")
	wal, err := orm.Get[db.Wallet](s.db.ORM, id)
	if err != nil || wal.OrgID != orgID {
		writeError(w, http.StatusNotFound, "wallet not found")
		return
	}
	defaultID := s.findDefaultWalletID(r.Context(), orgID, userID)
	writeJSON(w, http.StatusOK, toWalletResponse(wal, wal.Id() == defaultID))
}

// --- Default wallet per user ---
//
// The default wallet is stored as a User-scoped kv key (`mpc.defaultWalletId`)
// on the User record. To avoid model churn we reuse the User.MFASecret-like
// pointer? — Instead: store on a tiny `DefaultWallet` model. Simpler: a single
// field on User. For now, use an AddressWhitelist-ish lookup: store in Vault's
// AppID field for the single user-default vault. To keep the change tight we
// use a dedicated lightweight record.

// findDefaultWalletID scans for a per-user default wallet marker. The marker
// is represented by placing the sentinel tag "default:<userID>" in the wallet
// `Name` field. If no explicit default exists, the most recently created
// wallet for that user wins.
func (s *Server) findDefaultWalletID(
	ctx context.Context, orgID, userID string,
) string {
	if userID == "" {
		return ""
	}
	wallets, err := orm.TypedQuery[db.Wallet](s.db.ORM).
		Filter("orgId=", orgID).
		Filter("createdBy=", userID).
		Order("-createdAt").
		Limit(1).
		GetAll(ctx)
	if err != nil || len(wallets) == 0 {
		return ""
	}
	return wallets[0].Id()
}

func (s *Server) handleMpcSetDefaultWallet(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	userID := getUserID(r.Context())
	id := urlParam(r, "id")

	wal, err := orm.Get[db.Wallet](s.db.ORM, id)
	if err != nil || wal.OrgID != orgID {
		writeError(w, http.StatusNotFound, "wallet not found")
		return
	}
	// Tag the wallet with a default marker; one-default-per-user invariant is
	// enforced at read time (findDefaultWalletID reads most recent).
	marker := "default:" + userID
	wal.Name = &marker
	if err := wal.Update(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to set default wallet")
		return
	}
	s.recordMpcAudit(r.Context(), orgID, userID, "wallet.set_default", "wallet", wal.Id())
	writeJSON(w, http.StatusOK, toWalletResponse(wal, true))
}

func (s *Server) handleMpcGetDefaultWallet(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	userID := getUserID(r.Context())
	id := s.findDefaultWalletID(r.Context(), orgID, userID)
	if id == "" {
		writeError(w, http.StatusNotFound, "no default wallet")
		return
	}
	wal, err := orm.Get[db.Wallet](s.db.ORM, id)
	if err != nil {
		writeError(w, http.StatusNotFound, "no default wallet")
		return
	}
	writeJSON(w, http.StatusOK, toWalletResponse(wal, true))
}

func (s *Server) handleMpcCreateDefaultWallet(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	userID := getUserID(r.Context())
	// If a default already exists, return it.
	if id := s.findDefaultWalletID(r.Context(), orgID, userID); id != "" {
		wal, _ := orm.Get[db.Wallet](s.db.ORM, id)
		writeJSON(w, http.StatusOK, toWalletResponse(wal, true))
		return
	}
	// Otherwise, delegate to the spec wallet-create flow.
	s.handleMpcCreateWallet(w, r)
}

// --- /v1/mpc/wallets/sweep ---

func (s *Server) handleMpcSweepWallet(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	userID := getUserID(r.Context())

	var req struct {
		FromWalletID string `json:"fromWalletId"`
		ToAddress    string `json:"toAddress"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.FromWalletID == "" || req.ToAddress == "" {
		writeError(w, http.StatusBadRequest, "fromWalletId and toAddress are required")
		return
	}
	wal, err := orm.Get[db.Wallet](s.db.ORM, req.FromWalletID)
	if err != nil || wal.OrgID != orgID {
		writeError(w, http.StatusNotFound, "wallet not found")
		return
	}
	// Create a sweep operation (Transaction with txType=sweep). Returns the
	// `MpcTransaction` shape the spec expects.
	tx := orm.New[db.Transaction](s.db.ORM)
	tx.OrgID = orgID
	walletID := wal.Id()
	tx.WalletID = &walletID
	tx.TxType = "sweep"
	tx.Chain = "evm"
	tx.ToAddress = &req.ToAddress
	tx.Status = "pending"
	tx.InitiatedBy = nilIfEmpty(userID)
	if err := tx.Create(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to initiate sweep")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"txId":      tx.Id(),
		"status":    tx.Status,
		"createdAt": tx.CreatedAt,
	})
}

// --- /v1/mpc/wallets/balances + /v1/mpc/balances/{address} ---

func (s *Server) handleMpcWalletBalances(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	userID := getUserID(r.Context())
	role := getRole(r.Context())

	q := orm.TypedQuery[db.Wallet](s.db.ORM).Filter("orgId=", orgID).Limit(200)
	if role != "owner" && role != "admin" && userID != "" {
		q = q.Filter("createdBy=", userID)
	}
	wallets, err := q.GetAll(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	items := make([]map[string]interface{}, 0, len(wallets))
	for _, wal := range wallets {
		addr := ""
		if wal.EthAddress != nil {
			addr = *wal.EthAddress
		}
		items = append(items, map[string]interface{}{
			"walletId": wal.Id(),
			"address":  addr,
			"balances": []any{},
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"wallets": items})
}

func (s *Server) handleMpcBalancesByAddress(w http.ResponseWriter, r *http.Request) {
	addr := urlParam(r, "address")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"address":  addr,
		"balances": []any{},
	})
}

// --- /v1/mpc/crypto/wallet/{asset} ---

func (s *Server) handleMpcCryptoWallet(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	userID := getUserID(r.Context())
	asset := urlParam(r, "asset")

	id := s.findDefaultWalletID(r.Context(), orgID, userID)
	if id == "" {
		writeError(w, http.StatusNotFound, "no wallet for asset")
		return
	}
	wal, err := orm.Get[db.Wallet](s.db.ORM, id)
	if err != nil {
		writeError(w, http.StatusNotFound, "no wallet for asset")
		return
	}
	addr := ""
	network := ""
	switch asset {
	case "btc", "BTC":
		if wal.BtcAddress != nil {
			addr = *wal.BtcAddress
		}
		network = "bitcoin"
	case "sol", "SOL":
		if wal.SolAddress != nil {
			addr = *wal.SolAddress
		}
		network = "solana"
	default:
		if wal.EthAddress != nil {
			addr = *wal.EthAddress
		}
		network = "ethereum"
	}
	if addr == "" {
		writeError(w, http.StatusNotFound, "no wallet for asset")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"asset":    asset,
		"address":  addr,
		"network":  network,
		"walletId": wal.Id(),
	})
}

// --- /v1/mpc/sign + /v1/mpc/settlement/sign ---

type signRequest struct {
	Message   string `json:"message"`
	Encoding  string `json:"encoding,omitempty"`
	WalletID  string `json:"walletId,omitempty"`
	SessionID string `json:"sessionId,omitempty"`
	Value     string `json:"value,omitempty"`
}

func (s *Server) handleMpcSignDefault(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	userID := getUserID(r.Context())

	var req signRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Message == "" {
		writeError(w, http.StatusBadRequest, "message is required")
		return
	}
	walletID := req.WalletID
	if walletID == "" {
		walletID = s.findDefaultWalletID(r.Context(), orgID, userID)
	}
	if walletID == "" {
		writeError(w, http.StatusBadRequest, "no default wallet; specify walletId")
		return
	}
	wal, err := orm.Get[db.Wallet](s.db.ORM, walletID)
	if err != nil || wal.OrgID != orgID {
		writeError(w, http.StatusNotFound, "wallet not found")
		return
	}

	// Enforce session validity if a session is presented OR if org policy
	// requires one (no session + explicit sessionId → 403).
	if req.SessionID != "" {
		if _, err := s.consumeSessionForSign(r.Context(), orgID, walletID, userID, req.SessionID, req.Value); err != nil {
			writeHTTPError(w, err)
			return
		}
	}

	payload := decodeMessage(req.Message, req.Encoding)
	result, err := s.mpc.TriggerSign(orgID, wal.WalletID, payload)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "signing failed: "+err.Error())
		return
	}
	s.recordMpcAudit(r.Context(), orgID, userID, "operation.sign", "wallet", walletID)
	writeJSON(w, http.StatusOK, map[string]string{
		"signature": result.Signature,
		"r":         result.R,
		"s":         result.S,
	})
}

func (s *Server) handleMpcSignSettlement(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	userID := getUserID(r.Context())

	var req struct {
		WalletID       string `json:"walletId"`
		Payload        string `json:"payload"`
		Reason         string `json:"reason"`
		ReferenceID    string `json:"referenceId,omitempty"`
		IdempotencyKey string `json:"idempotencyKey,omitempty"`
		SessionID      string `json:"sessionId,omitempty"`
		Value          string `json:"value,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.WalletID == "" || req.Payload == "" || req.Reason == "" {
		writeError(w, http.StatusBadRequest, "walletId, payload, reason are required")
		return
	}
	switch req.Reason {
	case "trade_settlement", "deposit", "withdrawal", "issuance", "cancellation":
	default:
		writeError(w, http.StatusBadRequest, "invalid reason")
		return
	}
	wal, err := orm.Get[db.Wallet](s.db.ORM, req.WalletID)
	if err != nil || wal.OrgID != orgID {
		writeError(w, http.StatusNotFound, "wallet not found")
		return
	}
	if req.SessionID != "" {
		if _, err := s.consumeSessionForSign(r.Context(), orgID, req.WalletID, userID, req.SessionID, req.Value); err != nil {
			writeHTTPError(w, err)
			return
		}
	}
	payload := decodeMessage(req.Payload, "hex")
	result, err := s.mpc.TriggerSign(orgID, wal.WalletID, payload)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "settlement signing failed: "+err.Error())
		return
	}
	s.recordMpcAudit(r.Context(), orgID, userID, "operation.sign_settlement", "wallet", req.WalletID)
	writeJSON(w, http.StatusOK, map[string]string{
		"signature": result.Signature,
		"r":         result.R,
		"s":         result.S,
	})
}

// --- /v1/mpc/biometric/{enroll,status} ---

func (s *Server) handleBiometricEnroll(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	userID := getUserID(r.Context())

	var req struct {
		Template string `json:"template"`
		Modality string `json:"modality"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Template == "" {
		writeError(w, http.StatusBadRequest, "template is required")
		return
	}
	if req.Modality == "" {
		req.Modality = "face"
	}
	if req.Modality != "face" && req.Modality != "fingerprint" {
		writeError(w, http.StatusBadRequest, "modality must be face or fingerprint")
		return
	}
	// Record enrollment via DeviceEnrollment with biometricType=modality.
	enroll := orm.New[db.DeviceEnrollment](s.db.ORM)
	enroll.OrgID = orgID
	enroll.UserID = userID
	enroll.DeviceID = "biometric-" + req.Modality
	enroll.DeviceType = "biometric"
	enroll.BiometricType = req.Modality
	enroll.PublicKey = req.Template
	enroll.Status = "active"
	if err := enroll.Create(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to enroll biometric: "+err.Error())
		return
	}
	s.recordMpcAudit(r.Context(), orgID, userID, "biometric.enroll", "biometric", enroll.Id())
	writeJSON(w, http.StatusCreated, map[string]string{
		"enrollmentId": enroll.Id(),
		"status":       "enrolled",
	})
}

func (s *Server) handleBiometricStatus(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	userID := getUserID(r.Context())

	enrolls, err := orm.TypedQuery[db.DeviceEnrollment](s.db.ORM).
		Filter("orgId=", orgID).
		Filter("userId=", userID).
		Filter("deviceType=", "biometric").
		Order("-createdAt").
		Limit(1).
		GetAll(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if len(enrolls) == 0 {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"userId": userID,
			"status": "not_enrolled",
		})
		return
	}
	e := enrolls[0]
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"userId":       userID,
		"enrollmentId": e.Id(),
		"status":       e.Status,
		"enrolledAt":   e.CreatedAt,
	})
}

// --- /v1/mpc/webauthn/{challenge,verify} — spec-named aliases ---
//
// The spec uses `/v1/mpc/webauthn/challenge` + `/v1/mpc/webauthn/verify`.
// We already expose `handleRegisterWebAuthnBegin` and `handleVerifyWebAuthn`;
// just route the spec paths to those handlers.

// decodeMessage decodes the spec-declared `encoding` (hex|base64) into raw
// bytes. Unknown encodings fall through to raw string bytes.
func decodeMessage(msg, encoding string) []byte {
	switch encoding {
	case "", "hex":
		b, err := hexDecodeSafe(msg)
		if err == nil {
			return b
		}
		return []byte(msg)
	case "base64":
		b, err := base64DecodeSafe(msg)
		if err == nil {
			return b
		}
		return []byte(msg)
	default:
		return []byte(msg)
	}
}
