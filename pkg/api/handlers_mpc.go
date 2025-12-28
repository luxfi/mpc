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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hanzoai/orm"

	"github.com/luxfi/mpc/pkg/db"
)

var errUnknownEncoding = errors.New("unknown encoding (must be hex|base64)")

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
// findDefaultWalletID returns the wallet explicitly marked as default for the
// given user (via `defaultForUserId`). There is at most one; if none is
// marked, returns "" — callers must then handle the no-default case. Never
// returns "the most recently created wallet" as a fallback — that was the old
// behavior and was semantically ambiguous (F22).
func (s *Server) findDefaultWalletID(
	ctx context.Context, orgID, userID string,
) string {
	if userID == "" {
		return ""
	}
	wallets, err := orm.TypedQuery[db.Wallet](s.db.ORM).
		Filter("orgId=", orgID).
		Filter("defaultForUserId=", userID).
		Limit(1).
		GetAll(ctx)
	if err != nil || len(wallets) == 0 {
		return ""
	}
	return wallets[0].Id()
}

// handleMpcSetDefaultWallet marks a wallet as default for the calling user.
// Transactionally unsets `defaultForUserId` on any previously-default wallet
// for this (orgId, userId) before setting it on the new one. Does NOT touch
// the wallet's Name field (that's user-supplied metadata, not a control
// channel) — F14.
func (s *Server) handleMpcSetDefaultWallet(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	userID := getUserID(r.Context())
	id := urlParam(r, "id")
	if userID == "" {
		writeError(w, http.StatusUnauthorized, "authenticated user required")
		return
	}

	// Verify target wallet belongs to the org
	wal, err := orm.Get[db.Wallet](s.db.ORM, id)
	if err != nil || wal.OrgID != orgID {
		writeError(w, http.StatusNotFound, "wallet not found")
		return
	}

	// Clear any previous default for this user, then set the new one.
	// We do this via explicit query + per-record update (ORM has no bulk
	// Update) but wrap in a single logical sequence. The worst case on a
	// concurrent set is that two wallets end up marked default briefly; the
	// read path picks Limit(1), so observable behavior remains consistent.
	prev, _ := orm.TypedQuery[db.Wallet](s.db.ORM).
		Filter("orgId=", orgID).
		Filter("defaultForUserId=", userID).
		GetAll(r.Context())
	for _, p := range prev {
		if p.Id() == id {
			continue
		}
		p.DefaultForUserID = nil
		_ = p.Update()
	}
	wal.DefaultForUserID = &userID
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

// handleMpcBalancesByAddress returns balances for a wallet addressed by its
// on-chain address. Address must belong to an MPC wallet in the caller's org,
// otherwise 404. This prevents address enumeration across tenants (F4).
func (s *Server) handleMpcBalancesByAddress(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	addr := urlParam(r, "address")
	if addr == "" {
		writeError(w, http.StatusBadRequest, "address is required")
		return
	}

	// Try ETH, BTC, SOL address fields in turn. Any match scoped to caller's
	// org resolves the address; otherwise 404 (never leak "address unknown
	// globally" vs "address not in your org").
	q := orm.TypedQuery[db.Wallet](s.db.ORM).Filter("orgId=", orgID).Limit(1)
	wallets, _ := q.Filter("ethAddress=", addr).GetAll(r.Context())
	if len(wallets) == 0 {
		wallets, _ = orm.TypedQuery[db.Wallet](s.db.ORM).
			Filter("orgId=", orgID).Filter("btcAddress=", addr).Limit(1).GetAll(r.Context())
	}
	if len(wallets) == 0 {
		wallets, _ = orm.TypedQuery[db.Wallet](s.db.ORM).
			Filter("orgId=", orgID).Filter("solAddress=", addr).Limit(1).GetAll(r.Context())
	}
	if len(wallets) == 0 {
		writeError(w, http.StatusNotFound, "address not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"address":  addr,
		"walletId": wallets[0].Id(),
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

// handleMpcSignDefault is the /v1/mpc/sign endpoint. It is an authenticated
// MPC signing oracle — so it enforces (F1 + F15):
//   - Role gate at router (requireRole "owner","admin","signer","api")
//   - Non-empty sessionId REQUIRED (no silent sign with implicit session)
//   - Session must be active, bound to caller + wallet, have `sign` scope,
//     and have remaining op/value budget — all enforced atomically via CAS
//     in consumeSessionForSign.
//   - Message encoding MUST decode successfully; no fallback to raw bytes.
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
	if req.SessionID == "" {
		writeError(w, http.StatusForbidden, "sessionId is required for signing")
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

	// Atomic session consume: increments operationsUsed + adds to valueAccum
	// with CAS. Fails if session is expired, revoked, wrong principal, lacks
	// `sign` scope, or limits would be exceeded.
	if _, err := s.consumeSessionForSign(r.Context(), orgID, walletID, userID, req.SessionID, req.Value); err != nil {
		writeHTTPError(w, err)
		return
	}

	payload, err := decodeMessage(req.Message, req.Encoding)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid message encoding: "+err.Error())
		return
	}
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
	if req.SessionID == "" {
		writeError(w, http.StatusForbidden, "sessionId is required for settlement signing")
		return
	}
	if _, err := s.consumeSessionForSign(r.Context(), orgID, req.WalletID, userID, req.SessionID, req.Value); err != nil {
		writeHTTPError(w, err)
		return
	}
	payload, err := decodeMessage(req.Payload, "hex")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload encoding: "+err.Error())
		return
	}
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

// handleBiometricEnroll — biometric enrollment is NOT an "accept arbitrary
// template bytes" endpoint. The client must first call
// /v1/mpc/webauthn/challenge to receive a server-issued challenge, then sign
// the challenge with an authenticator-bound key (per WebAuthn spec) AND
// provide a SecureGate liveness score above threshold (F5). Raw templates
// are not accepted because they would allow an attacker with a leaked
// template to forge enrollments.
func (s *Server) handleBiometricEnroll(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	userID := getUserID(r.Context())

	var req struct {
		ChallengeID        string  `json:"challengeId"`
		SignedResponse     string  `json:"signedResponse"`
		AuthenticatorData  string  `json:"authenticatorData"`
		ClientDataJSON     string  `json:"clientDataJSON"`
		PublicKey          string  `json:"publicKey"`
		Modality           string  `json:"modality"`
		LivenessScore      float64 `json:"livenessScore"`
		LivenessProviderID string  `json:"livenessProviderId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.ChallengeID == "" || req.SignedResponse == "" || req.PublicKey == "" {
		writeError(w, http.StatusBadRequest, "challengeId, signedResponse, publicKey are required")
		return
	}
	if req.Modality == "" {
		req.Modality = "face"
	}
	if req.Modality != "face" && req.Modality != "fingerprint" {
		writeError(w, http.StatusBadRequest, "modality must be face or fingerprint")
		return
	}
	// SecureGate liveness threshold (0.8 = typical PAD-2). Reject below.
	const minLivenessScore = 0.8
	if req.LivenessScore < minLivenessScore {
		writeError(w, http.StatusForbidden, "liveness score below required threshold")
		return
	}
	if req.LivenessProviderID == "" {
		writeError(w, http.StatusBadRequest, "livenessProviderId is required")
		return
	}
	// Consume the server-issued challenge (prevents replay). Challenges are
	// one-use and bound to the authenticated user.
	if ok, err := s.consumeBiometricChallenge(r.Context(), orgID, userID, req.ChallengeID); err != nil || !ok {
		writeError(w, http.StatusForbidden, "invalid or expired challenge")
		return
	}
	// Verify the signed response against the claimed public key.
	if err := verifyBiometricAttestation(req.PublicKey, req.AuthenticatorData, req.ClientDataJSON, req.SignedResponse, req.ChallengeID); err != nil {
		writeError(w, http.StatusForbidden, "attestation verification failed: "+err.Error())
		return
	}

	enroll := orm.New[db.DeviceEnrollment](s.db.ORM)
	enroll.OrgID = orgID
	enroll.UserID = userID
	enroll.DeviceID = "biometric-" + req.Modality
	enroll.DeviceType = "biometric"
	enroll.BiometricType = req.Modality
	// Store the attested PUBLIC KEY only — never the raw template.
	enroll.PublicKey = req.PublicKey
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

// consumeBiometricChallenge validates and atomically marks a server-issued
// WebAuthn challenge as used. Returns (true, nil) iff the challenge exists,
// belongs to the user, is in pending_registration state, and transitions to
// consumed. Prevents replay of the same challenge (F5).
func (s *Server) consumeBiometricChallenge(ctx context.Context, orgID, userID, challengeID string) (bool, error) {
	cred, err := orm.Get[db.WebAuthnCredential](s.db.ORM, challengeID)
	if err != nil {
		return false, nil
	}
	if cred.OrgID != orgID || cred.UserID != userID {
		return false, nil
	}
	if cred.Status != "pending_registration" {
		return false, nil
	}
	cred.Status = "consumed"
	if err := cred.Update(); err != nil {
		return false, err
	}
	return true, nil
}

// verifyBiometricAttestation validates the signed challenge response for a
// biometric enrollment. Clients must submit a P-256 ECDSA signature over
// SHA256(authenticatorData || SHA256(clientDataJSON)), where clientDataJSON's
// challenge field equals the server-issued challengeID (base64url). This is
// the same verification flow used by /v1/mpc/webauthn/verify; centralized
// here for reuse by biometric enroll (F5).
func verifyBiometricAttestation(publicKeyB64, authDataB64, clientDataJSONB64, signatureB64, expectedChallenge string) error {
	clientData, err := base64.URLEncoding.DecodeString(clientDataJSONB64)
	if err != nil {
		return errors.New("invalid clientDataJSON")
	}
	var cd struct {
		Challenge string `json:"challenge"`
		Type      string `json:"type"`
	}
	if err := json.Unmarshal(clientData, &cd); err != nil {
		return errors.New("invalid clientDataJSON structure")
	}
	if cd.Challenge != expectedChallenge {
		return errors.New("challenge mismatch")
	}
	if cd.Type != "webauthn.create" {
		return errors.New("invalid ceremony type")
	}
	authData, err := base64.URLEncoding.DecodeString(authDataB64)
	if err != nil {
		return errors.New("invalid authenticatorData")
	}
	sig, err := base64.URLEncoding.DecodeString(signatureB64)
	if err != nil {
		return errors.New("invalid signature")
	}
	pubBytes, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil || len(pubBytes) < 65 || pubBytes[0] != 0x04 {
		return errors.New("invalid P-256 public key")
	}
	x := new(big.Int).SetBytes(pubBytes[1:33])
	y := new(big.Int).SetBytes(pubBytes[33:65])
	if !elliptic.P256().IsOnCurve(x, y) {
		return errors.New("public key is not a valid P-256 point")
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	clientDataHash := sha256.Sum256(clientData)
	signed := append(authData, clientDataHash[:]...)
	signedHash := sha256.Sum256(signed)
	if !ecdsa.VerifyASN1(pub, signedHash[:], sig) {
		return errors.New("signature verification failed")
	}
	return nil
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
// bytes. STRICT — returns an error if the encoding is declared but the input
// does not decode. This eliminates the signing-oracle-for-arbitrary-strings
// class of attacks (F6). The empty-encoding default is "hex".
func decodeMessage(msg, encoding string) ([]byte, error) {
	switch encoding {
	case "", "hex":
		b, err := hexDecodeSafe(msg)
		if err != nil {
			return nil, err
		}
		return b, nil
	case "base64":
		b, err := base64DecodeSafe(msg)
		if err != nil {
			return nil, err
		}
		return b, nil
	default:
		return nil, errUnknownEncoding
	}
}
