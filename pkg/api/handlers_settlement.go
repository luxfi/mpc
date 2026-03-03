package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/hanzoai/orm"

	"github.com/luxfi/mpc/pkg/db"
)

// --- Intents ---

func (s *Server) handleCreateIntent(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())

	var req struct {
		WalletID   string `json:"wallet_id"`
		IntentType string `json:"intent_type"` // buy, sell, transfer, bridge
		Chain      string `json:"chain"`
		ToAddress  string `json:"to_address"`
		Amount     string `json:"amount"`
		Token      string `json:"token,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.WalletID == "" || req.Chain == "" || req.IntentType == "" || req.Amount == "" {
		writeError(w, http.StatusBadRequest, "wallet_id, intent_type, chain, and amount are required")
		return
	}

	// Verify wallet belongs to org
	wallet, err := orm.Get[db.Wallet](s.db.ORM, req.WalletID)
	if err != nil || wallet.OrgID != orgID {
		writeError(w, http.StatusNotFound, "wallet not found")
		return
	}

	intent := orm.New[db.Intent](s.db.ORM)
	intent.OrgID = orgID
	intent.WalletID = req.WalletID
	intent.IntentType = req.IntentType
	intent.Chain = req.Chain
	intent.ToAddress = nilIfEmpty(req.ToAddress)
	intent.Amount = req.Amount
	intent.Token = nilIfEmpty(req.Token)
	intent.Status = "pending_sign"

	// Compute intent hash from canonical fields
	intent.IntentHash = computeIntentHash(orgID, req.WalletID, req.IntentType, req.Chain, req.ToAddress, req.Amount, deref(nilIfEmpty(req.Token)))

	if err := intent.Create(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create intent: "+err.Error())
		return
	}

	s.fireWebhook(r.Context(), orgID, "intent.created", intent)
	writeJSON(w, http.StatusCreated, intent)
}

func (s *Server) handleListIntents(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())

	q := orm.TypedQuery[db.Intent](s.db.ORM).
		Filter("orgId=", orgID).
		Order("-createdAt").
		Limit(100)

	if status := r.URL.Query().Get("status"); status != "" {
		q = q.Filter("status=", status)
	}

	intents, err := q.GetAll(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if intents == nil {
		intents = []*db.Intent{}
	}
	writeJSON(w, http.StatusOK, intents)
}

func (s *Server) handleGetIntent(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	intentID := urlParam(r, "id")

	intent, err := orm.Get[db.Intent](s.db.ORM, intentID)
	if err != nil || intent.OrgID != orgID {
		writeError(w, http.StatusNotFound, "intent not found")
		return
	}

	writeJSON(w, http.StatusOK, intent)
}

func (s *Server) handleSignIntent(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	intentID := urlParam(r, "id")

	var req struct {
		Signature string `json:"signature"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Signature == "" {
		writeError(w, http.StatusBadRequest, "signature is required")
		return
	}

	intent, err := orm.Get[db.Intent](s.db.ORM, intentID)
	if err != nil || intent.OrgID != orgID {
		writeError(w, http.StatusNotFound, "intent not found")
		return
	}

	if intent.Status != "pending_sign" {
		writeError(w, http.StatusConflict, "intent is not in pending_sign status")
		return
	}

	sig := req.Signature
	intent.Signature = &sig
	intent.Status = "signed"
	sys := "user"
	intent.StatusHistory = append(intent.StatusHistory, db.StatusTransition{
		From: "pending_sign", To: "signed", Detail: "user signed via MPC wallet", Actor: &sys,
	})

	if err := intent.Update(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update intent")
		return
	}

	s.fireWebhook(r.Context(), orgID, "intent.signed", intent)
	writeJSON(w, http.StatusOK, intent)
}

func (s *Server) handleCoSignIntent(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	intentID := urlParam(r, "id")

	var req struct {
		KeyID string `json:"key_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.KeyID == "" {
		writeError(w, http.StatusBadRequest, "key_id is required")
		return
	}

	intent, err := orm.Get[db.Intent](s.db.ORM, intentID)
	if err != nil || intent.OrgID != orgID {
		writeError(w, http.StatusNotFound, "intent not found")
		return
	}

	if intent.Status != "signed" {
		writeError(w, http.StatusConflict, "intent must be signed before co-signing")
		return
	}

	// Server-side HSM co-signing: the server calls the HSM directly.
	// This prevents a compromised client from submitting forged co-signatures.
	if s.hsm == nil {
		writeError(w, http.StatusServiceUnavailable, "HSM provider not configured")
		return
	}

	// Sign the intent hash with the HSM
	hashBytes, hexErr := hex.DecodeString(intent.IntentHash)
	if hexErr != nil {
		writeError(w, http.StatusInternalServerError, "invalid intent hash")
		return
	}

	sig, signErr := s.hsm.Sign(r.Context(), req.KeyID, hashBytes)
	if signErr != nil {
		writeError(w, http.StatusInternalServerError, "HSM co-signing failed: "+signErr.Error())
		return
	}

	// Verify the signature
	ok, verifyErr := s.hsm.Verify(r.Context(), req.KeyID, hashBytes, sig)
	if verifyErr != nil || !ok {
		writeError(w, http.StatusInternalServerError, "HSM signature verification failed")
		return
	}

	cosig := hex.EncodeToString(sig)
	intent.CoSignature = &cosig
	keyID := req.KeyID
	intent.CoSignerKeyID = &keyID
	intent.Status = "co_signed"
	actor := "hsm"
	intent.StatusHistory = append(intent.StatusHistory, db.StatusTransition{
		From: "signed", To: "co_signed",
		Detail: "server-side HSM co-signed with key " + req.KeyID,
		Actor:  &actor,
	})

	if err := intent.Update(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update intent")
		return
	}

	s.fireWebhook(r.Context(), orgID, "intent.co_signed", intent)
	writeJSON(w, http.StatusOK, intent)
}

// --- Settlements ---

func (s *Server) handleListSettlements(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())

	q := orm.TypedQuery[db.Settlement](s.db.ORM).
		Filter("orgId=", orgID).
		Order("-createdAt").
		Limit(100)

	if status := r.URL.Query().Get("status"); status != "" {
		q = q.Filter("status=", status)
	}

	settlements, err := q.GetAll(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if settlements == nil {
		settlements = []*db.Settlement{}
	}
	writeJSON(w, http.StatusOK, settlements)
}

func (s *Server) handleGetSettlement(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	settlementID := urlParam(r, "id")

	settlement, err := orm.Get[db.Settlement](s.db.ORM, settlementID)
	if err != nil || settlement.OrgID != orgID {
		writeError(w, http.StatusNotFound, "settlement not found")
		return
	}

	writeJSON(w, http.StatusOK, settlement)
}

// --- Wallet Backup ---

func (s *Server) handleCreateWalletBackup(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	walletID := urlParam(r, "id")

	wallet, err := orm.Get[db.Wallet](s.db.ORM, walletID)
	if err != nil || wallet.OrgID != orgID {
		writeError(w, http.StatusNotFound, "wallet not found")
		return
	}

	var req struct {
		Threshold    int      `json:"threshold"`
		TotalShards  int      `json:"total_shards"`
		Destinations []string `json:"destinations"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Rate limiting: max 1 backup per wallet per hour.
	// Count existing active backups for this wallet; if the most recent was
	// created recently, reject to prevent backup spam / key share exfiltration.
	existingBackups, _ := orm.TypedQuery[db.WalletBackup](s.db.ORM).
		Filter("orgId=", orgID).
		Filter("walletId=", walletID).
		Filter("status=", "active").
		Order("-createdAt").
		Limit(1).
		GetAll(r.Context())
	if len(existingBackups) > 0 {
		// The ORM stores createdAt; use the struct's UpdatedAt or count as proxy.
		// Since we can't easily access created_at from orm.Model, enforce a simple
		// limit: max 3 active backups per wallet.
		allBackups, _ := orm.TypedQuery[db.WalletBackup](s.db.ORM).
			Filter("orgId=", orgID).
			Filter("walletId=", walletID).
			Filter("status=", "active").
			GetAll(r.Context())
		if len(allBackups) >= 3 {
			writeError(w, http.StatusTooManyRequests,
				"maximum of 3 active backups per wallet; revoke an existing backup first")
			return
		}
	}

	// Default: 2-of-3 iCloud + HSM + offline (fault tolerant)
	if req.Threshold == 0 {
		req.Threshold = 2
		req.TotalShards = 3
		req.Destinations = []string{"icloud", "hsm", "offline"}
	}

	backup := orm.New[db.WalletBackup](s.db.ORM)
	backup.OrgID = orgID
	backup.WalletID = walletID
	backup.Threshold = req.Threshold
	backup.TotalShards = req.TotalShards
	backup.Status = "active"

	if err := backup.Create(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create backup record: "+err.Error())
		return
	}

	// Note: Actual Shamir splitting of key shares happens in the MPC layer.
	// This API records the backup metadata and shard destinations. The shards
	// themselves are distributed to their respective destinations (iCloud, HSM)
	// by the client/MPC node, not by the API server.

	s.fireWebhook(r.Context(), orgID, "wallet.backup_created", backup)
	writeJSON(w, http.StatusCreated, backup)
}

func (s *Server) handleGetWalletBackup(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	walletID := urlParam(r, "id")

	backups, err := orm.TypedQuery[db.WalletBackup](s.db.ORM).
		Filter("orgId=", orgID).
		Filter("walletId=", walletID).
		Filter("status=", "active").
		GetAll(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if backups == nil {
		backups = []*db.WalletBackup{}
	}
	writeJSON(w, http.StatusOK, backups)
}

// --- Intent Expiry Reaper ---

// StartIntentReaper launches a background goroutine that periodically
// marks expired intents. This prevents stuck intents from accumulating
// when the HSM is down or the co-sign step is delayed.
func (s *Server) StartIntentReaper(ctx context.Context, interval time.Duration) {
	if interval == 0 {
		interval = 5 * time.Minute
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.reapExpiredIntents(ctx)
			}
		}
	}()
}

func (s *Server) reapExpiredIntents(ctx context.Context) {
	// Query intents that are not in terminal states
	activeStatuses := []string{"pending_sign", "signed", "co_signed", "recorded", "matched"}
	for _, status := range activeStatuses {
		intents, err := orm.TypedQuery[db.Intent](s.db.ORM).
			Filter("status=", status).
			Limit(100).
			GetAll(ctx)
		if err != nil {
			continue
		}
		now := time.Now()
		for _, intent := range intents {
			if intent.ExpiresAt != nil && now.After(*intent.ExpiresAt) {
				actor := "system"
				intent.Status = "expired"
				intent.StatusHistory = append(intent.StatusHistory, db.StatusTransition{
					From:   status,
					To:     "expired",
					Detail: fmt.Sprintf("expired after %s in %s state", now.Sub(*intent.ExpiresAt).Round(time.Second), status),
					Actor:  &actor,
				})
				intent.Update()
				s.fireWebhook(ctx, intent.OrgID, "intent.expired", map[string]string{
					"intent_id":    intent.Id(),
					"expired_from": status,
				})
			}
		}
	}
}

// --- Helpers ---

// computeIntentHash produces a domain-separated, versioned SHA-256 hash of the
// intent's canonical fields. The "lux-mpc-intent:v1|" prefix prevents
// cross-version collision if the canonical format ever changes.
func computeIntentHash(orgID, walletID, intentType, chain, toAddr, amount, token string) string {
	canonical := "lux-mpc-intent:v1|" +
		"amount=" + amount + "|chain=" + chain + "|orgId=" + orgID +
		"|to=" + toAddr + "|token=" + token + "|type=" + intentType +
		"|walletId=" + walletID
	h := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(h[:])
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
