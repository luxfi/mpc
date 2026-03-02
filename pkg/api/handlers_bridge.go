package api

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/hanzoai/orm"
	"golang.org/x/crypto/sha3"

	"github.com/luxfi/mpc/pkg/db"
)

// Bridge signing request — matches the bridge server's expected format.
type bridgeSignRequest struct {
	TxID             string `json:"txId"`
	FromNetworkID    string `json:"fromNetworkId"`
	ToNetworkID      string `json:"toNetworkId"`
	ToTokenAddress   string `json:"toTokenAddress"`
	MsgSignature     string `json:"msgSignature"`
	ReceiverAddrHash string `json:"receiverAddressHash"`
}

// Bridge signing response — matches the bridge server's expected format.
type bridgeSignResponse struct {
	Status bool            `json:"status"`
	Msg    string          `json:"msg,omitempty"`
	Data   *bridgeSignData `json:"data,omitempty"`
}

type bridgeSignData struct {
	FromTokenAddress string `json:"fromTokenAddress"`
	Contract         string `json:"contract"`
	From             string `json:"from"`
	TokenAmount      string `json:"tokenAmount"`
	Signature        string `json:"signature"`
	MPCSigner        string `json:"mpcSigner"`
	HashedTxID       string `json:"hashedTxId"`
	ToTokenAddrHash  string `json:"toTokenAddressHash"`
	Vault            bool   `json:"vault"`
}

// handleBridgeSign handles POST /api/v1/generate_mpc_sig
func (s *Server) handleBridgeSign(w http.ResponseWriter, r *http.Request) {
	var req bridgeSignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(bridgeSignResponse{Status: false, Msg: "invalid request body"})
		return
	}

	if req.TxID == "" || req.FromNetworkID == "" || req.ToNetworkID == "" {
		json.NewEncoder(w).Encode(bridgeSignResponse{Status: false, Msg: "missing required fields"})
		return
	}

	// Check MPC cluster health
	status := s.mpc.GetClusterStatus()
	if status == nil || !status.Ready {
		json.NewEncoder(w).Encode(bridgeSignResponse{Status: false, Msg: "MPC cluster not ready"})
		return
	}

	// Find a bridge wallet — look for a wallet named "bridge" or use the first active secp256k1 wallet
	var bridgeWallet *db.Wallet

	// Try to find wallet with "bridge" in name
	wallets, err := orm.TypedQuery[db.Wallet](s.db.ORM).
		Filter("status=", "active").
		Filter("keyType=", "secp256k1").
		Order("createdAt").
		Limit(10).
		GetAll(r.Context())
	if err == nil {
		for _, w := range wallets {
			if w.Name != nil && contains(*w.Name, "bridge") {
				bridgeWallet = w
				break
			}
		}
		if bridgeWallet == nil && len(wallets) > 0 {
			bridgeWallet = wallets[0]
		}
	}

	if bridgeWallet == nil {
		json.NewEncoder(w).Encode(bridgeSignResponse{Status: false, Msg: "no signing wallet available"})
		return
	}

	mpcWalletID := bridgeWallet.WalletID
	ethAddress := ""
	if bridgeWallet.EthAddress != nil {
		ethAddress = *bridgeWallet.EthAddress
	}

	// Hash the transaction ID (keccak256)
	hashedTxID := keccak256Hex(req.TxID)

	// Create the message to sign: keccak256(txId)
	msgHash, err := hex.DecodeString(hashedTxID[2:]) // strip 0x
	if err != nil {
		json.NewEncoder(w).Encode(bridgeSignResponse{Status: false, Msg: "failed to hash tx"})
		return
	}

	// Trigger MPC signing
	result, err := s.mpc.TriggerSign(mpcWalletID, msgHash)
	if err != nil {
		json.NewEncoder(w).Encode(bridgeSignResponse{Status: false, Msg: "MPC signing failed: " + err.Error()})
		return
	}

	// Build signature: concatenate r + s + v
	sig := result.R + result.S
	if result.Signature != "" {
		sig = result.Signature
	}

	// Record the bridge transaction in DB
	orgID := getOrgID(r.Context())
	if orgID != "" {
		now := time.Now()
		tx := orm.New[db.Transaction](s.db.ORM)
		tx.OrgID = orgID
		tx.TxType = "bridge_sign"
		tx.Chain = req.ToNetworkID
		tx.ToAddress = nilIfEmpty(req.ReceiverAddrHash)
		tx.Status = "signed"
		tx.TxHash = nilIfEmpty(hashedTxID)
		tx.SignatureR = nilIfEmpty(result.R)
		tx.SignatureS = nilIfEmpty(result.S)
		tx.SignedAt = &now
		tx.Create()
	}

	toTokenAddrHash := keccak256Hex(req.ToTokenAddress)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(bridgeSignResponse{
		Status: true,
		Data: &bridgeSignData{
			FromTokenAddress: req.ToTokenAddress,
			Signature:        sig,
			MPCSigner:        ethAddress,
			HashedTxID:       hashedTxID,
			ToTokenAddrHash:  toTokenAddrHash,
			Vault:            false,
		},
	})
}

// handleBridgeComplete handles POST /api/v1/complete
func (s *Server) handleBridgeComplete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		HashedTxID string `json:"hashedTxId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"status": false, "msg": "invalid request"})
		return
	}

	if req.HashedTxID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"status": false, "msg": "hashedTxId required"})
		return
	}

	// Mark the bridge transaction as completed
	orgID := getOrgID(r.Context())
	if orgID != "" {
		txList, err := orm.TypedQuery[db.Transaction](s.db.ORM).
			Filter("orgId=", orgID).
			Filter("txType=", "bridge_sign").
			Filter("txHash=", req.HashedTxID).
			Limit(1).
			GetAll(r.Context())
		if err == nil && len(txList) > 0 {
			now := time.Now()
			tx := txList[0]
			tx.Status = "confirmed"
			tx.BroadcastAt = &now
			tx.Update()
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"status": true, "msg": "success"})
}

// keccak256Hex returns 0x-prefixed keccak256 hash of input string.
func keccak256Hex(input string) string {
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte(input))
	return "0x" + hex.EncodeToString(h.Sum(nil))
}

// contains checks if s contains substr (case-insensitive done simply via strings import).
func contains(s, substr string) bool {
	// Simple case-sensitive check; good enough for wallet name matching
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
