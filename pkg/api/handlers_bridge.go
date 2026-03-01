package api

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"golang.org/x/crypto/sha3"
)

// Bridge signing request — matches the bridge server's expected format.
type bridgeSignRequest struct {
	TxID              string `json:"txId"`
	FromNetworkID     string `json:"fromNetworkId"`
	ToNetworkID       string `json:"toNetworkId"`
	ToTokenAddress    string `json:"toTokenAddress"`
	MsgSignature      string `json:"msgSignature"`
	ReceiverAddrHash  string `json:"receiverAddressHash"`
}

// Bridge signing response — matches the bridge server's expected format.
type bridgeSignResponse struct {
	Status bool                `json:"status"`
	Msg    string              `json:"msg,omitempty"`
	Data   *bridgeSignData     `json:"data,omitempty"`
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
// This is the endpoint the bridge server calls to get MPC signatures for cross-chain transfers.
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

	// Find the bridge wallet — look for a wallet named "bridge" or use the first available
	var mpcWalletID, ecdsaPubKey, ethAddress string
	err := s.db.Pool.QueryRow(r.Context(),
		`SELECT wallet_id, ecdsa_pubkey, eth_address FROM wallets
		 WHERE name ILIKE '%bridge%' AND status = 'active'
		 ORDER BY created_at ASC LIMIT 1`).
		Scan(&mpcWalletID, &ecdsaPubKey, &ethAddress)
	if err != nil {
		// Fallback: use any active wallet
		err = s.db.Pool.QueryRow(r.Context(),
			`SELECT wallet_id, ecdsa_pubkey, eth_address FROM wallets
			 WHERE status = 'active' AND key_type = 'secp256k1'
			 ORDER BY created_at ASC LIMIT 1`).
			Scan(&mpcWalletID, &ecdsaPubKey, &ethAddress)
		if err != nil {
			json.NewEncoder(w).Encode(bridgeSignResponse{Status: false, Msg: "no signing wallet available"})
			return
		}
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
		s.db.Pool.Exec(r.Context(),
			`INSERT INTO transactions (org_id, tx_type, chain, to_address, status, tx_hash, signature_r, signature_s, signed_at)
			 VALUES ($1, 'bridge_sign', $2, $3, 'signed', $4, $5, $6, $7)`,
			orgID, req.ToNetworkID, req.ReceiverAddrHash, hashedTxID, result.R, result.S, time.Now())
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
// Called by the bridge server after a swap is finalized on the destination chain.
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
		s.db.Pool.Exec(r.Context(),
			`UPDATE transactions SET status = 'confirmed', broadcast_at = $1
			 WHERE tx_hash = $2 AND org_id = $3 AND tx_type = 'bridge_sign'`,
			time.Now(), req.HashedTxID, orgID)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"status": true, "msg": "success"})
}

// keccak256Hex returns 0x-prefixed keccak256 hash of input string.
func keccak256Hex(input string) string {
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte(input))
	return "0x" + hex.EncodeToString(h.Sum(nil))
}
