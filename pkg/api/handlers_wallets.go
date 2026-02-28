package api

import (
	"encoding/json"
	"net/http"

	"github.com/luxfi/mpc/pkg/db"
)

func (s *Server) handleListWallets(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	vaultID := urlParam(r, "id")

	rows, err := s.db.Pool.Query(r.Context(),
		`SELECT id, vault_id, org_id, wallet_id, name, key_type,
		        ecdsa_pubkey, eddsa_pubkey, eth_address, btc_address, sol_address,
		        threshold, participants, version, status, created_by, created_at
		 FROM wallets WHERE vault_id = $1 AND org_id = $2
		 ORDER BY created_at DESC`, vaultID, orgID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	var wallets []db.Wallet
	for rows.Next() {
		var wal db.Wallet
		if err := rows.Scan(&wal.ID, &wal.VaultID, &wal.OrgID, &wal.WalletID,
			&wal.Name, &wal.KeyType, &wal.ECDSAPubkey, &wal.EDDSAPubkey,
			&wal.EthAddress, &wal.BtcAddress, &wal.SolAddress,
			&wal.Threshold, &wal.Participants, &wal.Version, &wal.Status,
			&wal.CreatedBy, &wal.CreatedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "scan error")
			return
		}
		wallets = append(wallets, wal)
	}
	if wallets == nil {
		wallets = []db.Wallet{}
	}
	writeJSON(w, http.StatusOK, wallets)
}

func (s *Server) handleCreateWallet(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	userID := getUserID(r.Context())
	vaultID := urlParam(r, "id")

	var req struct {
		Name    string `json:"name"`
		KeyType string `json:"key_type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.KeyType == "" {
		req.KeyType = "secp256k1"
	}

	// Verify vault belongs to org
	var vaultExists bool
	s.db.Pool.QueryRow(r.Context(),
		`SELECT EXISTS(SELECT 1 FROM vaults WHERE id = $1 AND org_id = $2)`,
		vaultID, orgID).Scan(&vaultExists)
	if !vaultExists {
		writeError(w, http.StatusNotFound, "vault not found")
		return
	}

	// Trigger MPC keygen
	result, err := s.mpc.TriggerKeygen("")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "keygen failed: "+err.Error())
		return
	}

	// Get cluster status for participants
	status := s.mpc.GetClusterStatus()
	participants := []string{}
	if status != nil {
		participants = append(participants, status.NodeID)
	}

	var wallet db.Wallet
	err = s.db.Pool.QueryRow(r.Context(),
		`INSERT INTO wallets (vault_id, org_id, wallet_id, name, key_type,
		 ecdsa_pubkey, eddsa_pubkey, eth_address, threshold, participants, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		 RETURNING id, vault_id, org_id, wallet_id, name, key_type,
		 ecdsa_pubkey, eddsa_pubkey, eth_address, btc_address, sol_address,
		 threshold, participants, version, status, created_by, created_at`,
		vaultID, orgID, result.WalletID, req.Name, req.KeyType,
		result.ECDSAPubKey, result.EDDSAPubKey, result.EthAddress,
		status.Threshold, participants, userID).
		Scan(&wallet.ID, &wallet.VaultID, &wallet.OrgID, &wallet.WalletID,
			&wallet.Name, &wallet.KeyType, &wallet.ECDSAPubkey, &wallet.EDDSAPubkey,
			&wallet.EthAddress, &wallet.BtcAddress, &wallet.SolAddress,
			&wallet.Threshold, &wallet.Participants, &wallet.Version, &wallet.Status,
			&wallet.CreatedBy, &wallet.CreatedAt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save wallet: "+err.Error())
		return
	}

	s.fireWebhook(r.Context(), orgID, "keygen.complete", wallet)
	writeJSON(w, http.StatusCreated, wallet)
}

func (s *Server) handleGetWallet(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	walletID := urlParam(r, "id")

	var wallet db.Wallet
	err := s.db.Pool.QueryRow(r.Context(),
		`SELECT id, vault_id, org_id, wallet_id, name, key_type,
		        ecdsa_pubkey, eddsa_pubkey, eth_address, btc_address, sol_address,
		        threshold, participants, version, status, created_by, created_at
		 FROM wallets WHERE id = $1 AND org_id = $2`, walletID, orgID).
		Scan(&wallet.ID, &wallet.VaultID, &wallet.OrgID, &wallet.WalletID,
			&wallet.Name, &wallet.KeyType, &wallet.ECDSAPubkey, &wallet.EDDSAPubkey,
			&wallet.EthAddress, &wallet.BtcAddress, &wallet.SolAddress,
			&wallet.Threshold, &wallet.Participants, &wallet.Version, &wallet.Status,
			&wallet.CreatedBy, &wallet.CreatedAt)
	if err != nil {
		writeError(w, http.StatusNotFound, "wallet not found")
		return
	}

	writeJSON(w, http.StatusOK, wallet)
}

func (s *Server) handleGetWalletAddresses(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	walletID := urlParam(r, "id")

	var eth, btc, sol *string
	err := s.db.Pool.QueryRow(r.Context(),
		`SELECT eth_address, btc_address, sol_address
		 FROM wallets WHERE id = $1 AND org_id = $2`, walletID, orgID).
		Scan(&eth, &btc, &sol)
	if err != nil {
		writeError(w, http.StatusNotFound, "wallet not found")
		return
	}

	addresses := map[string]interface{}{}
	if eth != nil {
		addresses["ethereum"] = *eth
	}
	if btc != nil {
		addresses["bitcoin"] = *btc
	}
	if sol != nil {
		addresses["solana"] = *sol
	}
	writeJSON(w, http.StatusOK, addresses)
}

func (s *Server) handleReshareWallet(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	walletID := urlParam(r, "id")

	var req struct {
		NewThreshold    int      `json:"new_threshold"`
		NewParticipants []string `json:"new_participants"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var mpcWalletID string
	err := s.db.Pool.QueryRow(r.Context(),
		`SELECT wallet_id FROM wallets WHERE id = $1 AND org_id = $2`,
		walletID, orgID).Scan(&mpcWalletID)
	if err != nil {
		writeError(w, http.StatusNotFound, "wallet not found")
		return
	}

	if err := s.mpc.TriggerReshare(mpcWalletID, req.NewThreshold, req.NewParticipants); err != nil {
		writeError(w, http.StatusInternalServerError, "reshare failed: "+err.Error())
		return
	}

	// Update wallet version
	_, err = s.db.Pool.Exec(r.Context(),
		`UPDATE wallets SET version = version + 1, threshold = $1, participants = $2
		 WHERE id = $3 AND org_id = $4`,
		req.NewThreshold, req.NewParticipants, walletID, orgID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update wallet")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "reshare_complete"})
}

func (s *Server) handleWalletHistory(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	walletID := urlParam(r, "id")

	// First get the wallet's UUID from the URL param
	rows, err := s.db.Pool.Query(r.Context(),
		`SELECT id, org_id, wallet_id, tx_type, chain, to_address, amount, token,
		        tx_hash, status, initiated_by, created_at, signed_at, broadcast_at
		 FROM transactions WHERE wallet_id = $1 AND org_id = $2
		 ORDER BY created_at DESC LIMIT 100`, walletID, orgID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	var txs []db.Transaction
	for rows.Next() {
		var tx db.Transaction
		if err := rows.Scan(&tx.ID, &tx.OrgID, &tx.WalletID, &tx.TxType, &tx.Chain,
			&tx.ToAddress, &tx.Amount, &tx.Token, &tx.TxHash, &tx.Status,
			&tx.InitiatedBy, &tx.CreatedAt, &tx.SignedAt, &tx.BroadcastAt); err != nil {
			writeError(w, http.StatusInternalServerError, "scan error")
			return
		}
		txs = append(txs, tx)
	}
	if txs == nil {
		txs = []db.Transaction{}
	}
	writeJSON(w, http.StatusOK, txs)
}
