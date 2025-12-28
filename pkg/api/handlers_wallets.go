package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/hanzoai/orm"

	"github.com/luxfi/mpc/pkg/db"
)

func (s *Server) handleListWallets(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	vaultID := urlParam(r, "id")

	wallets, err := orm.TypedQuery[db.Wallet](s.db.ORM).
		Filter("vaultId=", vaultID).
		Filter("orgId=", orgID).
		Order("-createdAt").
		GetAll(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if wallets == nil {
		wallets = []*db.Wallet{}
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
	vault, err := orm.Get[db.Vault](s.db.ORM, vaultID)
	if err != nil || vault.OrgID != orgID {
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
		total := status.ExpectedPeers + 1
		for i := 0; i < total; i++ {
			participants = append(participants, fmt.Sprintf("node%d", i))
		}
	}

	name := req.Name
	wal := orm.New[db.Wallet](s.db.ORM)
	wal.VaultID = vaultID
	wal.OrgID = orgID
	wal.WalletID = result.WalletID
	wal.Name = nilIfEmpty(name)
	wal.KeyType = req.KeyType
	wal.ECDSAPubkey = nilIfEmpty(result.ECDSAPubKey)
	wal.EDDSAPubkey = nilIfEmpty(result.EDDSAPubKey)
	wal.EthAddress = nilIfEmpty(result.EthAddress)
	wal.Threshold = status.Threshold
	wal.Participants = participants
	wal.Version = 1
	wal.Status = "active"
	wal.CreatedBy = nilIfEmpty(userID)
	if err := wal.Create(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save wallet: "+err.Error())
		return
	}

	s.fireWebhook(r.Context(), orgID, "keygen.complete", wal)
	writeJSON(w, http.StatusCreated, wal)
}

func (s *Server) handleGetWallet(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	walletID := urlParam(r, "id")

	wallet, err := orm.Get[db.Wallet](s.db.ORM, walletID)
	if err != nil || wallet.OrgID != orgID {
		writeError(w, http.StatusNotFound, "wallet not found")
		return
	}

	writeJSON(w, http.StatusOK, wallet)
}

func (s *Server) handleGetWalletAddresses(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	walletID := urlParam(r, "id")

	wallet, err := orm.Get[db.Wallet](s.db.ORM, walletID)
	if err != nil || wallet.OrgID != orgID {
		writeError(w, http.StatusNotFound, "wallet not found")
		return
	}

	addresses := map[string]interface{}{}
	if wallet.EthAddress != nil {
		addresses["ethereum"] = *wallet.EthAddress
	}
	if wallet.BtcAddress != nil {
		addresses["bitcoin"] = *wallet.BtcAddress
	}
	if wallet.SolAddress != nil {
		addresses["solana"] = *wallet.SolAddress
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

	wallet, err := orm.Get[db.Wallet](s.db.ORM, walletID)
	if err != nil || wallet.OrgID != orgID {
		writeError(w, http.StatusNotFound, "wallet not found")
		return
	}

	if err := s.mpc.TriggerReshare(wallet.WalletID, req.NewThreshold, req.NewParticipants); err != nil {
		writeError(w, http.StatusInternalServerError, "reshare failed: "+err.Error())
		return
	}

	wallet.Version++
	wallet.Threshold = req.NewThreshold
	wallet.Participants = req.NewParticipants
	if err := wallet.Update(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update wallet")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "reshare_complete"})
}

func (s *Server) handleWalletHistory(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	walletID := urlParam(r, "id")

	txs, err := orm.TypedQuery[db.Transaction](s.db.ORM).
		Filter("walletId=", walletID).
		Filter("orgId=", orgID).
		Order("-createdAt").
		Limit(100).
		GetAll(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if txs == nil {
		txs = []*db.Transaction{}
	}
	writeJSON(w, http.StatusOK, txs)
}
