package api

import (
	"encoding/json"
	"net/http"

	"github.com/luxfi/mpc/pkg/db"
)

func (s *Server) handleDeploySmartWallet(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	walletID := urlParam(r, "id")

	var req struct {
		Chain             string   `json:"chain"`
		WalletType        string   `json:"wallet_type"` // safe, erc4337
		FactoryAddress    *string  `json:"factory_address,omitempty"`
		EntrypointAddress *string  `json:"entrypoint_address,omitempty"`
		Salt              *string  `json:"salt,omitempty"`
		Owners            []string `json:"owners"`
		Threshold         int      `json:"threshold"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Chain == "" || req.WalletType == "" || len(req.Owners) == 0 || req.Threshold == 0 {
		writeError(w, http.StatusBadRequest, "chain, wallet_type, owners, and threshold are required")
		return
	}

	// Verify wallet belongs to org
	var ethAddress *string
	err := s.db.Pool.QueryRow(r.Context(),
		`SELECT eth_address FROM wallets WHERE id = $1 AND org_id = $2`,
		walletID, orgID).Scan(&ethAddress)
	if err != nil {
		writeError(w, http.StatusNotFound, "wallet not found")
		return
	}

	// TODO: Deploy smart wallet via Safe SDK or ERC-4337 factory
	// For now, record the intent
	contractAddress := "0x0000000000000000000000000000000000000000" // placeholder

	var sw db.SmartWallet
	err = s.db.Pool.QueryRow(r.Context(),
		`INSERT INTO smart_wallets (wallet_id, org_id, chain, contract_address, wallet_type,
		 factory_address, entrypoint_address, salt, owners, threshold)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		 RETURNING id, wallet_id, org_id, chain, contract_address, wallet_type,
		 factory_address, entrypoint_address, salt, owners, threshold, status, deployed_at, created_at`,
		walletID, orgID, req.Chain, contractAddress, req.WalletType,
		req.FactoryAddress, req.EntrypointAddress, req.Salt, req.Owners, req.Threshold).
		Scan(&sw.ID, &sw.WalletID, &sw.OrgID, &sw.Chain, &sw.ContractAddress,
			&sw.WalletType, &sw.FactoryAddress, &sw.EntrypointAddress, &sw.Salt,
			&sw.Owners, &sw.Threshold, &sw.Status, &sw.DeployedAt, &sw.CreatedAt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create smart wallet: "+err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, sw)
}

func (s *Server) handleListSmartWallets(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	walletID := urlParam(r, "id")

	rows, err := s.db.Pool.Query(r.Context(),
		`SELECT id, wallet_id, org_id, chain, contract_address, wallet_type,
		        factory_address, entrypoint_address, salt, owners, threshold,
		        status, deployed_at, created_at
		 FROM smart_wallets WHERE wallet_id = $1 AND org_id = $2
		 ORDER BY created_at DESC`, walletID, orgID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	var wallets []db.SmartWallet
	for rows.Next() {
		var sw db.SmartWallet
		if err := rows.Scan(&sw.ID, &sw.WalletID, &sw.OrgID, &sw.Chain,
			&sw.ContractAddress, &sw.WalletType, &sw.FactoryAddress,
			&sw.EntrypointAddress, &sw.Salt, &sw.Owners, &sw.Threshold,
			&sw.Status, &sw.DeployedAt, &sw.CreatedAt); err != nil {
			continue
		}
		wallets = append(wallets, sw)
	}
	if wallets == nil {
		wallets = []db.SmartWallet{}
	}
	writeJSON(w, http.StatusOK, wallets)
}

func (s *Server) handleGetSmartWallet(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	swID := urlParam(r, "id")

	var sw db.SmartWallet
	err := s.db.Pool.QueryRow(r.Context(),
		`SELECT id, wallet_id, org_id, chain, contract_address, wallet_type,
		        factory_address, entrypoint_address, salt, owners, threshold,
		        status, deployed_at, created_at
		 FROM smart_wallets WHERE id = $1 AND org_id = $2`, swID, orgID).
		Scan(&sw.ID, &sw.WalletID, &sw.OrgID, &sw.Chain, &sw.ContractAddress,
			&sw.WalletType, &sw.FactoryAddress, &sw.EntrypointAddress, &sw.Salt,
			&sw.Owners, &sw.Threshold, &sw.Status, &sw.DeployedAt, &sw.CreatedAt)
	if err != nil {
		writeError(w, http.StatusNotFound, "smart wallet not found")
		return
	}
	writeJSON(w, http.StatusOK, sw)
}

func (s *Server) handleProposeSafeTx(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	swID := urlParam(r, "id")

	var req struct {
		To    string `json:"to"`
		Value string `json:"value"`
		Data  string `json:"data,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Verify smart wallet
	var walletID, chain string
	err := s.db.Pool.QueryRow(r.Context(),
		`SELECT wallet_id, chain FROM smart_wallets WHERE id = $1 AND org_id = $2`,
		swID, orgID).Scan(&walletID, &chain)
	if err != nil {
		writeError(w, http.StatusNotFound, "smart wallet not found")
		return
	}

	// TODO: Create Safe transaction proposal, sign with MPC
	writeJSON(w, http.StatusOK, map[string]string{
		"status":          "proposed",
		"smart_wallet_id": swID,
		"to":              req.To,
		"value":           req.Value,
	})
}

func (s *Server) handleExecuteSafeTx(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	swID := urlParam(r, "id")

	var req struct {
		SafeTxHash string `json:"safe_tx_hash"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var contractAddress string
	err := s.db.Pool.QueryRow(r.Context(),
		`SELECT contract_address FROM smart_wallets WHERE id = $1 AND org_id = $2`,
		swID, orgID).Scan(&contractAddress)
	if err != nil {
		writeError(w, http.StatusNotFound, "smart wallet not found")
		return
	}

	// TODO: Execute Safe transaction
	writeJSON(w, http.StatusOK, map[string]string{
		"status":        "executing",
		"safe_tx_hash":  req.SafeTxHash,
	})
}

func (s *Server) handleUserOperation(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	swID := urlParam(r, "id")

	var req struct {
		CallData string `json:"call_data"`
		Value    string `json:"value,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var walletType string
	err := s.db.Pool.QueryRow(r.Context(),
		`SELECT wallet_type FROM smart_wallets WHERE id = $1 AND org_id = $2`,
		swID, orgID).Scan(&walletType)
	if err != nil {
		writeError(w, http.StatusNotFound, "smart wallet not found")
		return
	}
	if walletType != "erc4337" {
		writeError(w, http.StatusBadRequest, "user operations only supported for ERC-4337 wallets")
		return
	}

	// TODO: Build and submit UserOperation
	writeJSON(w, http.StatusOK, map[string]string{
		"status":          "submitted",
		"smart_wallet_id": swID,
	})
}
