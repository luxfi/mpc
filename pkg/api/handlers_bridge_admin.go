package api

import (
	"encoding/json"
	"net/http"

	"github.com/hanzoai/orm"

	"github.com/luxfi/mpc/pkg/db"
)

// handleGetBridgeConfig returns the org's bridge configuration.
func (s *Server) handleGetBridgeConfig(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())

	configs, err := orm.TypedQuery[db.BridgeConfig](s.db.ORM).
		Filter("orgId=", orgID).
		Limit(1).
		GetAll(r.Context())
	if err != nil || len(configs) == 0 {
		// Return defaults if no config exists
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"org_id":              orgID,
			"signing_wallet_id":   "",
			"fee_collector":       "",
			"fee_rate_bps":        100,
			"deposits_enabled":    true,
			"withdrawals_enabled": true,
		})
		return
	}
	writeJSON(w, http.StatusOK, configs[0])
}

// handleUpdateBridgeConfig updates the org's bridge configuration.
func (s *Server) handleUpdateBridgeConfig(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())

	var req struct {
		SigningWalletID    *string `json:"signing_wallet_id"`
		FeeCollector       *string `json:"fee_collector"`
		FeeRateBps         *int    `json:"fee_rate_bps"`
		MinFeeBps          *int    `json:"min_fee_bps"`
		MaxFeeBps          *int    `json:"max_fee_bps"`
		DepositsEnabled    *bool   `json:"deposits_enabled"`
		WithdrawalsEnabled *bool   `json:"withdrawals_enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Find or create config
	configs, _ := orm.TypedQuery[db.BridgeConfig](s.db.ORM).
		Filter("orgId=", orgID).
		Limit(1).
		GetAll(r.Context())

	var cfg *db.BridgeConfig
	if len(configs) > 0 {
		cfg = configs[0]
	} else {
		cfg = orm.New[db.BridgeConfig](s.db.ORM)
		cfg.OrgID = orgID
		cfg.FeeRateBps = 100
		cfg.DepositsEnabled = true
		cfg.WithdrawalsEnabled = true
	}

	if req.SigningWalletID != nil {
		cfg.SigningWalletID = *req.SigningWalletID
	}
	if req.FeeCollector != nil {
		cfg.FeeCollector = *req.FeeCollector
	}
	if req.FeeRateBps != nil {
		cfg.FeeRateBps = *req.FeeRateBps
	}
	if req.MinFeeBps != nil {
		cfg.MinFeeBps = *req.MinFeeBps
	}
	if req.MaxFeeBps != nil {
		cfg.MaxFeeBps = *req.MaxFeeBps
	}
	if req.DepositsEnabled != nil {
		cfg.DepositsEnabled = *req.DepositsEnabled
	}
	if req.WithdrawalsEnabled != nil {
		cfg.WithdrawalsEnabled = *req.WithdrawalsEnabled
	}

	var err error
	if len(configs) > 0 {
		err = cfg.Update()
	} else {
		err = cfg.Create()
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save config")
		return
	}

	writeJSON(w, http.StatusOK, cfg)
}

// handleListBridgeNetworks returns the supported bridge networks.
func (s *Server) handleListBridgeNetworks(w http.ResponseWriter, r *http.Request) {
	networks := []map[string]interface{}{
		{"chain": "ethereum", "name": "Ethereum", "type": "evm", "deposit": true, "withdrawal": true},
		{"chain": "lux", "name": "Lux Network", "type": "evm", "deposit": true, "withdrawal": true},
		{"chain": "bsc", "name": "BNB Smart Chain", "type": "evm", "deposit": true, "withdrawal": true},
		{"chain": "base", "name": "Base", "type": "evm", "deposit": true, "withdrawal": true},
		{"chain": "arbitrum", "name": "Arbitrum", "type": "evm", "deposit": true, "withdrawal": true},
		{"chain": "polygon", "name": "Polygon", "type": "evm", "deposit": true, "withdrawal": true},
		{"chain": "bitcoin", "name": "Bitcoin", "type": "utxo", "deposit": false, "withdrawal": false},
		{"chain": "solana", "name": "Solana", "type": "solana", "deposit": false, "withdrawal": false},
	}
	writeJSON(w, http.StatusOK, networks)
}
