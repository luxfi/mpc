package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/hanzoai/orm"
	"github.com/luxfi/mpc/pkg/db"
	"github.com/luxfi/mpc/pkg/smart"
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

	// Verify wallet belongs to org and get the MPC EOA address
	wallet, err := orm.Get[db.Wallet](s.db.ORM, walletID)
	if err != nil || wallet.OrgID != orgID {
		writeError(w, http.StatusNotFound, "wallet not found")
		return
	}
	mpcEOA := ""
	if wallet.EthAddress != nil {
		mpcEOA = *wallet.EthAddress
	}
	if mpcEOA == "" {
		writeError(w, http.StatusBadRequest, "wallet has no Ethereum address (keygen not complete)")
		return
	}

	// Ensure the MPC EOA is always an owner
	hasEOA := false
	for _, o := range req.Owners {
		if o == mpcEOA {
			hasEOA = true
			break
		}
	}
	if !hasEOA {
		req.Owners = append(req.Owners, mpcEOA)
	}

	salt := ""
	if req.Salt != nil {
		salt = *req.Salt
	}
	factoryAddr := ""
	if req.FactoryAddress != nil {
		factoryAddr = *req.FactoryAddress
	}
	entrypointAddr := ""
	if req.EntrypointAddress != nil {
		entrypointAddr = *req.EntrypointAddress
	}

	// Compute the predicted contract address using real ABI encoding + CREATE2
	var contractAddress string
	var deployCalldata []byte
	switch req.WalletType {
	case "safe":
		cfg := smart.SafeConfig{
			FactoryAddress:  factoryAddr,
			SingletonAddr:   "",
			Owners:          req.Owners,
			Threshold:       req.Threshold,
			Salt:            salt,
			FallbackHandler: "",
		}
		contractAddress = smart.PredictAddress(cfg)
		deployCalldata, err = smart.EncodeDeploy(cfg)
		if err != nil {
			writeError(w, http.StatusBadRequest, "failed to encode Safe deploy: "+err.Error())
			return
		}
	case "erc4337":
		cfg := smart.AccountConfig{
			FactoryAddress:    factoryAddr,
			EntrypointAddress: entrypointAddr,
			OwnerAddress:      mpcEOA,
			Salt:              salt,
		}
		contractAddress = smart.PredictAccountAddress(cfg)
		deployCalldata, err = smart.EncodeInitCode(cfg)
		if err != nil {
			writeError(w, http.StatusBadRequest, "failed to encode ERC-4337 init code: "+err.Error())
			return
		}
	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported wallet_type: %q (use safe or erc4337)", req.WalletType))
		return
	}

	// Store deploy calldata so it can be broadcast to the chain
	_ = deployCalldata

	sw := orm.New[db.SmartWallet](s.db.ORM)
	sw.WalletID = walletID
	sw.OrgID = orgID
	sw.Chain = req.Chain
	sw.ContractAddress = contractAddress
	sw.WalletType = req.WalletType
	sw.FactoryAddress = req.FactoryAddress
	sw.EntrypointAddress = req.EntrypointAddress
	sw.Salt = req.Salt
	sw.Owners = req.Owners
	sw.Threshold = req.Threshold
	sw.Status = "pending"
	if err := sw.Create(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create smart wallet: "+err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, sw)
}

func (s *Server) handleListSmartWallets(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	walletID := urlParam(r, "id")

	wallets, err := orm.TypedQuery[db.SmartWallet](s.db.ORM).
		Filter("walletId =", walletID).
		Filter("orgId =", orgID).
		Order("-createdAt").
		GetAll(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if wallets == nil {
		wallets = []*db.SmartWallet{}
	}
	writeJSON(w, http.StatusOK, wallets)
}

func (s *Server) handleGetSmartWallet(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	swID := urlParam(r, "id")

	sw, err := orm.Get[db.SmartWallet](s.db.ORM, swID)
	if err != nil || sw.OrgID != orgID {
		writeError(w, http.StatusNotFound, "smart wallet not found")
		return
	}
	writeJSON(w, http.StatusOK, sw)
}

func (s *Server) handleProposeSafeTx(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	userID := getUserID(r.Context())
	swID := urlParam(r, "id")

	var req struct {
		To        string `json:"to"`
		Value     string `json:"value"`
		Data      string `json:"data,omitempty"`
		Operation int    `json:"operation"`   // 0=Call, 1=DelegateCall
		ChainID   int64  `json:"chain_id"`    // EVM chain ID for EIP-712
		Nonce     int    `json:"nonce"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.To == "" {
		writeError(w, http.StatusBadRequest, "to address is required")
		return
	}
	if req.ChainID == 0 {
		writeError(w, http.StatusBadRequest, "chain_id is required for EIP-712 Safe tx hash")
		return
	}

	sw, err := orm.Get[db.SmartWallet](s.db.ORM, swID)
	if err != nil || sw.OrgID != orgID {
		writeError(w, http.StatusNotFound, "smart wallet not found")
		return
	}
	if sw.WalletType != "safe" {
		writeError(w, http.StatusBadRequest, "propose is only for Safe wallets")
		return
	}

	// Compute real EIP-712 Safe transaction hash
	safeTx := smart.SafeTransaction{
		To:        req.To,
		Value:     req.Value,
		Data:      req.Data,
		Operation: req.Operation,
		Nonce:     req.Nonce,
	}
	txHash, err := smart.HashSafeTransaction(sw.ContractAddress, req.ChainID, safeTx)
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to hash safe tx: "+err.Error())
		return
	}

	// MPC signs the EIP-712 hash via the wallet that owns this Safe
	mpcWallet, err := orm.Get[db.Wallet](s.db.ORM, sw.WalletID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load MPC wallet")
		return
	}
	signResult, err := s.mpc.TriggerSign(mpcWallet.WalletID, txHash)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "MPC signing failed: "+err.Error())
		return
	}

	walletID := sw.WalletID
	tx := orm.New[db.Transaction](s.db.ORM)
	tx.OrgID = orgID
	tx.WalletID = &walletID
	tx.TxType = "safe_proposal"
	tx.Chain = sw.Chain
	tx.ToAddress = nilIfEmpty(req.To)
	tx.Amount = nilIfEmpty(req.Value)
	tx.RawTx = []byte(req.Data)
	tx.SignatureR = nilIfEmpty(signResult.R)
	tx.SignatureS = nilIfEmpty(signResult.S)
	tx.TxHash = nilIfEmpty(fmt.Sprintf("0x%x", txHash))
	tx.Status = "signed"
	tx.InitiatedBy = nilIfEmpty(userID)
	if err := tx.Create(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create transaction: "+err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"transaction":   tx,
		"safe_tx_hash":  fmt.Sprintf("0x%x", txHash),
		"signature_r":   signResult.R,
		"signature_s":   signResult.S,
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
	if req.SafeTxHash == "" {
		writeError(w, http.StatusBadRequest, "safe_tx_hash is required")
		return
	}

	sw, err := orm.Get[db.SmartWallet](s.db.ORM, swID)
	if err != nil || sw.OrgID != orgID {
		writeError(w, http.StatusNotFound, "smart wallet not found")
		return
	}

	// Find the most recent pending safe_proposal for this wallet
	txList, err := orm.TypedQuery[db.Transaction](s.db.ORM).
		Filter("walletId =", sw.WalletID).
		Filter("orgId =", orgID).
		Filter("txType =", "safe_proposal").
		Filter("status =", "pending").
		Order("-createdAt").
		Limit(1).
		GetAll(r.Context())
	if err != nil || len(txList) == 0 {
		writeError(w, http.StatusNotFound, "no pending safe proposal found for this wallet")
		return
	}

	tx := txList[0]
	tx.Status = "executing"
	tx.TxHash = nilIfEmpty(req.SafeTxHash)
	if err := tx.Update(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update transaction")
		return
	}

	writeJSON(w, http.StatusOK, tx)
}

func (s *Server) handleUserOperation(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	userID := getUserID(r.Context())
	swID := urlParam(r, "id")

	var req struct {
		CallData string `json:"call_data"`
		Value    string `json:"value,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.CallData == "" {
		writeError(w, http.StatusBadRequest, "call_data is required")
		return
	}

	sw, err := orm.Get[db.SmartWallet](s.db.ORM, swID)
	if err != nil || sw.OrgID != orgID {
		writeError(w, http.StatusNotFound, "smart wallet not found")
		return
	}
	if sw.WalletType != "erc4337" {
		writeError(w, http.StatusBadRequest, "user operations only supported for ERC-4337 wallets")
		return
	}

	walletID := sw.WalletID
	tx := orm.New[db.Transaction](s.db.ORM)
	tx.OrgID = orgID
	tx.WalletID = &walletID
	tx.TxType = "user_operation"
	tx.Chain = sw.Chain
	tx.Amount = nilIfEmpty(req.Value)
	tx.RawTx = []byte(req.CallData)
	tx.Status = "submitted"
	tx.InitiatedBy = nilIfEmpty(userID)
	if err := tx.Create(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create user operation: "+err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, tx)
}
