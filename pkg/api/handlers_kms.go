// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// ValidatorKeySet holds the MPC wallet reference for a validator's custodied
// "Corona" slot key.
//
// NAMING (truthful): the "Corona" slot is ed25519 signed via FROST threshold.
// It is NOT post-quantum and NOT the Corona R-LWE lattice protocol (that is a
// separate primitive in luxfi/threshold's dispatcher) — "Corona" here is a
// legacy slot label, not a PQ claim. Likewise the paired "BLS" slot is
// secp256k1/CGGMP21 threshold ECDSA, not bls12-381 aggregation.
//
// The validator's real BLS consensus key is deliberately NOT here: it is a
// native per-validator bls12-381 key (PoP + signature aggregation, the
// consensus fast-path) held by the validator itself, never threshold-custodied
// by this service. Only the ed25519/FROST "Corona" slot is custodied here
// (dealerless DKG).
type ValidatorKeySet struct {
	ValidatorID     string    `json:"validatorId"`
	CoronaWalletID  string    `json:"coronaWalletId"`
	CoronaPublicKey string    `json:"coronaPublicKey"`
	Threshold       int       `json:"threshold"`
	Parties         int       `json:"parties"`
	Status          string    `json:"status"`
	CreatedAt       time.Time `json:"createdAt"`
	UpdatedAt       time.Time `json:"updatedAt"`
}

type kmsGenerateRequest struct {
	ValidatorID string `json:"validator_id"`
	Threshold   int    `json:"threshold"`
	Parties     int    `json:"parties"`
}

type kmsRotateRequest struct {
	NewThreshold    int      `json:"new_threshold,omitempty"`
	NewParticipants []string `json:"new_participants,omitempty"`
}

type kmsSignRequest struct {
	KeyType string `json:"key_type"`
	Message []byte `json:"message"`
}

const kmsKind = "validator_keys"

// registerKMSRoutes adds validator key management routes to the MPC API.
// These replace the standalone KMS server — one binary for both.
func (s *Server) registerKMSRoutes(r chi.Router) {
	r.Route("/v1/keys", func(r chi.Router) {
		r.Post("/generate", s.handleKMSGenerate)
		r.Get("/", s.handleKMSList)
		r.Get("/{id}", s.handleKMSGet)
		r.Post("/{id}/sign", s.handleKMSSign)
		r.Post("/{id}/rotate", s.handleKMSRotate)
	})
}

func (s *Server) handleKMSGenerate(w http.ResponseWriter, r *http.Request) {
	var req kmsGenerateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.ValidatorID == "" {
		writeError(w, http.StatusBadRequest, "validator_id is required")
		return
	}
	if req.Threshold < 2 {
		writeError(w, http.StatusBadRequest, "threshold must be >= 2")
		return
	}
	if req.Parties < req.Threshold {
		writeError(w, http.StatusBadRequest, "parties must be >= threshold")
		return
	}

	orgID := getOrgID(r.Context())

	// Check duplicate.
	if s.db != nil {
		var existing ValidatorKeySet
		key := s.db.ORM.NewKey(kmsKind, req.ValidatorID, 0, nil)
		if err := s.db.ORM.Get(r.Context(), key, &existing); err == nil {
			writeError(w, http.StatusConflict, fmt.Sprintf("validator %s already exists", req.ValidatorID))
			return
		}
	}

	// Custody only the Corona PQ-threshold key (dealerless DKG). The validator's
	// BLS consensus key is native (held by the validator's node), never
	// threshold-custodied here.
	coronaWalletID := fmt.Sprintf("validator-%s-corona", req.ValidatorID)
	coronaResult, err := s.mpc.TriggerKeygen(orgID, coronaWalletID)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	now := time.Now().UTC()
	ks := &ValidatorKeySet{
		ValidatorID:     req.ValidatorID,
		CoronaWalletID:  coronaResult.WalletID,
		CoronaPublicKey: coronaResult.EDDSAPubKey,
		Threshold:       req.Threshold,
		Parties:         req.Parties,
		Status:          "active",
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	if s.db != nil {
		key := s.db.ORM.NewKey(kmsKind, req.ValidatorID, 0, nil)
		if _, err := s.db.ORM.Put(r.Context(), key, ks); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	writeJSON(w, http.StatusCreated, ks)
}

func (s *Server) handleKMSList(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		writeJSON(w, http.StatusOK, []ValidatorKeySet{})
		return
	}

	q := s.db.ORM.Query(kmsKind)
	var sets []ValidatorKeySet
	if _, err := q.GetAll(r.Context(), &sets); err != nil {
		writeJSON(w, http.StatusOK, []ValidatorKeySet{})
		return
	}
	writeJSON(w, http.StatusOK, sets)
}

func (s *Server) handleKMSGet(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if s.db == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}

	var ks ValidatorKeySet
	key := s.db.ORM.NewKey(kmsKind, id, 0, nil)
	if err := s.db.ORM.Get(r.Context(), key, &ks); err != nil {
		writeError(w, http.StatusNotFound, "validator key set not found")
		return
	}
	writeJSON(w, http.StatusOK, ks)
}

func (s *Server) handleKMSSign(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var req kmsSignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Message) == 0 {
		writeError(w, http.StatusBadRequest, "message is required")
		return
	}

	orgID := getOrgID(r.Context())

	ks, err := s.kmsGetValidator(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "validator key set not found")
		return
	}

	var walletID string
	switch req.KeyType {
	case "corona":
		walletID = ks.CoronaWalletID
	default:
		writeError(w, http.StatusBadRequest, "key_type must be 'corona'")
		return
	}

	result, err := s.mpc.TriggerSign(orgID, walletID, req.Message)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"signature": result.Signature,
		"r":         result.R,
		"s":         result.S,
		"v":         result.V,
	})
}

func (s *Server) handleKMSRotate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var req kmsRotateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.NewThreshold == 0 && len(req.NewParticipants) == 0 {
		writeError(w, http.StatusBadRequest, "new_threshold or new_participants required")
		return
	}

	orgID := getOrgID(r.Context())

	ks, err := s.kmsGetValidator(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "validator key set not found")
		return
	}

	if err := s.mpc.TriggerReshare(orgID, ks.CoronaWalletID, req.NewThreshold, req.NewParticipants); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("corona reshare: %v", err))
		return
	}

	if req.NewThreshold > 0 {
		ks.Threshold = req.NewThreshold
	}
	if len(req.NewParticipants) > 0 {
		ks.Parties = len(req.NewParticipants)
	}
	ks.UpdatedAt = time.Now().UTC()

	if s.db != nil {
		key := s.db.ORM.NewKey(kmsKind, id, 0, nil)
		s.db.ORM.Put(r.Context(), key, ks)
	}

	writeJSON(w, http.StatusOK, ks)
}

func (s *Server) kmsGetValidator(ctx context.Context, id string) (*ValidatorKeySet, error) {
	if s.db == nil {
		return nil, fmt.Errorf("no database")
	}
	var ks ValidatorKeySet
	key := s.db.ORM.NewKey(kmsKind, id, 0, nil)
	if err := s.db.ORM.Get(ctx, key, &ks); err != nil {
		return nil, err
	}
	return &ks, nil
}
