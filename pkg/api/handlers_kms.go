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

// ValidatorKeySet holds MPC wallet references for a validator's BLS and Ringtail keys.
type ValidatorKeySet struct {
	ValidatorID       string    `json:"validatorId"`
	BLSWalletID       string    `json:"blsWalletId"`
	RingtailWalletID  string    `json:"ringtailWalletId"`
	BLSPublicKey      string    `json:"blsPublicKey"`
	RingtailPublicKey string    `json:"ringtailPublicKey"`
	Threshold         int       `json:"threshold"`
	Parties           int       `json:"parties"`
	Status            string    `json:"status"`
	CreatedAt         time.Time `json:"createdAt"`
	UpdatedAt         time.Time `json:"updatedAt"`
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
	r.Route("/api/v1/keys", func(r chi.Router) {
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
		writeKMSError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.ValidatorID == "" {
		writeKMSError(w, http.StatusBadRequest, "validator_id is required")
		return
	}
	if req.Threshold < 2 {
		writeKMSError(w, http.StatusBadRequest, "threshold must be >= 2")
		return
	}
	if req.Parties < req.Threshold {
		writeKMSError(w, http.StatusBadRequest, "parties must be >= threshold")
		return
	}

	orgID := r.Header.Get("X-Org-ID")
	if orgID == "" {
		orgID = "default"
	}

	// Check duplicate.
	if s.db != nil {
		var existing ValidatorKeySet
		key := s.db.ORM.NewKey(kmsKind, req.ValidatorID, 0, nil)
		if err := s.db.ORM.Get(r.Context(), key, &existing); err == nil {
			writeKMSError(w, http.StatusConflict, fmt.Sprintf("validator %s already exists", req.ValidatorID))
			return
		}
	}

	blsWalletID := fmt.Sprintf("validator-%s-bls", req.ValidatorID)
	blsResult, err := s.mpc.TriggerKeygen(orgID, blsWalletID)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			writeKMSError(w, http.StatusConflict, err.Error())
			return
		}
		writeKMSError(w, http.StatusInternalServerError, err.Error())
		return
	}

	ringtailWalletID := fmt.Sprintf("validator-%s-ringtail", req.ValidatorID)
	ringtailResult, err := s.mpc.TriggerKeygen(orgID, ringtailWalletID)
	if err != nil {
		writeKMSError(w, http.StatusInternalServerError, err.Error())
		return
	}

	now := time.Now().UTC()
	ks := &ValidatorKeySet{
		ValidatorID:       req.ValidatorID,
		BLSWalletID:       blsResult.WalletID,
		RingtailWalletID:  ringtailResult.WalletID,
		BLSPublicKey:      blsResult.ECDSAPubKey,
		RingtailPublicKey: ringtailResult.EDDSAPubKey,
		Threshold:         req.Threshold,
		Parties:           req.Parties,
		Status:            "active",
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	if s.db != nil {
		key := s.db.ORM.NewKey(kmsKind, req.ValidatorID, 0, nil)
		if _, err := s.db.ORM.Put(r.Context(), key, ks); err != nil {
			writeKMSError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	writeKMSJSON(w, http.StatusCreated, ks)
}

func (s *Server) handleKMSList(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		writeKMSJSON(w, http.StatusOK, []ValidatorKeySet{})
		return
	}

	q := s.db.ORM.Query(kmsKind)
	var sets []ValidatorKeySet
	if _, err := q.GetAll(r.Context(), &sets); err != nil {
		writeKMSJSON(w, http.StatusOK, []ValidatorKeySet{})
		return
	}
	writeKMSJSON(w, http.StatusOK, sets)
}

func (s *Server) handleKMSGet(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if s.db == nil {
		writeKMSError(w, http.StatusNotFound, "not found")
		return
	}

	var ks ValidatorKeySet
	key := s.db.ORM.NewKey(kmsKind, id, 0, nil)
	if err := s.db.ORM.Get(r.Context(), key, &ks); err != nil {
		writeKMSError(w, http.StatusNotFound, "validator key set not found")
		return
	}
	writeKMSJSON(w, http.StatusOK, ks)
}

func (s *Server) handleKMSSign(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var req kmsSignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeKMSError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Message) == 0 {
		writeKMSError(w, http.StatusBadRequest, "message is required")
		return
	}

	orgID := r.Header.Get("X-Org-ID")
	if orgID == "" {
		orgID = "default"
	}

	ks, err := s.kmsGetValidator(r.Context(), id)
	if err != nil {
		writeKMSError(w, http.StatusNotFound, "validator key set not found")
		return
	}

	var walletID string
	switch req.KeyType {
	case "bls":
		walletID = ks.BLSWalletID
	case "ringtail":
		walletID = ks.RingtailWalletID
	default:
		writeKMSError(w, http.StatusBadRequest, "key_type must be 'bls' or 'ringtail'")
		return
	}

	result, err := s.mpc.TriggerSign(orgID, walletID, req.Message)
	if err != nil {
		writeKMSError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeKMSJSON(w, http.StatusOK, map[string]string{
		"signature": result.Signature,
		"r":         result.R,
		"s":         result.S,
	})
}

func (s *Server) handleKMSRotate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var req kmsRotateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeKMSError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.NewThreshold == 0 && len(req.NewParticipants) == 0 {
		writeKMSError(w, http.StatusBadRequest, "new_threshold or new_participants required")
		return
	}

	orgID := r.Header.Get("X-Org-ID")
	if orgID == "" {
		orgID = "default"
	}

	ks, err := s.kmsGetValidator(r.Context(), id)
	if err != nil {
		writeKMSError(w, http.StatusNotFound, "validator key set not found")
		return
	}

	if err := s.mpc.TriggerReshare(orgID, ks.BLSWalletID, req.NewThreshold, req.NewParticipants); err != nil {
		writeKMSError(w, http.StatusInternalServerError, fmt.Sprintf("bls reshare: %v", err))
		return
	}
	if err := s.mpc.TriggerReshare(orgID, ks.RingtailWalletID, req.NewThreshold, req.NewParticipants); err != nil {
		writeKMSError(w, http.StatusInternalServerError, fmt.Sprintf("ringtail reshare: %v", err))
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

	writeKMSJSON(w, http.StatusOK, ks)
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

func writeKMSJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeKMSError(w http.ResponseWriter, code int, msg string) {
	writeKMSJSON(w, code, map[string]string{"error": msg})
}
