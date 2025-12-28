package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/hanzoai/orm"

	"github.com/luxfi/mpc/pkg/db"
)

func (s *Server) handleListVaults(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	vaults, err := orm.TypedQuery[db.Vault](s.db.ORM).
		Filter("orgId=", orgID).
		Order("-createdAt").
		GetAll(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if vaults == nil {
		vaults = []*db.Vault{}
	}
	writeJSON(w, http.StatusOK, vaults)
}

func (s *Server) handleCreateVault(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	var req struct {
		Name        string  `json:"name"`
		Description *string `json:"description,omitempty"`
		AppID       *string `json:"app_id,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	v := orm.New[db.Vault](s.db.ORM)
	v.OrgID = orgID
	v.Name = req.Name
	v.Description = req.Description
	v.AppID = req.AppID
	if err := v.Create(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create vault")
		return
	}

	writeJSON(w, http.StatusCreated, v)
}

func (s *Server) handleGetVault(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	vaultID := urlParam(r, "id")

	vault, err := orm.Get[db.Vault](s.db.ORM, vaultID)
	if err != nil || vault.OrgID != orgID {
		writeError(w, http.StatusNotFound, "vault not found")
		return
	}

	writeJSON(w, http.StatusOK, vault)
}

func (s *Server) handleUpdateVault(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	vaultID := urlParam(r, "id")

	var req struct {
		Name        *string `json:"name,omitempty"`
		Description *string `json:"description,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	vault, err := orm.Get[db.Vault](s.db.ORM, vaultID)
	if err != nil || vault.OrgID != orgID {
		writeError(w, http.StatusNotFound, "vault not found")
		return
	}

	if req.Name != nil {
		vault.Name = *req.Name
	}
	if req.Description != nil {
		vault.Description = req.Description
	}
	if err := vault.Update(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update vault")
		return
	}

	writeJSON(w, http.StatusOK, vault)
}

func (s *Server) handleDeleteVault(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	vaultID := urlParam(r, "id")

	vault, err := orm.Get[db.Vault](s.db.ORM, vaultID)
	if err != nil || vault.OrgID != orgID {
		writeError(w, http.StatusNotFound, "vault not found")
		return
	}

	if err := vault.DeleteCtx(context.Background()); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete vault")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
