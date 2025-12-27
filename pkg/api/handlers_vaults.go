package api

import (
	"encoding/json"
	"net/http"

	"github.com/luxfi/mpc/pkg/db"
)

func (s *Server) handleListVaults(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	rows, err := s.db.Pool.Query(r.Context(),
		`SELECT id, org_id, name, description, app_id, created_at
		 FROM vaults WHERE org_id = $1 ORDER BY created_at DESC`, orgID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	var vaults []db.Vault
	for rows.Next() {
		var v db.Vault
		if err := rows.Scan(&v.ID, &v.OrgID, &v.Name, &v.Description, &v.AppID, &v.CreatedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "scan error")
			return
		}
		vaults = append(vaults, v)
	}
	if vaults == nil {
		vaults = []db.Vault{}
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

	var vault db.Vault
	err := s.db.Pool.QueryRow(r.Context(),
		`INSERT INTO vaults (org_id, name, description, app_id)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, org_id, name, description, app_id, created_at`,
		orgID, req.Name, req.Description, req.AppID).
		Scan(&vault.ID, &vault.OrgID, &vault.Name, &vault.Description, &vault.AppID, &vault.CreatedAt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create vault")
		return
	}

	writeJSON(w, http.StatusCreated, vault)
}

func (s *Server) handleGetVault(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	vaultID := urlParam(r, "id")

	var vault db.Vault
	err := s.db.Pool.QueryRow(r.Context(),
		`SELECT id, org_id, name, description, app_id, created_at
		 FROM vaults WHERE id = $1 AND org_id = $2`, vaultID, orgID).
		Scan(&vault.ID, &vault.OrgID, &vault.Name, &vault.Description, &vault.AppID, &vault.CreatedAt)
	if err != nil {
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

	var vault db.Vault
	err := s.db.Pool.QueryRow(r.Context(),
		`UPDATE vaults SET
		 name = COALESCE($1, name),
		 description = COALESCE($2, description)
		 WHERE id = $3 AND org_id = $4
		 RETURNING id, org_id, name, description, app_id, created_at`,
		req.Name, req.Description, vaultID, orgID).
		Scan(&vault.ID, &vault.OrgID, &vault.Name, &vault.Description, &vault.AppID, &vault.CreatedAt)
	if err != nil {
		writeError(w, http.StatusNotFound, "vault not found")
		return
	}

	writeJSON(w, http.StatusOK, vault)
}

func (s *Server) handleDeleteVault(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	vaultID := urlParam(r, "id")

	tag, err := s.db.Pool.Exec(r.Context(),
		`DELETE FROM vaults WHERE id = $1 AND org_id = $2`, vaultID, orgID)
	if err != nil || tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "vault not found")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
