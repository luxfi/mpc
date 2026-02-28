package api

import (
	"encoding/json"
	"net/http"

	"github.com/luxfi/mpc/pkg/db"
)

func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	rows, err := s.db.Pool.Query(r.Context(),
		`SELECT id, org_id, vault_id, name, priority, action, conditions,
		        required_approvers, approver_roles, enabled, created_at
		 FROM policies WHERE org_id = $1 ORDER BY priority DESC`, orgID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	var policies []db.Policy
	for rows.Next() {
		var p db.Policy
		if err := rows.Scan(&p.ID, &p.OrgID, &p.VaultID, &p.Name, &p.Priority,
			&p.Action, &p.Conditions, &p.RequiredApprovers, &p.ApproverRoles,
			&p.Enabled, &p.CreatedAt); err != nil {
			continue
		}
		policies = append(policies, p)
	}
	if policies == nil {
		policies = []db.Policy{}
	}
	writeJSON(w, http.StatusOK, policies)
}

func (s *Server) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	var req struct {
		VaultID           *string  `json:"vault_id,omitempty"`
		Name              string   `json:"name"`
		Priority          int      `json:"priority"`
		Action            string   `json:"action"`
		Conditions        json.RawMessage `json:"conditions"`
		RequiredApprovers int      `json:"required_approvers"`
		ApproverRoles     []string `json:"approver_roles"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" || req.Action == "" {
		writeError(w, http.StatusBadRequest, "name and action are required")
		return
	}

	var policy db.Policy
	err := s.db.Pool.QueryRow(r.Context(),
		`INSERT INTO policies (org_id, vault_id, name, priority, action, conditions, required_approvers, approver_roles)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 RETURNING id, org_id, vault_id, name, priority, action, conditions,
		 required_approvers, approver_roles, enabled, created_at`,
		orgID, req.VaultID, req.Name, req.Priority, req.Action,
		[]byte(req.Conditions), req.RequiredApprovers, req.ApproverRoles).
		Scan(&policy.ID, &policy.OrgID, &policy.VaultID, &policy.Name, &policy.Priority,
			&policy.Action, &policy.Conditions, &policy.RequiredApprovers, &policy.ApproverRoles,
			&policy.Enabled, &policy.CreatedAt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create policy: "+err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, policy)
}

func (s *Server) handleUpdatePolicy(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	policyID := urlParam(r, "id")

	var req struct {
		Name              *string          `json:"name,omitempty"`
		Priority          *int             `json:"priority,omitempty"`
		Action            *string          `json:"action,omitempty"`
		Conditions        *json.RawMessage `json:"conditions,omitempty"`
		RequiredApprovers *int             `json:"required_approvers,omitempty"`
		Enabled           *bool            `json:"enabled,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var policy db.Policy
	err := s.db.Pool.QueryRow(r.Context(),
		`UPDATE policies SET
		 name = COALESCE($1, name),
		 priority = COALESCE($2, priority),
		 action = COALESCE($3, action),
		 conditions = COALESCE($4, conditions),
		 required_approvers = COALESCE($5, required_approvers),
		 enabled = COALESCE($6, enabled)
		 WHERE id = $7 AND org_id = $8
		 RETURNING id, org_id, vault_id, name, priority, action, conditions,
		 required_approvers, approver_roles, enabled, created_at`,
		req.Name, req.Priority, req.Action, req.Conditions,
		req.RequiredApprovers, req.Enabled, policyID, orgID).
		Scan(&policy.ID, &policy.OrgID, &policy.VaultID, &policy.Name, &policy.Priority,
			&policy.Action, &policy.Conditions, &policy.RequiredApprovers, &policy.ApproverRoles,
			&policy.Enabled, &policy.CreatedAt)
	if err != nil {
		writeError(w, http.StatusNotFound, "policy not found")
		return
	}

	writeJSON(w, http.StatusOK, policy)
}

func (s *Server) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	policyID := urlParam(r, "id")

	tag, err := s.db.Pool.Exec(r.Context(),
		`DELETE FROM policies WHERE id = $1 AND org_id = $2`, policyID, orgID)
	if err != nil || tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "policy not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
