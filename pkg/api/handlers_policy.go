package api

import (
	"encoding/json"
	"net/http"

	"github.com/hanzoai/orm"
	"github.com/luxfi/mpc/pkg/db"
)

func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	policies, err := orm.TypedQuery[db.Policy](s.db.ORM).
		Filter("orgId =", orgID).
		Order("-priority").
		GetAll(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if policies == nil {
		policies = []*db.Policy{}
	}
	writeJSON(w, http.StatusOK, policies)
}

func (s *Server) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	var req struct {
		VaultID           *string         `json:"vault_id,omitempty"`
		Name              string          `json:"name"`
		Priority          int             `json:"priority"`
		Action            string          `json:"action"`
		Conditions        json.RawMessage `json:"conditions"`
		RequiredApprovers int             `json:"required_approvers"`
		ApproverRoles     []string        `json:"approver_roles"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" || req.Action == "" {
		writeError(w, http.StatusBadRequest, "name and action are required")
		return
	}

	policy := orm.New[db.Policy](s.db.ORM)
	policy.OrgID = orgID
	policy.VaultID = req.VaultID
	policy.Name = req.Name
	policy.Priority = req.Priority
	policy.Action = req.Action
	policy.Conditions = []byte(req.Conditions)
	policy.RequiredApprovers = req.RequiredApprovers
	policy.ApproverRoles = req.ApproverRoles
	policy.Enabled = true
	if err := policy.Create(); err != nil {
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

	policy, err := orm.Get[db.Policy](s.db.ORM, policyID)
	if err != nil || policy.OrgID != orgID {
		writeError(w, http.StatusNotFound, "policy not found")
		return
	}

	if req.Name != nil {
		policy.Name = *req.Name
	}
	if req.Priority != nil {
		policy.Priority = *req.Priority
	}
	if req.Action != nil {
		policy.Action = *req.Action
	}
	if req.Conditions != nil {
		policy.Conditions = []byte(*req.Conditions)
	}
	if req.RequiredApprovers != nil {
		policy.RequiredApprovers = *req.RequiredApprovers
	}
	if req.Enabled != nil {
		policy.Enabled = *req.Enabled
	}
	if err := policy.Update(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update policy")
		return
	}

	writeJSON(w, http.StatusOK, policy)
}

func (s *Server) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	policyID := urlParam(r, "id")

	policy, err := orm.Get[db.Policy](s.db.ORM, policyID)
	if err != nil || policy.OrgID != orgID {
		writeError(w, http.StatusNotFound, "policy not found")
		return
	}

	if err := policy.Delete(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete policy")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
