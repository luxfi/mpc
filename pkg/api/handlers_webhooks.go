package api

import (
	"encoding/json"
	"net/http"

	"github.com/hanzoai/orm"

	"github.com/luxfi/mpc/pkg/db"
)

func (s *Server) handleListWebhooks(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	webhooks, err := orm.TypedQuery[db.Webhook](s.db.ORM).
		Filter("orgId=", orgID).
		Order("-createdAt").
		GetAll(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if webhooks == nil {
		webhooks = []*db.Webhook{}
	}
	writeJSON(w, http.StatusOK, webhooks)
}

func (s *Server) handleCreateWebhook(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	var req struct {
		URL    string   `json:"url"`
		Events []string `json:"events"`
		Secret string   `json:"secret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.URL == "" || len(req.Events) == 0 || req.Secret == "" {
		writeError(w, http.StatusBadRequest, "url, events, and secret are required")
		return
	}

	wh := orm.New[db.Webhook](s.db.ORM)
	wh.OrgID = orgID
	wh.URL = req.URL
	wh.Secret = req.Secret
	wh.Events = req.Events
	wh.Enabled = true
	if err := wh.Create(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create webhook")
		return
	}
	writeJSON(w, http.StatusCreated, wh)
}

func (s *Server) handleUpdateWebhook(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	whID := urlParam(r, "id")

	var req struct {
		URL     *string  `json:"url,omitempty"`
		Events  []string `json:"events,omitempty"`
		Enabled *bool    `json:"enabled,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	wh, err := orm.Get[db.Webhook](s.db.ORM, whID)
	if err != nil || wh.OrgID != orgID {
		writeError(w, http.StatusNotFound, "webhook not found")
		return
	}

	if req.URL != nil {
		wh.URL = *req.URL
	}
	if len(req.Events) > 0 {
		wh.Events = req.Events
	}
	if req.Enabled != nil {
		wh.Enabled = *req.Enabled
	}
	if err := wh.Update(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update webhook")
		return
	}
	writeJSON(w, http.StatusOK, wh)
}

func (s *Server) handleDeleteWebhook(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	whID := urlParam(r, "id")

	wh, err := orm.Get[db.Webhook](s.db.ORM, whID)
	if err != nil || wh.OrgID != orgID {
		writeError(w, http.StatusNotFound, "webhook not found")
		return
	}

	if err := wh.Delete(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete webhook")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleTestWebhook(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	whID := urlParam(r, "id")

	wh, err := orm.Get[db.Webhook](s.db.ORM, whID)
	if err != nil || wh.OrgID != orgID {
		writeError(w, http.StatusNotFound, "webhook not found")
		return
	}

	testPayload := map[string]interface{}{
		"event": "test",
		"data":  map[string]string{"message": "test webhook delivery"},
	}
	go deliverWebhook(wh.URL, wh.Secret, testPayload)
	writeJSON(w, http.StatusOK, map[string]string{"status": "test event sent"})
}

// Whitelist handlers

func (s *Server) handleListWhitelist(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	entries, err := orm.TypedQuery[db.AddressWhitelist](s.db.ORM).
		Filter("orgId=", orgID).
		Order("-createdAt").
		GetAll(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if entries == nil {
		entries = []*db.AddressWhitelist{}
	}
	writeJSON(w, http.StatusOK, entries)
}

func (s *Server) handleAddWhitelist(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	userID := getUserID(r.Context())

	var req struct {
		VaultID *string `json:"vault_id,omitempty"`
		Address string  `json:"address"`
		Chain   string  `json:"chain"`
		Label   *string `json:"label,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Address == "" || req.Chain == "" {
		writeError(w, http.StatusBadRequest, "address and chain are required")
		return
	}

	entry := orm.New[db.AddressWhitelist](s.db.ORM)
	entry.OrgID = orgID
	entry.VaultID = req.VaultID
	entry.Address = req.Address
	entry.Chain = req.Chain
	entry.Label = req.Label
	entry.CreatedBy = nilIfEmpty(userID)
	if err := entry.Create(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to add whitelist entry")
		return
	}
	writeJSON(w, http.StatusCreated, entry)
}

func (s *Server) handleDeleteWhitelist(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	entryID := urlParam(r, "id")

	entry, err := orm.Get[db.AddressWhitelist](s.db.ORM, entryID)
	if err != nil || entry.OrgID != orgID {
		writeError(w, http.StatusNotFound, "whitelist entry not found")
		return
	}

	if err := entry.Delete(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete whitelist entry")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
