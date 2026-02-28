package api

import (
	"encoding/json"
	"net/http"

	"github.com/luxfi/mpc/pkg/db"
)

func (s *Server) handleListWebhooks(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	rows, err := s.db.Pool.Query(r.Context(),
		`SELECT id, org_id, url, events, enabled, created_at
		 FROM webhooks WHERE org_id = $1 ORDER BY created_at DESC`, orgID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	var webhooks []db.Webhook
	for rows.Next() {
		var wh db.Webhook
		if err := rows.Scan(&wh.ID, &wh.OrgID, &wh.URL, &wh.Events,
			&wh.Enabled, &wh.CreatedAt); err != nil {
			continue
		}
		webhooks = append(webhooks, wh)
	}
	if webhooks == nil {
		webhooks = []db.Webhook{}
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

	var wh db.Webhook
	err := s.db.Pool.QueryRow(r.Context(),
		`INSERT INTO webhooks (org_id, url, secret, events)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, org_id, url, events, enabled, created_at`,
		orgID, req.URL, req.Secret, req.Events).
		Scan(&wh.ID, &wh.OrgID, &wh.URL, &wh.Events, &wh.Enabled, &wh.CreatedAt)
	if err != nil {
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

	var wh db.Webhook
	err := s.db.Pool.QueryRow(r.Context(),
		`UPDATE webhooks SET
		 url = COALESCE($1, url),
		 events = COALESCE($2, events),
		 enabled = COALESCE($3, enabled)
		 WHERE id = $4 AND org_id = $5
		 RETURNING id, org_id, url, events, enabled, created_at`,
		req.URL, req.Events, req.Enabled, whID, orgID).
		Scan(&wh.ID, &wh.OrgID, &wh.URL, &wh.Events, &wh.Enabled, &wh.CreatedAt)
	if err != nil {
		writeError(w, http.StatusNotFound, "webhook not found")
		return
	}
	writeJSON(w, http.StatusOK, wh)
}

func (s *Server) handleDeleteWebhook(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	whID := urlParam(r, "id")

	tag, err := s.db.Pool.Exec(r.Context(),
		`DELETE FROM webhooks WHERE id = $1 AND org_id = $2`, whID, orgID)
	if err != nil || tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "webhook not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleTestWebhook(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	whID := urlParam(r, "id")

	var url, secret string
	err := s.db.Pool.QueryRow(r.Context(),
		`SELECT url, secret FROM webhooks WHERE id = $1 AND org_id = $2`,
		whID, orgID).Scan(&url, &secret)
	if err != nil {
		writeError(w, http.StatusNotFound, "webhook not found")
		return
	}

	testPayload := map[string]interface{}{
		"event": "test",
		"data":  map[string]string{"message": "test webhook delivery"},
	}
	go deliverWebhook(url, secret, testPayload)
	writeJSON(w, http.StatusOK, map[string]string{"status": "test event sent"})
}

// Whitelist handlers
func (s *Server) handleListWhitelist(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	rows, err := s.db.Pool.Query(r.Context(),
		`SELECT id, org_id, vault_id, address, chain, label, created_by, created_at
		 FROM address_whitelist WHERE org_id = $1 ORDER BY created_at DESC`, orgID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	var entries []db.AddressWhitelist
	for rows.Next() {
		var e db.AddressWhitelist
		if err := rows.Scan(&e.ID, &e.OrgID, &e.VaultID, &e.Address, &e.Chain,
			&e.Label, &e.CreatedBy, &e.CreatedAt); err != nil {
			continue
		}
		entries = append(entries, e)
	}
	if entries == nil {
		entries = []db.AddressWhitelist{}
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

	var entry db.AddressWhitelist
	err := s.db.Pool.QueryRow(r.Context(),
		`INSERT INTO address_whitelist (org_id, vault_id, address, chain, label, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING id, org_id, vault_id, address, chain, label, created_by, created_at`,
		orgID, req.VaultID, req.Address, req.Chain, req.Label, userID).
		Scan(&entry.ID, &entry.OrgID, &entry.VaultID, &entry.Address, &entry.Chain,
			&entry.Label, &entry.CreatedBy, &entry.CreatedAt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to add whitelist entry")
		return
	}
	writeJSON(w, http.StatusCreated, entry)
}

func (s *Server) handleDeleteWhitelist(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	entryID := urlParam(r, "id")

	tag, err := s.db.Pool.Exec(r.Context(),
		`DELETE FROM address_whitelist WHERE id = $1 AND org_id = $2`, entryID, orgID)
	if err != nil || tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "whitelist entry not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
