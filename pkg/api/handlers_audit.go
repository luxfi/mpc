package api

import (
	"net/http"

	"github.com/luxfi/mpc/pkg/db"
)

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	rows, err := s.db.Pool.Query(r.Context(),
		`SELECT id, org_id, user_id, action, resource_type, resource_id,
		        details, ip_address, created_at
		 FROM audit_log WHERE org_id = $1 ORDER BY created_at DESC LIMIT 200`, orgID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	var entries []db.AuditEntry
	for rows.Next() {
		var e db.AuditEntry
		if err := rows.Scan(&e.ID, &e.OrgID, &e.UserID, &e.Action,
			&e.ResourceType, &e.ResourceID, &e.Details, &e.IPAddress,
			&e.CreatedAt); err != nil {
			continue
		}
		entries = append(entries, e)
	}
	if entries == nil {
		entries = []db.AuditEntry{}
	}
	writeJSON(w, http.StatusOK, entries)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	status := s.mpc.GetClusterStatus()
	if status == nil {
		writeJSON(w, http.StatusOK, map[string]string{"status": "unknown"})
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"name":             "Lux MPC",
		"version":          "0.3.3",
		"supported_chains": []string{"ethereum", "bitcoin", "solana", "lux"},
		"key_types":        []string{"secp256k1", "ed25519"},
		"protocols":        []string{"CGGMP21", "FROST", "LSS"},
	})
}
