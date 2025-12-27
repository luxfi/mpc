package api

import (
	"net/http"

	"github.com/hanzoai/orm"
	"github.com/luxfi/mpc/pkg/db"
)

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	entries, err := orm.TypedQuery[db.AuditEntry](s.db.ORM).
		Filter("orgId =", orgID).
		Order("-createdAt").
		Limit(200).
		GetAll(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	if entries == nil {
		entries = []*db.AuditEntry{}
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
