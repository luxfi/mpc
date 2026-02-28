package api

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"

	"github.com/luxfi/mpc/pkg/db"
)

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	rows, err := s.db.Pool.Query(r.Context(),
		`SELECT id, org_id, email, role, created_at FROM users WHERE org_id = $1
		 ORDER BY created_at`, orgID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	var users []db.User
	for rows.Next() {
		var u db.User
		if err := rows.Scan(&u.ID, &u.OrgID, &u.Email, &u.Role, &u.CreatedAt); err != nil {
			continue
		}
		users = append(users, u)
	}
	if users == nil {
		users = []db.User{}
	}
	writeJSON(w, http.StatusOK, users)
}

func (s *Server) handleInviteUser(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	role := getRole(r.Context())
	if role != "owner" && role != "admin" {
		writeError(w, http.StatusForbidden, "only owner or admin can invite users")
		return
	}

	var req struct {
		Email    string `json:"email"`
		Role     string `json:"role"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password are required")
		return
	}
	if req.Role == "" {
		req.Role = "viewer"
	}

	hash, err := hashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	var user db.User
	err = s.db.Pool.QueryRow(r.Context(),
		`INSERT INTO users (org_id, email, password_hash, role)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, org_id, email, role, created_at`,
		orgID, req.Email, hash, req.Role).
		Scan(&user.ID, &user.OrgID, &user.Email, &user.Role, &user.CreatedAt)
	if err != nil {
		writeError(w, http.StatusConflict, "email already registered")
		return
	}

	writeJSON(w, http.StatusCreated, user)
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	userID := urlParam(r, "id")

	var req struct {
		Role *string `json:"role,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var user db.User
	err := s.db.Pool.QueryRow(r.Context(),
		`UPDATE users SET role = COALESCE($1, role) WHERE id = $2 AND org_id = $3
		 RETURNING id, org_id, email, role, created_at`,
		req.Role, userID, orgID).
		Scan(&user.ID, &user.OrgID, &user.Email, &user.Role, &user.CreatedAt)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	writeJSON(w, http.StatusOK, user)
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	userID := urlParam(r, "id")

	tag, err := s.db.Pool.Exec(r.Context(),
		`DELETE FROM users WHERE id = $1 AND org_id = $2 AND role != 'owner'`,
		userID, orgID)
	if err != nil || tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "user not found or cannot delete owner")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// API Key handlers
func (s *Server) handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	rows, err := s.db.Pool.Query(r.Context(),
		`SELECT id, org_id, name, key_prefix, permissions, created_at, expires_at, last_used_at
		 FROM api_keys WHERE org_id = $1 ORDER BY created_at DESC`, orgID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	var keys []db.APIKey
	for rows.Next() {
		var k db.APIKey
		if err := rows.Scan(&k.ID, &k.OrgID, &k.Name, &k.KeyPrefix, &k.Permissions,
			&k.CreatedAt, &k.ExpiresAt, &k.LastUsedAt); err != nil {
			continue
		}
		keys = append(keys, k)
	}
	if keys == nil {
		keys = []db.APIKey{}
	}
	writeJSON(w, http.StatusOK, keys)
}

func (s *Server) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	var req struct {
		Name        string   `json:"name"`
		Permissions []string `json:"permissions,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	key, keyHash, err := generateAPIKeyToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate key")
		return
	}
	prefix := key[:8]

	var apiKey db.APIKey
	err = s.db.Pool.QueryRow(r.Context(),
		`INSERT INTO api_keys (org_id, name, key_hash, key_prefix, permissions)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, org_id, name, key_prefix, permissions, created_at`,
		orgID, req.Name, keyHash, prefix, req.Permissions).
		Scan(&apiKey.ID, &apiKey.OrgID, &apiKey.Name, &apiKey.KeyPrefix,
			&apiKey.Permissions, &apiKey.CreatedAt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create API key")
		return
	}

	// Return full key only once
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"id":          apiKey.ID,
		"name":        apiKey.Name,
		"key":         key,
		"key_prefix":  apiKey.KeyPrefix,
		"permissions": apiKey.Permissions,
		"created_at":  apiKey.CreatedAt,
	})
}

func (s *Server) handleDeleteAPIKey(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	keyID := urlParam(r, "id")

	tag, err := s.db.Pool.Exec(r.Context(),
		`DELETE FROM api_keys WHERE id = $1 AND org_id = $2`, keyID, orgID)
	if err != nil || tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "api key not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Suppress unused import
var _ = sha256.Sum256
