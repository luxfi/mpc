package api

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"

	"github.com/hanzoai/orm"

	"github.com/luxfi/mpc/pkg/db"
)

// userView is the safe API representation — never exposes passwordHash or mfaSecret.
type userView struct {
	ID        string `json:"id"`
	CreatedAt any    `json:"createdAt"`
	OrgID     string `json:"orgId"`
	Email     string `json:"email"`
	Role      string `json:"role"`
}

func safeUser(u *db.User) userView {
	return userView{ID: u.Id(), CreatedAt: u.CreatedAt, OrgID: u.OrgID, Email: u.Email, Role: u.Role}
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	users, err := orm.TypedQuery[db.User](s.db.ORM).
		Filter("orgId=", orgID).
		Order("createdAt").
		GetAll(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	views := make([]userView, 0, len(users))
	for _, u := range users {
		views = append(views, safeUser(u))
	}
	writeJSON(w, http.StatusOK, views)
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

	user := orm.New[db.User](s.db.ORM)
	user.OrgID = orgID
	user.Email = req.Email
	user.PasswordHash = hash
	user.Role = req.Role
	if err := user.Create(); err != nil {
		writeError(w, http.StatusConflict, "email already registered")
		return
	}

	writeJSON(w, http.StatusCreated, safeUser(user))
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

	user, err := orm.Get[db.User](s.db.ORM, userID)
	if err != nil || user.OrgID != orgID {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	if req.Role != nil {
		user.Role = *req.Role
	}
	if err := user.Update(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update user")
		return
	}

	writeJSON(w, http.StatusOK, safeUser(user))
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	userID := urlParam(r, "id")

	user, err := orm.Get[db.User](s.db.ORM, userID)
	if err != nil || user.OrgID != orgID {
		writeError(w, http.StatusNotFound, "user not found or cannot delete owner")
		return
	}
	if user.Role == "owner" {
		writeError(w, http.StatusNotFound, "user not found or cannot delete owner")
		return
	}

	if err := user.Delete(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete user")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// API Key handlers

type apiKeyView struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	KeyPrefix   string   `json:"keyPrefix"`
	Permissions []string `json:"permissions"`
	ExpiresAt   any      `json:"expiresAt,omitempty"`
	LastUsedAt  any      `json:"lastUsedAt,omitempty"`
	CreatedAt   any      `json:"createdAt"`
}

func (s *Server) handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgID(r.Context())
	keys, err := orm.TypedQuery[db.APIKey](s.db.ORM).
		Filter("orgId=", orgID).
		Order("-createdAt").
		GetAll(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	views := make([]apiKeyView, 0, len(keys))
	for _, k := range keys {
		views = append(views, apiKeyView{
			ID: k.Id(), Name: k.Name, KeyPrefix: k.KeyPrefix,
			Permissions: k.Permissions, ExpiresAt: k.ExpiresAt,
			LastUsedAt: k.LastUsedAt, CreatedAt: k.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, views)
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

	apiKey := orm.New[db.APIKey](s.db.ORM)
	apiKey.OrgID = orgID
	apiKey.Name = req.Name
	apiKey.KeyHash = keyHash
	apiKey.KeyPrefix = prefix
	apiKey.Permissions = req.Permissions
	if err := apiKey.Create(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create API key")
		return
	}

	// Return full key only once
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"id":          apiKey.Id(),
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

	apiKey, err := orm.Get[db.APIKey](s.db.ORM, keyID)
	if err != nil || apiKey.OrgID != orgID {
		writeError(w, http.StatusNotFound, "api key not found")
		return
	}

	if err := apiKey.Delete(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete api key")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Suppress unused import
var _ = sha256.Sum256
