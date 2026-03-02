package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/hanzoai/orm"
	"github.com/luxfi/mpc/pkg/db"
)

type contextKey string

const (
	ctxUserID      contextKey = "user_id"
	ctxOrgID       contextKey = "org_id"
	ctxRole        contextKey = "role"
	ctxPermissions contextKey = "permissions"
)

func getUserID(ctx context.Context) string {
	v, _ := ctx.Value(ctxUserID).(string)
	return v
}

func getOrgID(ctx context.Context) string {
	v, _ := ctx.Value(ctxOrgID).(string)
	return v
}

func getRole(ctx context.Context) string {
	v, _ := ctx.Value(ctxRole).(string)
	return v
}

func getPermissions(ctx context.Context) []string {
	v, _ := ctx.Value(ctxPermissions).([]string)
	return v
}

func hasPermission(ctx context.Context, perm string) bool {
	for _, p := range getPermissions(ctx) {
		if p == perm || p == "*" {
			return true
		}
	}
	return false
}

func urlParam(r *http.Request, key string) string {
	return chi.URLParam(r, key)
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try JWT from Authorization header
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Bearer ") {
			token := strings.TrimPrefix(auth, "Bearer ")
			claims, err := s.validateJWT(token)
			if err != nil {
				writeError(w, http.StatusUnauthorized, "invalid token")
				return
			}
			ctx := context.WithValue(r.Context(), ctxUserID, claims.UserID)
			ctx = context.WithValue(ctx, ctxOrgID, claims.OrgID)
			ctx = context.WithValue(ctx, ctxRole, claims.Role)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// Try API key from X-API-Key header
		apiKeyHeader := r.Header.Get("X-API-Key")
		if apiKeyHeader != "" {
			key, err := s.validateAPIKey(r.Context(), apiKeyHeader)
			if err != nil {
				writeError(w, http.StatusUnauthorized, "invalid api key")
				return
			}
			ctx := context.WithValue(r.Context(), ctxOrgID, key.OrgID)
			ctx = context.WithValue(ctx, ctxRole, "api")
			ctx = context.WithValue(ctx, ctxPermissions, key.Permissions)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		writeError(w, http.StatusUnauthorized, "missing authorization")
	})
}

func (s *Server) auditMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		// Fire-and-forget audit log for mutating operations
		if r.Method != http.MethodGet {
			go s.writeAuditLog(r.Context(), r)
		}
	})
}

func requireRole(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			role := getRole(r.Context())
			for _, allowed := range roles {
				if role == allowed {
					next.ServeHTTP(w, r)
					return
				}
			}
			writeError(w, http.StatusForbidden, "insufficient permissions")
		})
	}
}

// requirePermission gates API key requests by checking their permissions slice.
// JWT-authenticated users (non-"api" role) pass through — role-based checks handle them.
func requirePermission(perm string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			role := getRole(r.Context())
			// JWT users: check role-based access, not per-permission
			if role != "api" {
				next.ServeHTTP(w, r)
				return
			}
			// API key users: must have the specific permission
			if !hasPermission(r.Context(), perm) {
				writeError(w, http.StatusForbidden, "api key missing permission: "+perm)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func (s *Server) writeAuditLog(ctx context.Context, r *http.Request) {
	orgID := getOrgID(ctx)
	userID := getUserID(ctx)
	if orgID == "" {
		return
	}

	action := r.Method + " " + r.URL.Path
	ip := r.RemoteAddr
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ip = strings.Split(xff, ",")[0]
	}

	entry := orm.New[db.AuditEntry](s.db.ORM)
	entry.OrgID = orgID
	entry.UserID = nilIfEmpty(userID)
	entry.Action = action
	entry.IPAddress = nilIfEmpty(ip)
	entry.Create()
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
