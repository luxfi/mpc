package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthMiddleware_ValidToken(t *testing.T) {
	s := newTestServer("middleware-secret")

	token, err := s.generateJWT("user-mid", "org-mid", "admin")
	if err != nil {
		t.Fatalf("generateJWT: %v", err)
	}

	// Handler that checks context values were set
	var gotUserID, gotOrgID, gotRole string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUserID = getUserID(r.Context())
		gotOrgID = getOrgID(r.Context())
		gotRole = getRole(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := s.authMiddleware(inner)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if gotUserID != "user-mid" {
		t.Errorf("UserID = %q, want %q", gotUserID, "user-mid")
	}
	if gotOrgID != "org-mid" {
		t.Errorf("OrgID = %q, want %q", gotOrgID, "org-mid")
	}
	if gotRole != "admin" {
		t.Errorf("Role = %q, want %q", gotRole, "admin")
	}
}

func TestAuthMiddleware_NoToken(t *testing.T) {
	s := newTestServer("middleware-secret")

	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	handler := s.authMiddleware(inner)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	// No Authorization header, no X-API-Key header
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if called {
		t.Error("inner handler should not have been called")
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["error"] != "missing authorization" {
		t.Errorf("error = %q, want %q", body["error"], "missing authorization")
	}
}

func TestAuthMiddleware_InvalidToken(t *testing.T) {
	s := newTestServer("middleware-secret")

	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	handler := s.authMiddleware(inner)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-token-data")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if called {
		t.Error("inner handler should not have been called")
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["error"] != "invalid token" {
		t.Errorf("error = %q, want %q", body["error"], "invalid token")
	}
}

func TestRequireRole_Allowed(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := requireRole("admin", "operator")(inner)

	// Set role=admin in context
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	ctx := context.WithValue(req.Context(), ctxRole, "admin")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !called {
		t.Error("inner handler should have been called")
	}
}

func TestRequireRole_Denied(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	handler := requireRole("admin")(inner)

	// Set role=viewer in context (not in allowed list)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	ctx := context.WithValue(req.Context(), ctxRole, "viewer")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if called {
		t.Error("inner handler should not have been called")
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["error"] != "insufficient permissions" {
		t.Errorf("error = %q, want %q", body["error"], "insufficient permissions")
	}
}

func TestRequireRole_NoRoleInContext(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	handler := requireRole("admin")(inner)

	// No role in context at all
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if called {
		t.Error("inner handler should not have been called")
	}
}

// R2-3: requireRoleOrAPIPermission must admit human roles on their role
// alone, but require API-key callers to carry the explicit permission. A
// bare "api" role with permissions=[] must be rejected.
func TestRequireRoleOrAPIPermission(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	gate := requireRoleOrAPIPermission([]string{"owner", "admin", "signer"}, "mpc:sign")

	run := func(name, role string, perms []string, wantCode int) {
		t.Helper()
		called = false
		req := httptest.NewRequest(http.MethodPost, "/sign", nil)
		ctx := context.WithValue(req.Context(), ctxRole, role)
		if perms != nil {
			ctx = context.WithValue(ctx, ctxPermissions, perms)
		}
		req = req.WithContext(ctx)
		rec := httptest.NewRecorder()
		gate(inner).ServeHTTP(rec, req)
		if rec.Code != wantCode {
			t.Errorf("%s: status=%d want=%d body=%s", name, rec.Code, wantCode, rec.Body.String())
		}
	}

	// Human roles pass without any permission check.
	run("owner passes", "owner", nil, http.StatusOK)
	run("admin passes", "admin", nil, http.StatusOK)
	run("signer passes", "signer", nil, http.StatusOK)

	// API key with the right permission passes.
	run("api+mpc:sign passes", "api", []string{"mpc:sign"}, http.StatusOK)

	// R3-2: `*` wildcard is NOT honored. A misissued key with perms=["*"]
	// must be rejected on every named permission check — no god-key.
	run("api+* rejected (no wildcard)", "api", []string{"*"}, http.StatusForbidden)
	run("api+*-plus-unrelated rejected", "api", []string{"*", "unrelated:scope"}, http.StatusForbidden)

	// Bare API key without the permission — R2-3 regression.
	run("api+no-perms rejected", "api", []string{}, http.StatusForbidden)
	run("api+wrong-perm rejected", "api", []string{"sign"}, http.StatusForbidden)

	// Unknown role rejected.
	run("guest rejected", "guest", nil, http.StatusForbidden)
	run("empty rejected", "", nil, http.StatusForbidden)

	_ = called
}

// R3-2: assert wildcard does not bypass sensitive gates. Every one of
// these permission names must reject a `*`-only key. Done explicitly so
// a regression on any one of them fails the table row by name.
func TestRequireRoleOrAPIPermission_WildcardRejectedOnSensitive(t *testing.T) {
	sensitivePerms := []string{
		"mpc:sign",
		"mpc:settlement:sign",
		"mpc:operations:approve",
		"mpc:wallet:sweep",
		"mpc:policy:write",
	}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	for _, perm := range sensitivePerms {
		perm := perm
		t.Run("wildcard_rejects_"+perm, func(t *testing.T) {
			gate := requireRoleOrAPIPermission([]string{"owner", "admin", "signer"}, perm)
			req := httptest.NewRequest(http.MethodPost, "/sensitive", nil)
			ctx := context.WithValue(req.Context(), ctxRole, "api")
			ctx = context.WithValue(ctx, ctxPermissions, []string{"*"})
			req = req.WithContext(ctx)
			rec := httptest.NewRecorder()
			gate(inner).ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Errorf("perm=%q with permissions=[*] must be rejected; got %d body=%s",
					perm, rec.Code, rec.Body.String())
			}
		})
	}
}

// R3-2: assert requirePermission (the lower-level gate used by trade
// approval etc.) also no longer accepts `*` for a named permission.
func TestRequirePermission_WildcardRejected(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	gate := requirePermission("trade:submit")
	req := httptest.NewRequest(http.MethodPost, "/trade", nil)
	ctx := context.WithValue(req.Context(), ctxRole, "api")
	ctx = context.WithValue(ctx, ctxPermissions, []string{"*"})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	gate(inner).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("requirePermission must reject `*`; got %d body=%s",
			rec.Code, rec.Body.String())
	}
}

func TestRequireRole_MultipleAllowed(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := requireRole("admin", "operator", "api")(inner)

	// role=operator is in the allowed list
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	ctx := context.WithValue(req.Context(), ctxRole, "operator")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !called {
		t.Error("inner handler should have been called")
	}
}

func TestContextHelpers(t *testing.T) {
	// Empty context returns zero values
	ctx := context.Background()
	if v := getUserID(ctx); v != "" {
		t.Errorf("getUserID(empty) = %q, want empty", v)
	}
	if v := getOrgID(ctx); v != "" {
		t.Errorf("getOrgID(empty) = %q, want empty", v)
	}
	if v := getRole(ctx); v != "" {
		t.Errorf("getRole(empty) = %q, want empty", v)
	}

	// With values
	ctx = context.WithValue(ctx, ctxUserID, "u1")
	ctx = context.WithValue(ctx, ctxOrgID, "o1")
	ctx = context.WithValue(ctx, ctxRole, "admin")
	if v := getUserID(ctx); v != "u1" {
		t.Errorf("getUserID = %q, want %q", v, "u1")
	}
	if v := getOrgID(ctx); v != "o1" {
		t.Errorf("getOrgID = %q, want %q", v, "o1")
	}
	if v := getRole(ctx); v != "admin" {
		t.Errorf("getRole = %q, want %q", v, "admin")
	}
}

func TestWriteJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSON(rec, http.StatusCreated, map[string]string{"msg": "ok"})

	if rec.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusCreated)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["msg"] != "ok" {
		t.Errorf("body[msg] = %q, want %q", body["msg"], "ok")
	}
}

func TestWriteError(t *testing.T) {
	rec := httptest.NewRecorder()
	writeError(rec, http.StatusBadRequest, "bad input")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["error"] != "bad input" {
		t.Errorf("body[error] = %q, want %q", body["error"], "bad input")
	}
}

func TestNilIfEmpty(t *testing.T) {
	if v := nilIfEmpty(""); v != nil {
		t.Errorf("nilIfEmpty(\"\") = %v, want nil", v)
	}
	if v := nilIfEmpty("hello"); v == nil || *v != "hello" {
		t.Errorf("nilIfEmpty(\"hello\") = %v, want *\"hello\"", v)
	}
}
