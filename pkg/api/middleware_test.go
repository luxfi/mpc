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
