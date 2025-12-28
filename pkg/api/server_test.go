package api

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMaxBodySize_SmallBody(t *testing.T) {
	// A body under the limit should pass through without error.
	limit := int64(1 << 20) // 1 MB
	handler := maxBodySize(limit)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeError(w, http.StatusRequestEntityTooLarge, "body too large")
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))

	payload := bytes.Repeat([]byte("a"), 1024) // 1 KB
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(payload))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if rec.Body.Len() != 1024 {
		t.Fatalf("body length = %d, want %d", rec.Body.Len(), 1024)
	}
}

func TestMaxBodySize_ExactlyAtLimit(t *testing.T) {
	limit := int64(1024)
	handler := maxBodySize(limit)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if err != nil {
			writeError(w, http.StatusRequestEntityTooLarge, "body too large")
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	payload := bytes.Repeat([]byte("x"), 1024)
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(payload))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestMaxBodySize_OverLimit(t *testing.T) {
	limit := int64(1024)
	handler := maxBodySize(limit)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if err != nil {
			// http.MaxBytesReader returns an error when the body exceeds the limit.
			writeError(w, http.StatusRequestEntityTooLarge, "body too large")
			return
		}
		// If we reach here, the middleware failed to enforce the limit.
		w.WriteHeader(http.StatusOK)
	}))

	// 2 KB body against 1 KB limit.
	payload := bytes.Repeat([]byte("x"), 2048)
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(payload))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestMaxBodySize_1MB_Production(t *testing.T) {
	// Verify the production limit (1 MB = 1 << 20) rejects 2 MB.
	limit := int64(1 << 20)
	handler := maxBodySize(limit)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if err != nil {
			writeError(w, http.StatusRequestEntityTooLarge, "body too large")
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	// 2 MB payload.
	payload := bytes.Repeat([]byte("A"), 2<<20)
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(payload))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestMaxBodySize_EmptyBody(t *testing.T) {
	limit := int64(1024)
	handler := maxBodySize(limit)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeError(w, http.StatusRequestEntityTooLarge, "body too large")
			return
		}
		if len(body) != 0 {
			t.Errorf("body length = %d, want 0", len(body))
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestMaxBodySize_GetRequest(t *testing.T) {
	// GET requests have no body; middleware should not interfere.
	limit := int64(1024)
	handler := maxBodySize(limit)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}
