package identity

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestBootstrap_PrivateMode_NoRegistrarCalled(t *testing.T) {
	dir := t.TempDir()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	id, err := Bootstrap(context.Background(), Config{
		NodeID:       "node0",
		KeysDir:      dir,
		Mode:         ModePrivate,
		RegistrarURL: srv.URL, // present but must NOT be hit
	})
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("registrar hits=%d want 0 in private mode", got)
	}
	if id.Mode != ModePrivate {
		t.Fatalf("mode=%q want %q", id.Mode, ModePrivate)
	}
	if len(id.PublicKey) != 32 {
		t.Fatalf("pubkey len=%d want 32", len(id.PublicKey))
	}
}

func TestBootstrap_PrimaryMode_RegistrarHitOnce(t *testing.T) {
	dir := t.TempDir()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	cfg := Config{
		NodeID:       "node0",
		KeysDir:      dir,
		Mode:         ModePrimary,
		RegistrarURL: srv.URL,
	}
	if _, err := Bootstrap(context.Background(), cfg); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	// Reinvoke — second call announces too (registrar is responsible for
	// idempotency). What the second call MUST NOT do is regenerate keys.
	id2, err := Bootstrap(context.Background(), cfg)
	if err != nil {
		t.Fatalf("bootstrap 2: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("registrar hits=%d want 2", got)
	}
	if id2.Mode != ModePrimary {
		t.Fatalf("mode=%q want %q", id2.Mode, ModePrimary)
	}

	id3, err := loadIdentity(filepath.Join(dir, "node0_identity.json"))
	if err != nil || id3 == nil {
		t.Fatalf("load: %v", err)
	}
	for i := range id2.PublicKey {
		if id2.PublicKey[i] != id3.PublicKey[i] {
			t.Fatalf("pubkey changed across reload")
		}
	}
}

func TestBootstrap_PrimaryMode_NoRegistrarURLIsNoop(t *testing.T) {
	dir := t.TempDir()
	id, err := Bootstrap(context.Background(), Config{
		NodeID:  "node0",
		KeysDir: dir,
		Mode:    ModePrimary,
	})
	if err != nil {
		t.Fatalf("bootstrap with empty URL must succeed (air-gapped staging): %v", err)
	}
	if id.Mode != ModePrimary {
		t.Fatalf("mode=%q want %q", id.Mode, ModePrimary)
	}
}

func TestBootstrap_PrimaryMode_RegistrarFailureSurfaces(t *testing.T) {
	dir := t.TempDir()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(503)
	}))
	defer srv.Close()

	_, err := Bootstrap(context.Background(), Config{
		NodeID:       "node0",
		KeysDir:      dir,
		Mode:         ModePrimary,
		RegistrarURL: srv.URL,
	})
	if err == nil {
		t.Fatal("expected error from 503 registrar")
	}
}
