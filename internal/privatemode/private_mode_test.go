// Package privatemode holds the deployment-mode contract test for
// fund-private mpcd clusters.
//
// Lives outside e2e/ on purpose: that subdir's compose-driven tests
// require docker + zapdb plumbing this contract test does not need.
// The test exercises pkg/audit + pkg/identity directly, which is enough
// to verify the mode flag actually gates external traffic.
package privatemode

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/luxfi/mpc/pkg/audit"
	"github.com/luxfi/mpc/pkg/identity"
)

func TestPrivateMode_NoRegistrarTraffic(t *testing.T) {
	dir := t.TempDir()
	var registrarHits int32
	registrar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&registrarHits, 1)
		w.WriteHeader(200)
	}))
	defer registrar.Close()

	for _, nodeID := range []string{"fund-0", "fund-1", "fund-2"} {
		id, err := identity.Bootstrap(context.Background(), identity.Config{
			NodeID:       nodeID,
			KeysDir:      filepath.Join(dir, nodeID, "keys"),
			Mode:         identity.ModePrivate,
			RegistrarURL: registrar.URL,
		})
		if err != nil {
			t.Fatalf("bootstrap %s: %v", nodeID, err)
		}
		if id.Mode != identity.ModePrivate {
			t.Fatalf("%s: mode=%q want %q", nodeID, id.Mode, identity.ModePrivate)
		}
		if len(id.PublicKey) != 32 {
			t.Fatalf("%s: pubkey len=%d", nodeID, len(id.PublicKey))
		}
	}

	if got := atomic.LoadInt32(&registrarHits); got != 0 {
		t.Fatalf("registrar received %d POSTs in private mode (want 0). The mode flag is leaking primary-mode traffic.", got)
	}
}

func TestPrivateMode_AuditChainSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	wormPath := filepath.Join(dir, "audit.log")

	d, err := audit.NewDispatcher(context.Background(), audit.Config{
		Store:    audit.StoreLocalWORM,
		WORMPath: wormPath,
	})
	if err != nil {
		t.Fatalf("dispatcher: %v", err)
	}

	for i := 0; i < 5; i++ {
		ev := &audit.Event{
			NodeID:   "fund-0",
			Kind:     audit.KindSign,
			OrgID:    "fund-treasury",
			WalletID: "wallet-cold-1",
		}
		if _, err := d.Append(context.Background(), ev); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	seq1, head1, err := d.VerifyHead(context.Background())
	if err != nil {
		t.Fatalf("verify1: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	d2, err := audit.NewDispatcher(context.Background(), audit.Config{
		Store:    audit.StoreLocalWORM,
		WORMPath: wormPath,
	})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer d2.Close()
	seq2, head2, _ := d2.VerifyHead(context.Background())
	if seq2 != seq1 || head2 != head1 {
		t.Fatalf("restart chain mismatch: got (seq=%d head=%q) want (seq=%d head=%q)", seq2, head2, seq1, head1)
	}

	if _, err := d2.Append(context.Background(), &audit.Event{NodeID: "fund-0", Kind: audit.KindBackup}); err != nil {
		t.Fatalf("append after restart: %v", err)
	}
	seq3, _, _ := d2.VerifyHead(context.Background())
	if seq3 != seq1+1 {
		t.Fatalf("post-restart seq=%d want %d", seq3, seq1+1)
	}
}

func TestPrivateMode_AuditTamperingIsDetected(t *testing.T) {
	dir := t.TempDir()
	wormPath := filepath.Join(dir, "audit.log")

	d, err := audit.NewDispatcher(context.Background(), audit.Config{Store: audit.StoreLocalWORM, WORMPath: wormPath})
	if err != nil {
		t.Fatalf("dispatcher: %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := d.Append(context.Background(), &audit.Event{NodeID: "fund-0", Kind: audit.KindSign}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	d.Close()

	data, err := os.ReadFile(wormPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(data) < 50 {
		t.Fatalf("audit file too small (%d bytes) — should contain 3 events", len(data))
	}
	data[len(data)/2] ^= 0x01
	if err := os.WriteFile(wormPath, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if _, err := audit.NewDispatcher(context.Background(), audit.Config{Store: audit.StoreLocalWORM, WORMPath: wormPath}); err == nil {
		t.Fatal("expected tampered WORM log to fail to open; got success (integrity check is broken)")
	}
}

func TestPrivateMode_CloudStubsFailLoud(t *testing.T) {
	for _, store := range []string{audit.StoreS3GlacierVault, audit.StoreAzureImmutable, audit.StoreGCSObjectLock} {
		_, err := audit.NewDispatcher(context.Background(), audit.Config{Store: store})
		if err == nil {
			t.Errorf("%s: expected an explicit not-implemented error so an operator can't accidentally select an unbuilt cloud backend", store)
		}
	}
}
