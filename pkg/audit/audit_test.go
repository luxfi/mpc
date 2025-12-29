package audit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func mustEvent(t *testing.T, kind EventKind, payload any) *Event {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return &Event{
		NodeID:  "node0",
		Kind:    kind,
		OrgID:   "org-test",
		Payload: raw,
	}
}

func TestEvent_SealComputesHashAndChain(t *testing.T) {
	a := mustEvent(t, KindKeygen, map[string]string{"wallet": "w1"})
	if _, err := a.Seal(0, ""); err != nil {
		t.Fatalf("seal a: %v", err)
	}
	if a.Hash == "" {
		t.Fatal("a.Hash empty")
	}

	b := mustEvent(t, KindSign, map[string]string{"wallet": "w1", "tx": "deadbeef"})
	if _, err := b.Seal(1, a.Hash); err != nil {
		t.Fatalf("seal b: %v", err)
	}
	if b.PrevHash != a.Hash {
		t.Fatalf("b.PrevHash=%q want %q", b.PrevHash, a.Hash)
	}

	if idx, err := VerifyChain([]*Event{a, b}); err != nil || idx != -1 {
		t.Fatalf("verify clean chain: idx=%d err=%v", idx, err)
	}

	// Tamper the payload of b. Hash recomputation must fail.
	b.Payload = json.RawMessage(`{"wallet":"w1","tx":"00"}`)
	if idx, err := VerifyChain([]*Event{a, b}); err == nil || idx != 1 {
		t.Fatalf("verify tampered chain: idx=%d err=%v (want idx=1, err!=nil)", idx, err)
	}
}

func TestEvent_DoubleSealRejected(t *testing.T) {
	ev := mustEvent(t, KindKeygen, nil)
	if _, err := ev.Seal(0, ""); err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := ev.ComputeHash(); err == nil {
		t.Fatal("expected ComputeHash to reject pre-sealed event")
	}
}

func TestWORMDispatcher_AppendAndReplay(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	d, err := NewWORMDispatcher(path)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	for i := 0; i < 5; i++ {
		ev := mustEvent(t, KindSign, map[string]int{"i": i})
		if _, err := d.Append(context.Background(), ev); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	seq, head, _ := d.VerifyHead(context.Background())
	if seq != 4 {
		t.Fatalf("seq=%d want 4", seq)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Reopen — replay must recover the same head.
	d2, err := NewWORMDispatcher(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer d2.Close()
	seq2, head2, _ := d2.VerifyHead(context.Background())
	if seq2 != seq || head2 != head {
		t.Fatalf("replay mismatch: got (seq=%d head=%q) want (seq=%d head=%q)", seq2, head2, seq, head)
	}

	ev := mustEvent(t, KindBackup, nil)
	out, err := d2.Append(context.Background(), ev)
	if err != nil {
		t.Fatalf("post-replay append: %v", err)
	}
	if out.Seq != seq+1 {
		t.Fatalf("post-replay seq=%d want %d", out.Seq, seq+1)
	}
}

func TestMChainDispatcher_BatchAndAnchor(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["batchHash"] == "" {
			t.Errorf("anchor body missing batchHash")
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d, err := NewMChainDispatcher(srv.URL, "test-key", 3)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer d.Close()

	for i := 0; i < 7; i++ {
		ev := mustEvent(t, KindSign, map[string]int{"i": i})
		if _, err := d.Append(context.Background(), ev); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if err := d.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	got := atomic.LoadInt32(&hits)
	// 7 events, batchSize=3 → 2 size-triggered flushes (after #3 and #6)
	// + 1 explicit Flush of the trailing event = 3 anchor calls.
	if got != 3 {
		t.Fatalf("anchor hits=%d want 3", got)
	}
}

func TestNewDispatcher_Composite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d, err := NewDispatcher(context.Background(), Config{
		Store:       "composite",
		Composite:   []string{StoreLocalWORM, StoreMChain},
		WORMPath:    path,
		MChainURL:   srv.URL,
		MChainBatch: 1,
	})
	if err != nil {
		t.Fatalf("new composite: %v", err)
	}
	defer d.Close()

	for i := 0; i < 3; i++ {
		ev := mustEvent(t, KindKeygen, map[string]int{"i": i})
		if _, err := d.Append(context.Background(), ev); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
}

func TestNewDispatcher_CloudStubsAreNotImplemented(t *testing.T) {
	for _, store := range []string{StoreS3GlacierVault, StoreAzureImmutable, StoreGCSObjectLock} {
		_, err := NewDispatcher(context.Background(), Config{Store: store})
		if err == nil {
			t.Errorf("%s: expected NotImplemented error", store)
		}
	}
}
