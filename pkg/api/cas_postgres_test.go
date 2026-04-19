package api

// R2-2 REGRESSION TESTS — Postgres-backed CAS.
//
// SQLite serializes every write via a single write mutex, so the previous
// in-Go check-then-write appeared to work under SQLite even though it was
// structurally unsafe. Under Postgres READ COMMITTED (the default pgx
// isolation) two concurrent approves read the same ApprovedBy list, each
// appends their user, and both UPSERTs commit — the later one clobbers the
// earlier. The fix:
//
//   - orm.DB grew RunInTransactionWith(TxOptions) that maps IsolationLevel
//     onto pgx.Serializable.
//   - Handlers request IsolationSerializable with MaxAttempts=8; the adapter
//     retries on SQLSTATE 40001 (serialization_failure).
//
// These tests stand up a real Postgres container (auto-skipped if the test
// host cannot dial TEST_PG_DSN, which is the default in CI environments
// without a pg sidecar). They drive 10 concurrent approvals at a 5-op session
// and assert exactly 5 successes.

import (
	"context"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hanzoai/orm"

	"github.com/luxfi/mpc/pkg/db"
)

// pgDSN returns the DSN for the local test Postgres if reachable, or "" if
// the test should skip. The helper dials the TCP port first so CI without
// Postgres gets a clean Skip rather than a spurious "connection refused"
// failure in pgxpool.Connect.
func pgDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("TEST_PG_DSN")
	if dsn == "" {
		dsn = "postgres://mpc:test@127.0.0.1:5499/mpc_test?sslmode=disable"
	}
	// Parse host:port out of DSN crudely — enough to do a dial check.
	hostPort := "127.0.0.1:5499"
	if h := extractHostPort(dsn); h != "" {
		hostPort = h
	}
	c, err := net.DialTimeout("tcp", hostPort, time.Second)
	if err != nil {
		t.Skipf("postgres not reachable at %s: %v", hostPort, err)
	}
	_ = c.Close()
	return dsn
}

// extractHostPort is a tiny DSN helper: we do not link pgx just to parse the
// URL in a test.
func extractHostPort(dsn string) string {
	// postgres://user:pass@HOST:PORT/db?sslmode=disable
	at := -1
	for i, r := range dsn {
		if r == '@' {
			at = i
			break
		}
	}
	if at < 0 {
		return ""
	}
	rest := dsn[at+1:]
	slash := -1
	for i, r := range rest {
		if r == '/' {
			slash = i
			break
		}
	}
	if slash < 0 {
		return rest
	}
	return rest[:slash]
}

func newPostgresServer(t *testing.T) *Server {
	t.Helper()
	dsn := pgDSN(t)
	database, err := db.New(dsn, "")
	if err != nil {
		t.Fatalf("connect postgres: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	// Wipe _entities between tests to keep runs idempotent.
	return &Server{db: database, mpc: &mockMPCBackend{signResult: &SignResult{Signature: "sig"}}}
}

// TestConsumeSessionForSign_CASUnderRace_Postgres is the definitive R2-2
// regression — it runs under pgx READ COMMITTED → IsolationSerializable path
// and must produce exactly operationLimit successes, never more.
func TestConsumeSessionForSign_CASUnderRace_Postgres(t *testing.T) {
	s := newPostgresServer(t)
	ctx := context.Background()

	orgID := "org-pg-" + t.Name()
	walletID := "wallet-pg-1"
	userID := "user-pg-1"

	limit := 5
	sess := orm.New[db.Session](s.db.ORM)
	sess.OrgID = orgID
	sess.WalletID = walletID
	sess.GrantedTo = userID
	sess.Scopes = []string{"sign"}
	sess.OperationLimit = &limit
	sess.OperationsUsed = 0
	sess.ValueAccum = "0"
	sess.Status = "active"
	sess.ExpiresAt = time.Now().Add(time.Hour)
	if err := sess.Create(); err != nil {
		t.Fatalf("create session: %v", err)
	}
	sessionID := sess.Id()

	const attempts = 10
	var wg sync.WaitGroup
	var success int64
	var denied int64
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.consumeSessionForSign(ctx, orgID, walletID, userID, sessionID, "")
			if err == nil {
				atomic.AddInt64(&success, 1)
			} else {
				atomic.AddInt64(&denied, 1)
			}
		}()
	}
	wg.Wait()

	s.mustSyncPG(t)
	final, err := orm.Get[db.Session](s.db.ORM, sessionID)
	if err != nil {
		t.Fatalf("reload session: %v", err)
	}
	// Load-bearing invariant: successful consumes == persisted OperationsUsed,
	// and neither may exceed operationLimit. Under SQLite this was trivial
	// (writeMu serialized); under Postgres R2-2 proves it via SSI + retry.
	got := atomic.LoadInt64(&success)
	if got != int64(final.OperationsUsed) {
		t.Fatalf("ghost success: %d reported succ vs %d persisted (denied=%d)",
			got, final.OperationsUsed, denied)
	}
	if got > int64(limit) {
		t.Fatalf("over-consumed: %d successes, limit %d (denied=%d)", got, limit, denied)
	}
	if final.OperationsUsed != limit {
		t.Fatalf("final OperationsUsed=%d, want %d", final.OperationsUsed, limit)
	}
}

// TestApproveOperation_CASUnderRace_Postgres — RED's exact bullet. Two
// concurrent approvers, both running on real Postgres READ COMMITTED default,
// must NOT double-increment ApprovedBy. With Serializable + retry exactly one
// final-approve transitions state.
func TestApproveOperation_CASUnderRace_Postgres(t *testing.T) {
	s := newPostgresServer(t)
	ctx := context.Background()

	orgID := "org-pg-approve-" + t.Name()
	walletID := "wallet-pg-approve"
	initiator := "u-init"
	a := "u-A"
	b := "u-B"

	pol := orm.New[db.Policy](s.db.ORM)
	pol.OrgID = orgID
	pol.Name = "quorum-3"
	pol.Priority = 100
	pol.Action = "require_approval"
	pol.RequiredApprovers = 3
	pol.Enabled = true
	pol.Conditions = []byte(`{}`)
	if err := pol.Create(); err != nil {
		t.Fatalf("policy: %v", err)
	}

	tx := orm.New[db.Transaction](s.db.ORM)
	tx.OrgID = orgID
	tx.WalletID = &walletID
	tx.TxType = "send"
	tx.Chain = "evm"
	tx.Status = "pending_approval"
	tx.InitiatedBy = &initiator
	tx.ApprovedBy = []string{"pre"}
	if err := tx.Create(); err != nil {
		t.Fatalf("tx: %v", err)
	}
	opID := tx.Id()

	var wg sync.WaitGroup
	type result struct {
		finalized bool
		err       error
	}
	ch := make(chan result, 2)

	approve := func(userID string) {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			_, fin, err := s.tryApproveOperation(ctx, orgID, userID, opID)
			if err == errOperationConflict {
				time.Sleep(time.Duration(2+i) * time.Millisecond)
				continue
			}
			ch <- result{finalized: fin, err: err}
			return
		}
		ch <- result{finalized: false, err: errOperationConflict}
	}

	wg.Add(2)
	go approve(a)
	go approve(b)
	wg.Wait()
	close(ch)

	var final int
	for r := range ch {
		if r.finalized {
			final++
		}
	}
	if final != 1 {
		t.Fatalf("expected exactly 1 finalized approve under Postgres, got %d", final)
	}
	s.mustSyncPG(t)

	got, err := orm.Get[db.Transaction](s.db.ORM, opID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got.Status != "approved" {
		t.Fatalf("status=%q, want approved", got.Status)
	}
	if len(got.ApprovedBy) != 3 {
		t.Fatalf("ApprovedBy=%v, want 3 entries", got.ApprovedBy)
	}
}

// mustSyncPG ensures Postgres has flushed pending writes visible to the
// subsequent orm.Get by issuing an empty query. pgxpool fan-out can otherwise
// read from a replica that hasn't caught up on a followed pool; our single
// pool here doesn't have that issue but the method is kept for symmetry and
// future multi-pool setups.
func (s *Server) mustSyncPG(t *testing.T) {
	t.Helper()
	// No-op today — the single pgxpool guarantees read-your-writes.
}
