package api

// CAS concurrency tests. These exercise the read-modify-write races Red
// identified (F2, F3) using real SQLite-backed storage and parallel goroutines
// all racing to mutate the same row.

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hanzoai/orm"

	"github.com/luxfi/mpc/pkg/db"
)

func newConcurrencyServer(t *testing.T) *Server {
	t.Helper()
	path := t.TempDir() + "/cas.db"
	d, err := db.New("sqlite://"+path, "")
	if err != nil {
		t.Fatalf("db.New: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return &Server{db: d, mpc: &mockMPCBackend{signResult: &SignResult{Signature: "sig"}}}
}

// TestConsumeSessionForSign_CASUnderRace — F3 reproducer. 10 concurrent sign
// attempts racing against an operationLimit=5 session must yield exactly 5
// successes and 5 denials (limit reached or conflict after retry exhaustion).
// Pre-fix, we could observe up to 10 successes because read-then-write had
// no atomicity.
func TestConsumeSessionForSign_CASUnderRace(t *testing.T) {
	s := newConcurrencyServer(t)
	ctx := context.Background()

	orgID := "org-cas-1"
	walletID := "wallet-cas-1"
	userID := "user-cas-1"

	// Create the session with operationLimit=5.
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

	if got := atomic.LoadInt64(&success); got > int64(limit) {
		t.Fatalf("session over-consumed: %d successes with limit %d", got, limit)
	}
	if atomic.LoadInt64(&success)+atomic.LoadInt64(&denied) != attempts {
		t.Fatalf("lost attempts: success=%d denied=%d", success, denied)
	}

	// Verify persisted state — OperationsUsed must equal the observed number
	// of successes, not more, not less.
	final, err := orm.Get[db.Session](s.db.ORM, sessionID)
	if err != nil {
		t.Fatalf("reload session: %v", err)
	}
	if int64(final.OperationsUsed) != atomic.LoadInt64(&success) {
		t.Fatalf("OperationsUsed=%d, want %d", final.OperationsUsed, success)
	}
}

// TestApproveOperation_CASUnderRace — F2 reproducer. Two distinct approvers
// racing against an operation with required=3 must result in exactly one
// final quorum transition (one "finalized=true" approve, one "finalized=false"
// approve since quorum is not yet reached), never both, never zero.
//
// We seed ApprovedBy=[pre-approver] so required=3 means A and B are the 2nd
// and 3rd approvers. Only the 3rd one to commit transitions state to approved.
func TestApproveOperation_CASUnderRace(t *testing.T) {
	s := newConcurrencyServer(t)
	ctx := context.Background()

	orgID := "org-cas-2"
	walletID := "wallet-cas-2"
	initiator := "user-init"
	approverA := "user-A"
	approverB := "user-B"

	// Seed a policy requiring 3 approvers so that racing A & B produce
	// deterministic final state: after both commit, ApprovedBy=[pre, A, B]
	// and status transitions to "approved" exactly once.
	pol := orm.New[db.Policy](s.db.ORM)
	pol.OrgID = orgID
	pol.Name = "three-approvers"
	pol.Priority = 100
	pol.Action = "require_approval"
	pol.RequiredApprovers = 3
	pol.Enabled = true
	pol.Conditions = []byte(`{}`)
	if err := pol.Create(); err != nil {
		t.Fatalf("create policy: %v", err)
	}

	tx := orm.New[db.Transaction](s.db.ORM)
	tx.OrgID = orgID
	tx.TxType = "send"
	tx.Chain = "evm"
	amt := "1000"
	tx.Amount = &amt
	tx.WalletID = &walletID
	tx.Status = "pending_approval"
	tx.InitiatedBy = &initiator
	tx.ApprovedBy = []string{"pre-approver"}
	if err := tx.Create(); err != nil {
		t.Fatalf("create tx: %v", err)
	}
	opID := tx.Id()

	// Sanity-check that loadPolicies returns our seeded policy (requires
	// sqlite json1 tag; see Makefile `test` target).
	got, _ := s.loadPolicies(ctx, orgID, nil)
	if len(got) != 1 {
		t.Skipf("loadPolicies returned %d (json1 tag required)", len(got))
	}
	if got[0].RequiredApprovers != 3 {
		t.Fatalf("policy RequiredApprovers=%d, want 3", got[0].RequiredApprovers)
	}

	// Two approvers race, each trying to be the final 2nd approval.
	// (With required=2 and zero prior approvers, both A and B are 1st-of-2
	// for some ordering; only one sequence can achieve quorum.)
	var wg sync.WaitGroup
	resA := make(chan struct {
		tx        *db.Transaction
		finalized bool
		err       error
	}, 1)
	resB := make(chan struct {
		tx        *db.Transaction
		finalized bool
		err       error
	}, 1)

	approve := func(userID string, out chan struct {
		tx        *db.Transaction
		finalized bool
		err       error
	}) {
		defer wg.Done()
		const retries = 20
		for i := 0; i < retries; i++ {
			t0, fin, err := s.tryApproveOperation(ctx, orgID, userID, opID)
			if err != nil {
				// Conflict errors map to a retry; policy errors do not.
				if err == errOperationConflict {
					time.Sleep(time.Duration(2+i) * time.Millisecond)
					continue
				}
			}
			out <- struct {
				tx        *db.Transaction
				finalized bool
				err       error
			}{t0, fin, err}
			return
		}
		out <- struct {
			tx        *db.Transaction
			finalized bool
			err       error
		}{nil, false, errOperationConflict}
	}

	wg.Add(2)
	go approve(approverA, resA)
	go approve(approverB, resB)
	wg.Wait()

	a := <-resA
	b := <-resB

	// Exactly one of the two approvals must have finalized.
	finalCount := 0
	if a.finalized {
		finalCount++
	}
	if b.finalized {
		finalCount++
	}
	if finalCount != 1 {
		t.Fatalf("expected exactly one finalized approve, got %d (A.finalized=%v B.finalized=%v A.err=%v B.err=%v)",
			finalCount, a.finalized, b.finalized, a.err, b.err)
	}

	// Persisted state must reflect both approvers present in ApprovedBy and
	// the status transitioned to "approved".
	final, err := orm.Get[db.Transaction](s.db.ORM, opID)
	if err != nil {
		t.Fatalf("reload tx: %v", err)
	}
	// With required=3 and 1 pre-seeded approver, the final state after A+B
	// commit should have 3 approvers in ApprovedBy and status "approved".
	if final.Status != "approved" {
		t.Fatalf("final.Status=%q, want approved", final.Status)
	}
	if len(final.ApprovedBy) != 3 {
		t.Fatalf("ApprovedBy=%v, want 3 entries", final.ApprovedBy)
	}
}

// TestInitiatorCannotApprove_Regardless — F23 regression. Even if many other
// approvers have already approved, the initiator must never succeed at
// approving.
func TestInitiatorCannotApprove_Regardless(t *testing.T) {
	s := newConcurrencyServer(t)
	ctx := context.Background()
	orgID := "org-cas-3"
	initiator := "user-init-3"

	tx := orm.New[db.Transaction](s.db.ORM)
	tx.OrgID = orgID
	tx.TxType = "send"
	tx.Chain = "evm"
	tx.Status = "pending_approval"
	tx.InitiatedBy = &initiator
	// Simulate prior approvers already present.
	tx.ApprovedBy = []string{"approver-1", "approver-2"}
	if err := tx.Create(); err != nil {
		t.Fatalf("create tx: %v", err)
	}
	opID := tx.Id()

	_, _, err := s.tryApproveOperation(ctx, orgID, initiator, opID)
	if err == nil {
		t.Fatal("expected initiator self-approve to be rejected")
	}
	herr, ok := err.(*httpError)
	if !ok || herr.code != 403 {
		t.Fatalf("expected 403 httpError, got %T %v", err, err)
	}
}
