package api

import (
	"testing"
	"time"
)

func TestReplayGuard_RejectsMissingRequestID(t *testing.T) {
	rg := newReplayGuard()
	defer rg.stop()

	reason := rg.check("", 0)
	if reason == "" {
		t.Fatal("expected rejection for empty request_id")
	}
}

func TestReplayGuard_AcceptsFirstRequest(t *testing.T) {
	rg := newReplayGuard()
	defer rg.stop()

	reason := rg.check("req-1", time.Now().Unix())
	if reason != "" {
		t.Fatalf("expected acceptance, got: %s", reason)
	}
}

func TestReplayGuard_RejectsDuplicate(t *testing.T) {
	rg := newReplayGuard()
	defer rg.stop()

	ts := time.Now().Unix()
	reason := rg.check("req-dup", ts)
	if reason != "" {
		t.Fatalf("first request should succeed, got: %s", reason)
	}

	reason = rg.check("req-dup", ts)
	if reason == "" {
		t.Fatal("expected rejection for duplicate request_id")
	}
	if reason != "duplicate request_id" {
		t.Fatalf("unexpected reason: %s", reason)
	}
}

func TestReplayGuard_RejectsStaleTimestamp(t *testing.T) {
	rg := newReplayGuard()
	defer rg.stop()

	staleTS := time.Now().Add(-2 * time.Minute).Unix()
	reason := rg.check("req-stale", staleTS)
	if reason == "" {
		t.Fatal("expected rejection for stale timestamp")
	}
}

func TestReplayGuard_AcceptsZeroTimestamp(t *testing.T) {
	rg := newReplayGuard()
	defer rg.stop()

	// timestamp=0 skips age check (used by bridge endpoints)
	reason := rg.check("req-no-ts", 0)
	if reason != "" {
		t.Fatalf("expected acceptance with zero timestamp, got: %s", reason)
	}
}

func TestReplayGuard_DifferentIDsAccepted(t *testing.T) {
	rg := newReplayGuard()
	defer rg.stop()

	ts := time.Now().Unix()
	for i := 0; i < 100; i++ {
		reason := rg.check("req-"+string(rune('A'+i)), ts)
		if reason != "" {
			t.Fatalf("request %d should succeed, got: %s", i, reason)
		}
	}
}
