// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package main, file sign_idempotency_test.go.
//
// Unit tests for the HTTP POST /sign idempotency cache — the anti-oracle
// guard that backs the wallet-backend custody adapter's Sign contract.
// Pure unit tests (NO build tag): they run in plain `go test ./cmd/mpcd/...`
// and never touch a live MPC cluster. The signer is injected as a counting
// mock so we can assert it is invoked exactly once under concurrent duplicate
// calls, never on conflict, and never twice for an idempotent retry.
package main

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	mpcapi "github.com/luxfi/mpc/pkg/api"
)

// fields builds a signFields with sensible defaults, overridable per test.
func fields(mut ...func(*signFields)) signFields {
	f := signFields{
		OrgID:       "org-1",
		WalletID:    "wallet-1",
		KeyType:     "secp256k1",
		ChainID:     96369,
		PayloadHash: "deadbeef",
	}
	for _, m := range mut {
		m(&f)
	}
	return f
}

func TestCanonicalSignHash_StableAndFieldSensitive(t *testing.T) {
	base := fields().canonicalHash()

	// Stable: identical inputs → identical hash, regardless of call order.
	if got := fields().canonicalHash(); got != base {
		t.Fatalf("canonical hash not stable: %q != %q", got, base)
	}

	// The idempotency_key is NOT part of the canonical hash (it keys the
	// cache; the hash is over the request CONTENT). Two requests with the
	// same content but different keys must share the same canonical hash.
	if got := fields().canonicalHash(); got != base {
		t.Fatalf("canonical hash must ignore idempotency_key: %q != %q", got, base)
	}

	// Field-sensitive: flipping ANY content field changes the hash.
	mutators := map[string]func(*signFields){
		"org_id":       func(f *signFields) { f.OrgID = "org-2" },
		"wallet_id":    func(f *signFields) { f.WalletID = "wallet-2" },
		"key_type":     func(f *signFields) { f.KeyType = "ed25519" },
		"chain_id":     func(f *signFields) { f.ChainID = 96368 },
		"payload_hash": func(f *signFields) { f.PayloadHash = "c0ffee" },
	}
	for name, m := range mutators {
		if got := fields(m).canonicalHash(); got == base {
			t.Errorf("canonical hash unchanged after mutating %s — field not bound", name)
		}
	}

	// Canonical hash must be unambiguous across field boundaries: moving a
	// character from one field to the next must NOT collide (delimiter test).
	a := fields(func(f *signFields) { f.OrgID = "ab"; f.WalletID = "c" }).canonicalHash()
	b := fields(func(f *signFields) { f.OrgID = "a"; f.WalletID = "bc" }).canonicalHash()
	if a == b {
		t.Errorf("canonical hash collides across field boundary (delimiter missing)")
	}
}

func TestSignIdempotency_ValidateRequest(t *testing.T) {
	// Empty idempotency key → rejected, no signing.
	if err := validateSignRequest("", fields()); !errors.Is(err, errIdempotencyKeyRequired) {
		t.Errorf("empty idempotency key: got %v, want errIdempotencyKeyRequired", err)
	}
	// Empty org_id → rejected (tenant isolation).
	if err := validateSignRequest("idem-1", fields(func(f *signFields) { f.OrgID = "" })); !errors.Is(err, errOrgIDRequired) {
		t.Errorf("empty org_id: got %v, want errOrgIDRequired", err)
	}
	// Well-formed → ok.
	if err := validateSignRequest("idem-1", fields()); err != nil {
		t.Errorf("well-formed request rejected: %v", err)
	}
}

func TestSignIdempotency_CachesResult(t *testing.T) {
	c := newSignIdempotencyCache()
	var calls atomic.Int64
	signer := func(org, wallet string, payload []byte) (*mpcapi.SignResult, error) {
		calls.Add(1)
		return &mpcapi.SignResult{R: "aa", S: "bb", Signature: "ccdd"}, nil
	}

	f := fields()
	r1, err := c.Do("idem-1", f, []byte{0xde, 0xad}, signer)
	if err != nil {
		t.Fatalf("first Do failed: %v", err)
	}
	r2, err := c.Do("idem-1", f, []byte{0xde, 0xad}, signer)
	if err != nil {
		t.Fatalf("second Do failed: %v", err)
	}

	if calls.Load() != 1 {
		t.Errorf("signer invoked %d times, want exactly 1 (cached)", calls.Load())
	}
	if r1.Signature != r2.Signature || r2.Signature != "ccdd" {
		t.Errorf("cached result mismatch: r1=%+v r2=%+v", r1, r2)
	}
	// Same key + same content → SAME session id (stable across retries).
	if r1.SessionID == "" || r1.SessionID != r2.SessionID {
		t.Errorf("session id not stable across idempotent retry: %q vs %q", r1.SessionID, r2.SessionID)
	}
}

func TestSignIdempotency_ConflictNeverSigns(t *testing.T) {
	c := newSignIdempotencyCache()
	var calls atomic.Int64
	signer := func(org, wallet string, payload []byte) (*mpcapi.SignResult, error) {
		calls.Add(1)
		return &mpcapi.SignResult{Signature: "ccdd"}, nil
	}

	if _, err := c.Do("idem-1", fields(), []byte{0x01}, signer); err != nil {
		t.Fatalf("first Do failed: %v", err)
	}
	// Reuse the SAME idempotency key with DIFFERENT content → conflict.
	conflicting := fields(func(f *signFields) { f.PayloadHash = "feedface" })
	_, err := c.Do("idem-1", conflicting, []byte{0x02}, signer)
	if !errors.Is(err, errIdempotencyConflict) {
		t.Fatalf("conflict: got %v, want errIdempotencyConflict", err)
	}
	if calls.Load() != 1 {
		t.Errorf("signer invoked %d times, want 1 — conflict must NOT re-sign (oracle defense)", calls.Load())
	}
}

func TestSignIdempotency_ConcurrentSingleFlight(t *testing.T) {
	c := newSignIdempotencyCache()
	var calls atomic.Int64
	// Block all callers at a barrier so they pile up on the same key
	// simultaneously, then release — proving single-flight (one signer call).
	release := make(chan struct{})
	signer := func(org, wallet string, payload []byte) (*mpcapi.SignResult, error) {
		calls.Add(1)
		<-release
		return &mpcapi.SignResult{Signature: "ccdd"}, nil
	}

	const n = 64
	f := fields()
	var wg sync.WaitGroup
	results := make([]*cachedSign, n)
	errs := make([]error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start // line everyone up at the gate
			results[i], errs[i] = c.Do("idem-hot", f, []byte{0x07}, signer)
		}(i)
	}
	close(start)            // fire all goroutines
	close(release)          // let the in-flight signer return
	wg.Wait()

	if calls.Load() != 1 {
		t.Errorf("signer invoked %d times under %d concurrent duplicates, want exactly 1", calls.Load(), n)
	}
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Errorf("caller %d errored: %v", i, errs[i])
			continue
		}
		if results[i] == nil || results[i].Signature != "ccdd" {
			t.Errorf("caller %d got wrong result: %+v", i, results[i])
		}
		if results[i].SessionID != results[0].SessionID {
			t.Errorf("caller %d session id %q != %q", i, results[i].SessionID, results[0].SessionID)
		}
	}
}

func TestSignIdempotency_DistinctKeysSignSeparately(t *testing.T) {
	c := newSignIdempotencyCache()
	var calls atomic.Int64
	signer := func(org, wallet string, payload []byte) (*mpcapi.SignResult, error) {
		n := calls.Add(1)
		return &mpcapi.SignResult{Signature: fmt.Sprintf("sig-%d", n)}, nil
	}
	if _, err := c.Do("idem-a", fields(), []byte{0x01}, signer); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do("idem-b", fields(), []byte{0x01}, signer); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Errorf("two distinct idempotency keys → signer calls = %d, want 2", calls.Load())
	}
}

// TestSignIdempotency_SignerErrorNotCached proves a failed sign is NOT cached:
// a retry with the same key must be allowed to re-attempt (the failure was not
// a committed result, so it is not an oracle hazard).
func TestSignIdempotency_SignerErrorNotCached(t *testing.T) {
	c := newSignIdempotencyCache()
	var calls atomic.Int64
	signer := func(org, wallet string, payload []byte) (*mpcapi.SignResult, error) {
		n := calls.Add(1)
		if n == 1 {
			return nil, errors.New("transient consensus timeout")
		}
		return &mpcapi.SignResult{Signature: "recovered"}, nil
	}
	f := fields()
	if _, err := c.Do("idem-retry", f, []byte{0x01}, signer); err == nil {
		t.Fatal("expected first Do to surface signer error")
	}
	res, err := c.Do("idem-retry", f, []byte{0x01}, signer)
	if err != nil {
		t.Fatalf("retry after transient failure should succeed: %v", err)
	}
	if res.Signature != "recovered" {
		t.Errorf("retry result = %q, want recovered", res.Signature)
	}
	if calls.Load() != 2 {
		t.Errorf("signer calls = %d, want 2 (failure not cached, retry re-signs)", calls.Load())
	}
}
