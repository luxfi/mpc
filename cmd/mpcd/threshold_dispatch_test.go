// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Verifies the embedded threshold dispatcher (luxfi/threshold/pkg/thresholdd)
// is reachable from mpcd's process and answers a full keygen → sign → verify
// round-trip over the ZAP wire with at least one production scheme (FROST —
// fast keygen, no upstream flakiness).
//
// These tests used to drive "bls". thresholdd no longer serves that scheme —
// trusted-dealer threshold-BLS custody was ripped for security (H-2) and
// luxfi/threshold v1.12.x exposes only cggmp21, frost, pulsar, corona,
// magnetar and doerner — so every call answered `unknown procedure
// "bls.keygen"` instead of exercising the dispatcher. FROST is a live
// production scheme on the same wire, so the assertions below are unchanged
// and land on a surface that exists.
//
// This is the smallest possible test that proves the consolidation is
// real: mpcd embeds the same package the standalone thresholdd CLI uses,
// the wire shape matches what teleport/mpc's ZAP client will speak once
// it lands, and the dispatcher refuses unknown procedures explicitly.
package main

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/luxfi/threshold/pkg/thresholdd"
)

// startEmbeddedDispatcher brings up the threshold ZAP dispatcher on an
// ephemeral loopback port and returns its addr + a cleanup func.
func startEmbeddedDispatcher(t *testing.T, authToken string) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("alloc port: %v", err)
	}
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	ln.Close()
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	srv, err := thresholdd.NewZapServer(thresholdd.ZapServerConfig{
		NodeID:    "mpcd-threshold-test",
		Port:      port,
		AuthToken: authToken,
	})
	if err != nil {
		t.Fatalf("NewZapServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	return fmt.Sprintf("127.0.0.1:%d", port), srv.Stop
}

// TestEmbeddedDispatcher_FROSTRoundTrip verifies the dispatcher mpcd
// embeds answers a real FROST keygen → sign → verify round-trip on the
// same ZAP wire teleport's signers will speak.
func TestEmbeddedDispatcher_FROSTRoundTrip(t *testing.T) {
	addr, stop := startEmbeddedDispatcher(t, "")
	defer stop()

	ctx := context.Background()
	c, err := thresholdd.ConnectZap(ctx, addr, thresholdd.WithZapCallTimeout(30*time.Second))
	if err != nil {
		t.Fatalf("ConnectZap: %v", err)
	}
	defer c.Close()

	pubKey, shares, err := c.Keygen(ctx, "frost", 2, 3)
	if err != nil {
		t.Fatalf("frost.keygen: %v", err)
	}
	if len(pubKey) == 0 {
		t.Fatalf("empty publicKey")
	}
	if len(shares) != 3 {
		t.Fatalf("shares=%d want=3", len(shares))
	}

	msg := []byte("mpcd embedded dispatch smoke test")
	sig, err := c.Sign(ctx, "frost", msg, pubKey)
	if err != nil {
		t.Fatalf("frost.sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatalf("empty signature")
	}

	ok, err := c.Verify(ctx, "frost", msg, sig, pubKey)
	if err != nil {
		t.Fatalf("frost.verify: %v", err)
	}
	if !ok {
		t.Fatalf("verify: round-trip signature failed under embedded dispatcher")
	}

	// forgery rejection — different message under same signature must fail
	wrong := []byte("forged")
	bad, err := c.Verify(ctx, "frost", wrong, sig, pubKey)
	if err != nil {
		t.Fatalf("frost.verify(wrong): %v", err)
	}
	if bad {
		t.Fatalf("verify: forgery accepted (different message)")
	}
}

// TestIsThresholdLoopback locks the loopback policy that gates the
// embedded dispatcher bind (Red HIGH B1). Bare `:port` is NOT loopback
// — operators must spell out the host so an accidental
// `--threshold-listen :7301` doesn't expose the dispatcher cluster-wide.
func TestIsThresholdLoopback(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:7301", true},
		{"127.0.0.99:7301", true},
		{"[::1]:7301", true},
		{"localhost:7301", true},
		{"0.0.0.0:7301", false},
		{":7301", false},
		{"10.0.0.1:7301", false},
		{"[2001:db8::1]:7301", false},
		{"not-an-addr", false},
	}
	for _, tc := range cases {
		if got := isThresholdLoopback(tc.addr); got != tc.want {
			t.Errorf("isThresholdLoopback(%q) = %v, want %v", tc.addr, got, tc.want)
		}
	}
}

// TestEmbeddedDispatcher_AuthGate proves that when mpcd installs an
// auth token on the dispatcher, mismatched peer NodeID receives an
// unauthorized error and the matching NodeID passes through.
func TestEmbeddedDispatcher_AuthGate(t *testing.T) {
	addr, stop := startEmbeddedDispatcher(t, "cluster-token")
	defer stop()

	ctx := context.Background()

	// Wrong peer NodeID → unauthorized
	bad, err := thresholdd.ConnectZap(ctx, addr,
		thresholdd.WithZapNodeID("wrong-id"),
		thresholdd.WithZapCallTimeout(10*time.Second))
	if err != nil {
		t.Fatalf("ConnectZap wrong-id: %v", err)
	}
	defer bad.Close()
	_, _, err = bad.Keygen(ctx, "frost", 2, 3)
	if err == nil {
		t.Fatalf("wrong-id: expected unauthorized, got success")
	}
	if !strings.Contains(err.Error(), "unauthorized") {
		t.Fatalf("wrong-id: error %v does not name unauthorized", err)
	}

	// Valid NodeID → success (under -short skip the heavy FROST keygen)
	if !testing.Short() {
		good, err := thresholdd.ConnectZap(ctx, addr,
			thresholdd.WithZapNodeID("cluster-token"),
			thresholdd.WithZapCallTimeout(30*time.Second))
		if err != nil {
			t.Fatalf("ConnectZap cluster-token: %v", err)
		}
		defer good.Close()
		pubKey, _, err := good.Keygen(ctx, "frost", 2, 3)
		if err != nil {
			t.Fatalf("cluster-token Keygen: %v", err)
		}
		if len(pubKey) == 0 {
			t.Fatalf("empty pubKey")
		}
	}
}

// TestEmbeddedDispatcher_UnknownScheme verifies the dispatcher returns
// an explicit "unknown procedure" error for an unrecognized scheme —
// the teleport bus relies on this contract to route fall-back signers.
func TestEmbeddedDispatcher_UnknownScheme(t *testing.T) {
	addr, stop := startEmbeddedDispatcher(t, "")
	defer stop()

	ctx := context.Background()
	c, err := thresholdd.ConnectZap(ctx, addr, thresholdd.WithZapCallTimeout(10*time.Second))
	if err != nil {
		t.Fatalf("ConnectZap: %v", err)
	}
	defer c.Close()

	_, _, err = c.Keygen(ctx, "bogus", 1, 1)
	if err == nil {
		t.Fatalf("expected unknown-procedure error, got success")
	}
	if !strings.Contains(err.Error(), "unknown procedure") {
		t.Fatalf("error %v does not name unknown procedure", err)
	}
}
