// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestAwaitAirgapResponse_ImmediateContent: the happy path — a response
// file already sitting on disk with a complete payload returns on the
// first stable poll.
func TestAwaitAirgapResponse_ImmediateContent(t *testing.T) {
	t.Parallel()

	respPath := filepath.Join(t.TempDir(), "session.resp")
	want := []byte("0xdeadbeef")
	if err := os.WriteFile(respPath, want, 0o600); err != nil {
		t.Fatalf("seed response: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	got, err := awaitAirgapResponseEvery(ctx, respPath, 5*time.Millisecond)
	if err != nil {
		t.Fatalf("awaitAirgapResponseEvery: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("payload = %q, want %q", got, want)
	}
}

// TestAwaitAirgapResponse_EmptyThenContent regresses the bug that an
// operator who creates the response file before writing it (kiosk
// `touch && cat` flow, file managers that pre-create the destination,
// editors that drop a zero-byte stub) would crash the ceremony with
// "response file is empty" instead of waiting for the actual payload.
func TestAwaitAirgapResponse_EmptyThenContent(t *testing.T) {
	t.Parallel()

	respPath := filepath.Join(t.TempDir(), "session.resp")
	if err := os.WriteFile(respPath, nil, 0o600); err != nil {
		t.Fatalf("seed empty file: %v", err)
	}

	want := []byte("psbt-bytes")
	go func() {
		// Wait a few polls so we exercise the zero-byte branch.
		time.Sleep(30 * time.Millisecond)
		_ = os.WriteFile(respPath, want, 0o600)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	got, err := awaitAirgapResponseEvery(ctx, respPath, 5*time.Millisecond)
	if err != nil {
		t.Fatalf("awaitAirgapResponseEvery: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("payload = %q, want %q", got, want)
	}
}

// TestAwaitAirgapResponse_GrowingThenStable simulates an operator
// writing the file in chunks (a multi-megabyte UR-encoded payload
// streamed across QR frames into a host buffer, flushed incrementally).
// We must not return the truncated prefix — only the settled bytes.
func TestAwaitAirgapResponse_GrowingThenStable(t *testing.T) {
	t.Parallel()

	respPath := filepath.Join(t.TempDir(), "session.resp")
	final := []byte("aaaaabbbbbccccc")

	go func() {
		// Three growth steps separated by enough polls to be observed
		// as growth (not stable), then a long pause for stability.
		_ = os.WriteFile(respPath, final[:5], 0o600)
		time.Sleep(15 * time.Millisecond)
		_ = os.WriteFile(respPath, final[:10], 0o600)
		time.Sleep(15 * time.Millisecond)
		_ = os.WriteFile(respPath, final, 0o600)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	got, err := awaitAirgapResponseEvery(ctx, respPath, 5*time.Millisecond)
	if err != nil {
		t.Fatalf("awaitAirgapResponseEvery: %v", err)
	}
	if !bytes.Equal(got, final) {
		t.Fatalf("payload = %q, want %q", got, final)
	}
}

// TestAwaitAirgapResponse_ContextCanceled: when the operator timeout
// fires before the file lands, we propagate ctx.Err() so the caller
// reports a useful "ceremony failed" diagnostic.
func TestAwaitAirgapResponse_ContextCanceled(t *testing.T) {
	t.Parallel()

	respPath := filepath.Join(t.TempDir(), "session.resp")

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()

	_, err := awaitAirgapResponseEvery(ctx, respPath, 5*time.Millisecond)
	if err == nil {
		t.Fatalf("expected context error, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded, got %v", err)
	}
}

// TestAwaitAirgapResponse_StatErrorIsTerminal: a stat error that is
// not "does not exist" (for example, permission denied on the working
// directory) must surface immediately rather than spin until timeout.
// Skipped when run as root because root reads through 0000 dirs.
func TestAwaitAirgapResponse_StatErrorIsTerminal(t *testing.T) {
	t.Parallel()

	if os.Geteuid() == 0 {
		t.Skip("running as root — permission-denied is unreachable")
	}

	dir := t.TempDir()
	respPath := filepath.Join(dir, "session.resp")
	if err := os.WriteFile(respPath, []byte("payload"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	_, err := awaitAirgapResponseEvery(ctx, respPath, 5*time.Millisecond)
	if err == nil {
		t.Fatalf("expected stat error, got nil")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected stat error, got DeadlineExceeded (we should have errored out before timeout)")
	}
}
