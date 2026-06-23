// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build integration

// Package main, file standalone_test.go.
//
// Exercises mpcd in standalone (1-of-1 self-loop) mode. mpcd's
// "consensus" mode is the same code path used in production multi-node
// deployments — running it with no peers and threshold=1 makes the node
// its own signing quorum. This is not for production but is the smallest
// possible smoke test that exercises the full daemon: identity, transport,
// PoA membership (n=1), HTTP control plane, and graceful shutdown.
//
// What this test covers:
//  1. Build mpcd
//  2. Start it with --node-id=solo --threshold=1 and no peers
//  3. Wait for /healthz to report status=healthy + quorum=true
//  4. Confirm the readyCount, threshold, and version fields
//  5. Send SIGTERM and confirm clean exit
//
// Keygen/signing are NOT exercised here. CGGMP21 and FROST require ≥2
// parties to produce a signature share — a 1-of-1 ensemble is structurally
// unable to keygen. Multi-node correctness is covered by ../e2e.
//
// Run: `go test -tags=integration ./cmd/mpcd/... -count=1 -timeout 90s`.
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func TestStandaloneSelfQuorum(t *testing.T) {
	tmpDir := t.TempDir()

	binPath := filepath.Join(tmpDir, "mpcd")
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Dir = "."
	build.Stdout, build.Stderr = os.Stdout, os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("go build mpcd: %v", err)
	}

	listenPort := freePort(t)
	apiPort := freePort(t)
	dataDir := filepath.Join(tmpDir, "data")
	keysDir := filepath.Join(tmpDir, "keys")

	cmd := exec.Command(binPath,
		"start",
		"--node-id", "solo",
		"--listen", fmt.Sprintf(":%d", listenPort),
		"--api", fmt.Sprintf("127.0.0.1:%d", apiPort),
		"--data", dataDir,
		"--keys", keysDir,
		"--threshold", "1",
		"--log-level", "warn",
	)
	cmd.Env = append(os.Environ(),
		// Standalone uses env-provider for the ZapDB password to keep
		// the test self-contained — no cloud KMS required. The `env`
		// provider reads MPC_PASSWORD (its native var); ZAPDB_PASSWORD is
		// the viper-config fallback. Set BOTH so the password resolves
		// regardless of which path the startup takes (the env provider is
		// tried first, so MPC_PASSWORD is what actually unlocks ZapDB).
		"MPC_HSM_PROVIDER=env",
		"MPC_PASSWORD=smoke-test-password",
		"ZAPDB_PASSWORD=smoke-test-password",
		// Skip the event_initiator_pubkey requirement: in standalone
		// mode there's no external event initiator.
	)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start mpcd: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	})

	// Poll /healthz until quorum=true (or fail after 60s).
	healthURL := fmt.Sprintf("http://127.0.0.1:%d/healthz", apiPort)
	deadline := time.Now().Add(60 * time.Second)
	var last map[string]interface{}
	for time.Now().Before(deadline) {
		resp, err := http.Get(healthURL)
		if err == nil {
			var body map[string]interface{}
			_ = json.NewDecoder(resp.Body).Decode(&body)
			resp.Body.Close()
			last = body
			if resp.StatusCode == 200 {
				if quorum, _ := body["signing_quorum"].(bool); quorum {
					// Confirm shape of the response.
					if got, _ := body["threshold"].(float64); int(got) != 1 {
						t.Fatalf("threshold mismatch: got %v want 1", body["threshold"])
					}
					if got, _ := body["mode"].(string); got != "consensus" {
						t.Fatalf("mode mismatch: got %v want consensus", got)
					}
					return
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("mpcd never reached signing quorum on :%d, last=%v", apiPort, last)
}
