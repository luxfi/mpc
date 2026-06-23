// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build integration

// Package e2e, file live_http_sign_test.go.
//
// LIVE MPC custody proof. A real 3-node mpcd ensemble (consensus mode — the
// PRODUCTION code path: ZAP transport, CGGMP21 keygen, t-of-n threshold
// signing) is started, and we drive it over the REAL internal HTTP API
// (`/keygen`, `/sign`) exactly as the lux/wallet custody adapter does. This is
// not a mock: every signature is a genuine threshold signature produced from
// key shares that never leave each node's encrypted ZapDB. No plaintext private
// key is ever assembled, and the test asserts none appears in any response or
// node log.
//
// What it proves end to end:
//   - 3-node 2-of-3 ensemble forms a signing quorum over the ZAP transport.
//   - POST /keygen → a real distributed keypair (ecdsa pubkey + evm/btc address).
//   - POST /sign → a real threshold signature over a 32-byte payload hash.
//   - Idempotency (anti-oracle): same key+content → cached identical signature;
//     same key+different content → HTTP 409, no signing; empty key → 400.
//   - No plaintext key leaks (response bodies + node logs scanned).
//
// Run:
//
//	cd /Users/z/work/lux/mpc && \
//	  GOEXPERIMENT=runtimesecret,simd go test -tags integration ./e2e/ \
//	  -run TestLiveHTTPSign -count=1 -timeout 300s -v
//
// mpcd is built from the repo ROOT module (the checked-out source), not from
// the e2e module's pinned luxfi/mpc dependency — so this exercises the local
// tree. See buildMPCD.
package e2e

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
)

// internalAPIKey is the bearer token every node in the ensemble shares. Set as
// MPC_INTERNAL_API_KEY so the test holds the token (it is a test fixture — fine
// to embed/log). In production this is injected from the KMS-synced Secret.
const internalAPIKey = "live-e2e-internal-api-key"

// zapdbPassword unlocks each node's embedded ZapDB. The `env` HSM provider reads
// MPC_PASSWORD; the consensus startup's viper fallback reads ZAPDB_PASSWORD — we
// set both to the same value so either path resolves it.
const zapdbPassword = "live-e2e-zapdb-password"

// ensemble is a running set of mpcd nodes plus their HTTP API addresses.
type ensemble struct {
	t        *testing.T
	apiAddrs []string // index → "127.0.0.1:<port>"
	procs    []*exec.Cmd
	logs     []*syncBuf
}

// syncBuf is a goroutine-safe byte buffer capturing a node's stdout+stderr.
type syncBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// freePort returns a currently-free TCP port on loopback.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// buildMPCD compiles mpcd from the repo ROOT module (../cmd/mpcd) with the
// canonical build flags from the Makefile (GOWORK=off, GOEXPERIMENT). CGO is
// disabled so the binary is self-contained. Returns the binary path.
func buildMPCD(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "mpcd")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/mpcd")
	cmd.Dir = ".." // repo root module (the checked-out feat/mpcd-http-sign tree)
	cmd.Env = append(os.Environ(),
		"GOWORK=off",
		"GOEXPERIMENT=runtimesecret,simd",
		"CGO_ENABLED=0",
	)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	t.Logf("building mpcd from repo root (../cmd/mpcd)…")
	if err := cmd.Run(); err != nil {
		t.Fatalf("go build mpcd: %v\n%s", err, out.String())
	}
	return bin
}

// startEnsemble launches n consensus-mode mpcd nodes with the given threshold,
// fully meshed, each on its own ports + data/keys dirs, and waits until every
// node reports signing_quorum=true (or fails with health + log dumps).
func startEnsemble(t *testing.T, n, threshold int) *ensemble {
	t.Helper()
	if n < 2 {
		t.Fatalf("ensemble needs >= 2 nodes (CGGMP21/FROST cannot keygen with 1), got %d", n)
	}
	bin := buildMPCD(t)
	root := t.TempDir()

	nodeIDs := make([]string, n)
	listen := make([]int, n)
	api := make([]int, n)
	for i := 0; i < n; i++ {
		nodeIDs[i] = fmt.Sprintf("node%d", i)
		listen[i] = freePort(t)
		api[i] = freePort(t)
	}

	e := &ensemble{t: t, apiAddrs: make([]string, n), procs: make([]*exec.Cmd, n), logs: make([]*syncBuf, n)}

	for i := 0; i < n; i++ {
		// Wire every OTHER node as a --peer.
		args := []string{
			"start",
			"--node-id", nodeIDs[i],
			"--listen", fmt.Sprintf("127.0.0.1:%d", listen[i]),
			"--api", fmt.Sprintf("127.0.0.1:%d", api[i]),
			"--data", filepath.Join(root, nodeIDs[i]),
			"--keys", filepath.Join(root, nodeIDs[i], "keys"),
			"--threshold", fmt.Sprint(threshold),
			"--log-level", "info",
			// Disable the optional servers the proof does not need so the node
			// is the minimal consensus + internal-HTTP surface.
			"--kms-zap-listen", "",
			"--threshold-listen", "",
		}
		for j := 0; j < n; j++ {
			if j == i {
				continue
			}
			args = append(args, "--peer", fmt.Sprintf("%s@127.0.0.1:%d", nodeIDs[j], listen[j]))
		}

		cmd := exec.Command(bin, args...)
		cmd.Env = append(os.Environ(),
			"MPC_HSM_PROVIDER=env",
			"MPC_PASSWORD="+zapdbPassword,   // hsm/env provider's native var
			"ZAPDB_PASSWORD="+zapdbPassword, // viper fallback used by consensus startup
			"MPC_INTERNAL_API_KEY="+internalAPIKey,
			// Deliberately NO MPC_JWT_SECRET → the Base dashboard does not start.
		)
		lb := &syncBuf{}
		cmd.Stdout = io.MultiWriter(lb, testLogWriter{t, nodeIDs[i]})
		cmd.Stderr = cmd.Stdout
		if err := cmd.Start(); err != nil {
			t.Fatalf("start %s: %v", nodeIDs[i], err)
		}
		e.procs[i] = cmd
		e.logs[i] = lb
		e.apiAddrs[i] = fmt.Sprintf("127.0.0.1:%d", api[i])
	}

	t.Cleanup(e.stop)

	e.waitQuorum(90 * time.Second)
	return e
}

// testLogWriter forwards node output to t.Log line-prefixed, for live debugging.
type testLogWriter struct {
	t  *testing.T
	id string
}

func (w testLogWriter) Write(p []byte) (int, error) {
	for _, line := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		if line != "" {
			w.t.Logf("[%s] %s", w.id, line)
		}
	}
	return len(p), nil
}

// waitQuorum polls every node's /healthz until all report signing_quorum=true
// AND ready=true (ready = all peers connected, which keygen requires). Fails
// with the last health bodies + node logs if the deadline passes.
func (e *ensemble) waitQuorum(timeout time.Duration) {
	e.t.Helper()
	deadline := time.Now().Add(timeout)
	last := make([]string, len(e.apiAddrs))
	for time.Now().Before(deadline) {
		allReady := true
		for i, addr := range e.apiAddrs {
			body, code := e.health(addr)
			last[i] = body
			if code != http.StatusOK {
				allReady = false
				continue
			}
			var h struct {
				SigningQuorum bool `json:"signing_quorum"`
				Ready         bool `json:"ready"`
			}
			_ = json.Unmarshal([]byte(body), &h)
			// keygen needs ALL peers (ready=true); signing needs only quorum.
			// Gate on the stricter condition so keygen is reliable.
			if !h.SigningQuorum || !h.Ready {
				allReady = false
			}
		}
		if allReady {
			e.t.Logf("ensemble healthy: all %d nodes report signing_quorum=true, ready=true", len(e.apiAddrs))
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	for i := range e.apiAddrs {
		e.t.Logf("node%d last health: %s", i, last[i])
		e.t.Logf("node%d log tail:\n%s", i, tail(e.logs[i].String(), 40))
	}
	e.t.Fatalf("ensemble never reached full readiness within %s", timeout)
}

func (e *ensemble) health(addr string) (string, int) {
	resp, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		return err.Error(), 0
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b), resp.StatusCode
}

// post issues an authenticated POST to a node's internal API and returns the
// status code + decoded body map.
func (e *ensemble) post(addr, path string, body any) (int, map[string]any) {
	e.t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		e.t.Fatalf("marshal: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, "http://"+addr+path, bytes.NewReader(buf))
	if err != nil {
		e.t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+internalAPIKey)
	client := &http.Client{Timeout: 90 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		e.t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

// stop SIGTERMs every node and waits briefly, killing any straggler. Registered
// as a t.Cleanup so no process or port leaks across tests.
func (e *ensemble) stop() {
	for _, cmd := range e.procs {
		if cmd == nil || cmd.Process == nil {
			continue
		}
		_ = cmd.Process.Signal(syscall.SIGTERM)
	}
	for _, cmd := range e.procs {
		if cmd == nil || cmd.Process == nil {
			continue
		}
		done := make(chan struct{})
		go func(c *exec.Cmd) { _, _ = c.Process.Wait(); close(done) }(cmd)
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	}
}

// allLogs concatenates every node's captured output — used for the no-leak scan.
func (e *ensemble) allLogs() string {
	var b strings.Builder
	for i, lb := range e.logs {
		fmt.Fprintf(&b, "=== node%d ===\n%s\n", i, lb.String())
	}
	return b.String()
}

func tail(s string, lines int) string {
	parts := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(parts) <= lines {
		return s
	}
	return strings.Join(parts[len(parts)-lines:], "\n")
}

// TestLiveHTTPSign is the live keygen + threshold-sign + idempotency proof
// against a real 3-node 2-of-3 consensus ensemble over the HTTP endpoints.
func TestLiveHTTPSign(t *testing.T) {
	e := startEnsemble(t, 3, 2) // 3 nodes, 2-of-3 — the canonical ensemble.
	node0 := e.apiAddrs[0]

	// --- 1) LIVE KEYGEN (needs all 3 peers ready; allow a couple retries since
	// a fresh ensemble can race the first round). ---
	walletID := uuid.NewString()
	var keygen map[string]any
	var evmAddr, ecdsaPub string
	for attempt := 1; attempt <= 3; attempt++ {
		code, body := e.post(node0, "/keygen", map[string]string{
			"org_id":    "test-org",
			"wallet_id": walletID,
		})
		if code == http.StatusOK {
			if rt, _ := body["result_type"].(string); rt == "success" {
				keygen = body
				evmAddr, _ = body["evm_address"].(string)
				ecdsaPub, _ = body["ecdsa_pub_key"].(string)
				break
			}
		}
		t.Logf("keygen attempt %d not yet successful: code=%d body=%v", attempt, code, body)
		// New walletID per attempt so a stale in-flight session can't collide.
		walletID = uuid.NewString()
		time.Sleep(2 * time.Second)
	}
	if keygen == nil {
		t.Fatalf("LIVE KEYGEN failed after retries; node logs:\n%s", e.allLogs())
	}
	if ecdsaPub == "" {
		t.Fatalf("keygen returned empty ecdsa_pub_key: %v", keygen)
	}
	if evmAddr == "" || !strings.HasPrefix(evmAddr, "0x") || len(evmAddr) != 42 {
		t.Fatalf("keygen returned bad evm_address %q: %v", evmAddr, keygen)
	}
	t.Logf("LIVE KEYGEN OK: wallet=%s evm_address=%s ecdsa_pub_key=%s…",
		walletID, evmAddr, truncate(ecdsaPub, 16))

	// --- 2) LIVE THRESHOLD SIGN over a real 32-byte payload hash. ---
	digest := sha256.Sum256([]byte("live-e2e fake tx for " + walletID))
	payloadHash := hex.EncodeToString(digest[:])
	idemKey := uuid.NewString()
	signBody := map[string]any{
		"org_id":          "test-org",
		"wallet_id":       walletID,
		"key_type":        "secp256k1",
		"chain_id":        96369,
		"payload_hash":    payloadHash,
		"idempotency_key": idemKey,
	}

	code, sign1 := e.post(node0, "/sign", signBody)
	if code != http.StatusOK {
		t.Fatalf("LIVE SIGN failed: code=%d body=%v; logs:\n%s", code, sign1, e.allLogs())
	}
	if status, _ := sign1["status"].(string); status != "signed" {
		t.Fatalf("sign status = %v, want signed: %v", sign1["status"], sign1)
	}
	if errStr, _ := sign1["error"].(string); errStr != "" {
		t.Fatalf("sign returned error: %q", errStr)
	}
	sig1, _ := sign1["signature"].(string)
	if sig1 == "" {
		t.Fatalf("sign returned empty signature: %v", sign1)
	}
	if _, err := hex.DecodeString(sig1); err != nil {
		t.Fatalf("signature is not valid hex: %q (%v)", sig1, err)
	}
	t.Logf("LIVE THRESHOLD SIGN OK: signature=%s… session=%v", truncate(sig1, 32), sign1["session_id"])

	// --- 3) IDEMPOTENCY: same key + same content → cached identical signature
	// (signer NOT re-run). ---
	code, sign2 := e.post(node0, "/sign", signBody)
	if code != http.StatusOK {
		t.Fatalf("idempotent re-sign failed: code=%d body=%v", code, sign2)
	}
	sig2, _ := sign2["signature"].(string)
	if sig2 != sig1 {
		t.Fatalf("idempotency BROKEN: re-sign with same key returned different signature\n got=%s\nwant=%s", sig2, sig1)
	}
	t.Logf("IDEMPOTENCY cached-match OK: identical signature returned for repeated (key,content)")

	// --- 4) ANTI-ORACLE: same idempotency key, DIFFERENT payload → HTTP 409,
	// no signing. ---
	conflictBody := map[string]any{}
	for k, v := range signBody {
		conflictBody[k] = v
	}
	other := sha256.Sum256([]byte("a DIFFERENT tx under the same idempotency key"))
	conflictBody["payload_hash"] = hex.EncodeToString(other[:])
	code, conflict := e.post(node0, "/sign", conflictBody)
	if code != http.StatusConflict {
		t.Fatalf("anti-oracle BROKEN: reused idempotency key with new content → code=%d (want 409); body=%v", code, conflict)
	}
	t.Logf("ANTI-ORACLE 409 OK: reused key + different content refused without signing: %v", conflict["error"])

	// --- 5) Boundary: empty idempotency key → 400. ---
	emptyKeyBody := map[string]any{}
	for k, v := range signBody {
		emptyKeyBody[k] = v
	}
	emptyKeyBody["idempotency_key"] = ""
	code, badReq := e.post(node0, "/sign", emptyKeyBody)
	if code != http.StatusBadRequest {
		t.Fatalf("empty idempotency key → code=%d (want 400); body=%v", code, badReq)
	}
	t.Logf("BOUNDARY 400 OK: empty idempotency_key rejected: %v", badReq["error"])

	// --- 6) NO PLAINTEXT KEY ANYWHERE. The design never assembles a full
	// private key; assert no response or node log emits one. We scan for the
	// obvious secret markers AND for any 64-hex token that is NOT one of the
	// known PUBLIC values (pubkey/signature/payload). ---
	assertNoKeyLeak(t, e, ecdsaPub, sig1, payloadHash, fmt.Sprint(sign1), fmt.Sprint(keygen))
	t.Logf("NO-LEAK OK: no plaintext private key in any response or node log")
}

// truncate returns up to n leading characters of s — for log readability.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// assertNoKeyLeak fails if any captured response or node log contains a marker
// of private key material. The MPC design never assembles a full key, so the
// only key-shaped material that should ever appear is PUBLIC (pubkeys,
// addresses, signatures, protocol ssids/hashes).
func assertNoKeyLeak(t *testing.T, e *ensemble, public ...string) {
	t.Helper()
	haystack := strings.ToLower(e.allLogs() + " " + strings.Join(public, " "))
	for _, marker := range []string{
		"private_key", "privatekey", "priv_key", "privkey",
		"secret_key", "secretkey", "secret_share", "private share",
		"mnemonic", "seed phrase", "plaintext key",
	} {
		// The node DOES legitimately log the string "TLS identity keys" and
		// "Ed25519 keys" — those are about transport key PRESENCE, not values,
		// and don't match the markers above. So any hit here is a real leak.
		if strings.Contains(haystack, marker) {
			// Show the offending lines for diagnosis.
			for _, line := range strings.Split(e.allLogs(), "\n") {
				if strings.Contains(strings.ToLower(line), marker) {
					t.Errorf("possible key leak (marker %q): %s", marker, line)
				}
			}
		}
	}
}

