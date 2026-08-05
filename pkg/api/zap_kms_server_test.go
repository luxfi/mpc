// Wire-level tests for the KMS-facing ZAP server.
//
// The security claim: this port serves threshold signatures ONLY to a peer
// that has (a) completed the hybrid handshake and (b) proved a native IAM
// identity. Reachability is not authority.
//
// Every refusal test drives a real luxfi/zap.Node over a real socket and
// asserts on the BACKEND CALL COUNT, not just the response body — a server
// that signs and then reports an error is still a server that signed.
//
// The prior version of this file asserted the opposite. Its
// TestKMSZAP_SignRoundTrip dialed with no handshake and no credential and
// required the backend to sign; the fail-open was pinned in place by the
// test suite.
package api

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	kmszap "github.com/luxfi/mpc/pkg/zap"
	"github.com/luxfi/zap"
)

// stubBackend implements MPCBackend and counts every threshold operation it
// is asked to perform. A refusal test passes only if these stay at zero.
type stubBackend struct {
	mu           sync.Mutex
	keygenCalls  int
	signCalls    int
	reshareCalls int
}

func (s *stubBackend) TriggerKeygen(orgID, walletID string) (*KeygenResult, error) {
	s.mu.Lock()
	s.keygenCalls++
	s.mu.Unlock()
	return &KeygenResult{
		WalletID:    walletID,
		ECDSAPubKey: "0202020202",
		EDDSAPubKey: "0303030303",
		EVMAddress:  "0x0000000000000000000000000000000000000001",
	}, nil
}

func (s *stubBackend) TriggerSign(orgID, walletID string, payload []byte) (*SignResult, error) {
	s.mu.Lock()
	s.signCalls++
	s.mu.Unlock()
	return &SignResult{R: "aa", S: "bb", Signature: "ccdd"}, nil
}

func (s *stubBackend) TriggerReshare(orgID, walletID string, newT int, newP []string) error {
	s.mu.Lock()
	s.reshareCalls++
	s.mu.Unlock()
	return nil
}

func (s *stubBackend) ExportKeyShare(orgID, walletID string) ([]byte, error) { return nil, nil }

func (s *stubBackend) GetClusterStatus() *ClusterStatus {
	return &ClusterStatus{
		NodeID: "test-node", Mode: "consensus",
		ExpectedPeers: 3, ConnectedPeers: 3,
		Ready: true, Threshold: 2, Version: "test",
	}
}

func (s *stubBackend) counts() (keygen, sign, reshare int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keygenCalls, s.signCalls, s.reshareCalls
}

// requireUntouched fails when the backend performed any threshold work.
func (s *stubBackend) requireUntouched(t *testing.T) {
	t.Helper()
	k, sg, r := s.counts()
	if k != 0 || sg != 0 || r != 0 {
		t.Fatalf("SECURITY: backend ran for an unauthorized peer — keygen=%d sign=%d reshare=%d", k, sg, r)
	}
}

// stubVerifier accepts exactly the tokens it was given. It stands in for
// IAM so the server's ENFORCEMENT is tested independently of IAM's
// cryptography (which zap_kms_iam_test.go covers against a real JWKS).
type stubVerifier struct{ accept map[string]*Identity }

func (v *stubVerifier) Verify(_ context.Context, token string) (*Identity, error) {
	if id, ok := v.accept[token]; ok {
		return id, nil
	}
	return nil, fmt.Errorf("token not recognized")
}

const goodToken = "iam-access-token-for-kms-pod"

func testVerifier() *stubVerifier {
	return &stubVerifier{accept: map[string]*Identity{
		goodToken: {Subject: "lux/lux-kms", Owner: "lux", Expires: time.Now().Add(time.Hour)},
	}}
}

func pickPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pickPort: %v", err)
	}
	addr := l.Addr().(*net.TCPAddr)
	l.Close()
	return fmt.Sprintf("127.0.0.1:%d", addr.Port)
}

func startServer(t *testing.T) (*KMSZapServer, *stubBackend, string) {
	t.Helper()
	backend := &stubBackend{}
	addr := pickPort(t)
	srv, err := StartKMSZAP(backend, "test-server", addr, testVerifier())
	if err != nil {
		t.Fatalf("StartKMSZAP: %v", err)
	}
	t.Cleanup(srv.Stop)
	time.Sleep(50 * time.Millisecond)
	return srv, backend, addr
}

// client is a synthetic KMS peer. Each step of the protocol is separate so
// a test can stop partway and prove the server refuses.
type client struct {
	node *zap.Node
	peer string
	sess *kmszap.Session
	st   *kmszap.ClientState
}

// dial connects without performing any handshake.
func dial(t *testing.T, addr, nodeID string) *client {
	t.Helper()
	n := zap.NewNode(zap.NodeConfig{
		NodeID: nodeID, ServiceType: "_mpc-kms._tcp", NoDiscovery: true,
	})
	if err := n.ConnectDirect(addr); err != nil {
		t.Fatalf("ConnectDirect %s: %v", addr, err)
	}
	peers := n.Peers()
	if len(peers) == 0 {
		t.Fatal("no peers after ConnectDirect")
	}
	t.Cleanup(n.Stop)
	return &client{node: n, peer: peers[0]}
}

// raw sends opcode||body verbatim and returns the response opcode and body.
func (c *client) raw(t *testing.T, op uint16, body []byte) (uint16, []byte) {
	t.Helper()
	out := make([]byte, 2+len(body))
	binary.LittleEndian.PutUint16(out[0:2], op)
	copy(out[2:], body)
	b := zap.NewBuilder(len(out) + 64)
	b.WriteBytes(out)
	msg, err := zap.Parse(b.Finish())
	if err != nil {
		t.Fatalf("parse req: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := c.node.Call(ctx, c.peer, msg)
	if err != nil {
		t.Fatalf("Call op=0x%04x: %v", op, err)
	}
	raw := resp.Bytes()
	if len(raw) < zap.HeaderSize+2 {
		t.Fatalf("response too short: %d bytes", len(raw))
	}
	rb := raw[zap.HeaderSize:]
	return binary.LittleEndian.Uint16(rb[0:2]), rb[2:]
}

// handshake runs ClientHello/ServerHello with the given capabilities.
func (c *client) handshake(t *testing.T, caps uint16) ([]byte, error) {
	t.Helper()
	st, hello, err := kmszap.NewClient(caps)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	c.st = st
	op, body := c.raw(t, kmszap.OpClientHello, hello)
	if op != kmszap.OpServerHello {
		t.Fatalf("handshake reply opcode: want 0x%04x got 0x%04x", kmszap.OpServerHello, op)
	}
	if errText(body) != "" {
		return body, fmt.Errorf("%s", errText(body))
	}
	res, err := st.ClientFinish(body)
	if err != nil {
		return body, err
	}
	sess, err := kmszap.NewSession(res.SessionKey, res.Hybrid)
	if err != nil {
		return body, err
	}
	c.sess = sess
	return body, nil
}

// auth presents a token, sealed under the session key.
func (c *client) auth(t *testing.T, token string) []byte {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"token": token})
	return c.sealedCall(t, kmszap.OpAuth, body)
}

// call issues a KMS opcode with a sealed JSON payload.
func (c *client) call(t *testing.T, op uint16, payload any) []byte {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return c.sealedCall(t, op, body)
}

func (c *client) sealedCall(t *testing.T, op uint16, plain []byte) []byte {
	t.Helper()
	sealed, err := c.sess.Seal(kmszap.DirClientToServer, plain)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	respOp, respBody := c.raw(t, op, sealed)
	if respOp != op {
		t.Fatalf("response opcode: want 0x%04x got 0x%04x", op, respOp)
	}
	// A refusal issued before the session existed comes back unsealed.
	if opened, err := c.sess.Open(kmszap.DirServerToClient, respBody); err == nil {
		return opened
	}
	return respBody
}

// errText returns the "error" field of a JSON body, or "".
func errText(body []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &e) != nil {
		return ""
	}
	return e.Error
}

func requireRefused(t *testing.T, body []byte, want string) {
	t.Helper()
	got := errText(body)
	if got == "" {
		t.Fatalf("SECURITY: expected a refusal, got a served response: %s", string(body))
	}
	if !strings.Contains(got, want) {
		t.Fatalf("refusal reason: got %q, want it to contain %q", got, want)
	}
	t.Logf("refused as expected: %q", got)
}

// --- Refusals ---

// TestNoHandshakeIsRefused is the exact attack the old code served: a peer
// that simply never sends ClientHello and talks in the clear.
func TestNoHandshakeIsRefused(t *testing.T) {
	_, backend, addr := startServer(t)
	c := dial(t, addr, "attacker")

	for _, tc := range []struct {
		name string
		op   uint16
		body any
	}{
		{"sign", OpKMSSign, kmsZapSignRequest{VaultID: "v", WalletID: "w", Payload: []byte("give me a signature")}},
		{"keygen", OpKMSKeygen, map[string]string{"vault_id": "v"}},
		{"status", OpKMSStatus, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plain, _ := json.Marshal(tc.body)
			_, resp := c.raw(t, tc.op, plain)
			requireRefused(t, resp, "handshake required")
		})
	}
	backend.requireUntouched(t)
}

// TestHandshakeWithoutAuthIsRefused: holding a session key is not identity.
func TestHandshakeWithoutAuthIsRefused(t *testing.T) {
	_, backend, addr := startServer(t)
	c := dial(t, addr, "kms-pod-0")
	if _, err := c.handshake(t, kmszap.CapMLKEM768); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	resp := c.call(t, OpKMSSign, kmsZapSignRequest{
		VaultID: "v", WalletID: "w", Payload: []byte("sign me"),
	})
	requireRefused(t, resp, "authentication required")
	backend.requireUntouched(t)
}

// TestBadTokenIsRefused: a peer that presents a credential IAM does not
// recognize gets nothing, and learns nothing about why.
func TestBadTokenIsRefused(t *testing.T) {
	_, backend, addr := startServer(t)
	c := dial(t, addr, "kms-pod-0")
	if _, err := c.handshake(t, kmszap.CapMLKEM768); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	authResp := c.auth(t, "forged-token")
	requireRefused(t, authResp, "authentication failed")

	resp := c.call(t, OpKMSSign, kmsZapSignRequest{
		VaultID: "v", WalletID: "w", Payload: []byte("sign me"),
	})
	requireRefused(t, resp, "authentication required")
	backend.requireUntouched(t)
}

// TestExpiredCredentialIsRefused: a verified identity stops working when
// the token behind it expires, without waiting for a reconnect.
func TestExpiredCredentialIsRefused(t *testing.T) {
	backend := &stubBackend{}
	addr := pickPort(t)
	v := &stubVerifier{accept: map[string]*Identity{
		goodToken: {Subject: "lux/lux-kms", Owner: "lux", Expires: time.Now().Add(-time.Second)},
	}}
	srv, err := StartKMSZAP(backend, "test-server", addr, v)
	if err != nil {
		t.Fatalf("StartKMSZAP: %v", err)
	}
	t.Cleanup(srv.Stop)
	time.Sleep(50 * time.Millisecond)

	c := dial(t, addr, "kms-pod-0")
	if _, err := c.handshake(t, kmszap.CapMLKEM768); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if e := errText(c.auth(t, goodToken)); e != "" {
		t.Fatalf("auth should succeed (the token verifies; it is merely stale): %s", e)
	}
	resp := c.call(t, OpKMSSign, kmsZapSignRequest{
		VaultID: "v", WalletID: "w", Payload: []byte("sign me"),
	})
	requireRefused(t, resp, "credential expired")
	backend.requireUntouched(t)
}

// TestSpoofedPeerIDCannotUseAnotherSession is the attack that survives a
// naive fix. zap's `from` is a string the peer chooses, so an attacker can
// name itself after an authenticated pod and land on its session entry.
// It still cannot produce a frame that opens under that session's key.
func TestSpoofedPeerIDCannotUseAnotherSession(t *testing.T) {
	_, backend, addr := startServer(t)

	victim := dial(t, addr, "kms-pod-0")
	if _, err := victim.handshake(t, kmszap.CapMLKEM768); err != nil {
		t.Fatalf("victim handshake: %v", err)
	}
	if e := errText(victim.auth(t, goodToken)); e != "" {
		t.Fatalf("victim auth: %s", e)
	}
	// Victim works.
	if e := errText(victim.call(t, OpKMSSign, kmsZapSignRequest{
		VaultID: "v", WalletID: "w", Payload: []byte("legit"),
	})); e != "" {
		t.Fatalf("victim sign should succeed: %s", e)
	}
	victim.node.Stop()
	time.Sleep(100 * time.Millisecond)

	// Attacker claims the victim's node ID and sends plaintext, hoping to
	// ride the session the victim authenticated.
	attacker := dial(t, addr, "kms-pod-0")
	plain, _ := json.Marshal(kmsZapSignRequest{
		VaultID: "v", WalletID: "w", Payload: []byte("stolen"),
	})
	_, resp := attacker.raw(t, OpKMSSign, plain)
	requireRefused(t, resp, "session decrypt failed")

	// One signature, the victim's. The attacker got none.
	_, signs, _ := backend.counts()
	if signs != 1 {
		t.Fatalf("SECURITY: expected exactly the victim's 1 signature, got %d", signs)
	}
}

// TestMLKEMDowngradeIsRefused: a peer that clears the ML-KEM bit asks for
// classical-only key agreement. Both ends of this wire are ours.
func TestMLKEMDowngradeIsRefused(t *testing.T) {
	_, backend, addr := startServer(t)
	c := dial(t, addr, "downgrader")
	body, err := c.handshake(t, 0) // no CapMLKEM768
	if err == nil {
		t.Fatal("SECURITY: classical-only handshake was accepted")
	}
	requireRefused(t, body, "ML-KEM-768 required")
	backend.requireUntouched(t)
}

// TestVerifierIsMandatory: there is no way to build a server that serves
// anonymously — not a flag, not a zero value.
func TestVerifierIsMandatory(t *testing.T) {
	_, err := StartKMSZAP(&stubBackend{}, "test-server", pickPort(t), nil)
	if err == nil {
		t.Fatal("SECURITY: StartKMSZAP built a server with no identity verifier")
	}
	t.Logf("refused to start: %v", err)
}

// --- The authenticated path still works ---

// TestAuthenticatedPeerIsServed proves the refusals above are not simply a
// server that refuses everything.
func TestAuthenticatedPeerIsServed(t *testing.T) {
	_, backend, addr := startServer(t)
	c := dial(t, addr, "kms-pod-0")
	if _, err := c.handshake(t, kmszap.CapMLKEM768); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	authBody := c.auth(t, goodToken)
	if e := errText(authBody); e != "" {
		t.Fatalf("auth failed: %s", e)
	}
	var who struct {
		Subject string `json:"subject"`
		Owner   string `json:"owner"`
	}
	if err := json.Unmarshal(authBody, &who); err != nil {
		t.Fatalf("decode auth reply: %v body=%s", err, authBody)
	}
	if who.Subject != "lux/lux-kms" || who.Owner != "lux" {
		t.Fatalf("auth reply: got %+v", who)
	}

	t.Run("sign", func(t *testing.T) {
		body := c.call(t, OpKMSSign, kmsZapSignRequest{
			VaultID: "vault-1", WalletID: "wallet-1", Payload: []byte("hello-mpc"),
		})
		var sr SignResult
		if err := json.Unmarshal(body, &sr); err != nil {
			t.Fatalf("decode sign: %v body=%s", err, body)
		}
		if sr.R != "aa" || sr.S != "bb" {
			t.Fatalf("sign: got R=%q S=%q want aa/bb", sr.R, sr.S)
		}
	})

	t.Run("keygen", func(t *testing.T) {
		body := c.call(t, OpKMSKeygen, map[string]any{
			"vault_id": "vault-1",
			"request":  map[string]string{"wallet_id": "wallet-2"},
		})
		var kr KeygenResult
		if err := json.Unmarshal(body, &kr); err != nil {
			t.Fatalf("decode keygen: %v body=%s", err, body)
		}
		if kr.WalletID != "wallet-2" {
			t.Fatalf("keygen: got %+v", kr)
		}
	})

	t.Run("status", func(t *testing.T) {
		body := c.call(t, OpKMSStatus, nil)
		var st kmsZapStatusResponse
		if err := json.Unmarshal(body, &st); err != nil {
			t.Fatalf("decode status: %v body=%s", err, body)
		}
		if st.NodeID != "test-node" || st.Threshold != 2 || !st.Ready {
			t.Fatalf("status: got %+v", st)
		}
	})

	k, s, _ := backend.counts()
	if k != 1 || s != 1 {
		t.Fatalf("backend calls: keygen=%d sign=%d, want 1/1", k, s)
	}
}

// TestUnknownOpcodeAfterAuth keeps the mux honest: an authenticated peer
// asking for something that does not exist gets an error, not a panic.
func TestUnknownOpcodeAfterAuth(t *testing.T) {
	_, _, addr := startServer(t)
	c := dial(t, addr, "kms-pod-0")
	if _, err := c.handshake(t, kmszap.CapMLKEM768); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if e := errText(c.auth(t, goodToken)); e != "" {
		t.Fatalf("auth: %s", e)
	}
	resp := c.call(t, 0x0099, map[string]string{})
	requireRefused(t, resp, "unknown opcode")
}
