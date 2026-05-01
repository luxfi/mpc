// In-process KMS ZAP server round-trip test. Spins up a real luxfi/zap.Node
// listener, dials it as a synthetic client, exercises the handshake +
// status / sign / keygen opcodes, and asserts wire framing.
package api

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	kmszap "github.com/luxfi/mpc/pkg/zap"
	"github.com/luxfi/zap"
)

// stubBackend implements MPCBackend with deterministic results so tests can
// assert byte-level outputs without standing up the full consensus stack.
type stubBackend struct {
	keygenCalls int
	signCalls   int
	mu          sync.Mutex
}

func (s *stubBackend) TriggerKeygen(orgID, walletID string) (*KeygenResult, error) {
	s.mu.Lock()
	s.keygenCalls++
	s.mu.Unlock()
	return &KeygenResult{
		WalletID:    walletID,
		ECDSAPubKey: "0202020202",
		EDDSAPubKey: "0303030303",
		EthAddress:  "0x0000000000000000000000000000000000000001",
	}, nil
}
func (s *stubBackend) TriggerSign(orgID, walletID string, payload []byte) (*SignResult, error) {
	s.mu.Lock()
	s.signCalls++
	s.mu.Unlock()
	return &SignResult{R: "aa", S: "bb", Signature: "ccdd"}, nil
}
func (s *stubBackend) TriggerReshare(orgID, walletID string, newT int, newP []string) error {
	return nil
}
func (s *stubBackend) ExportKeyShare(orgID, walletID string) ([]byte, error) { return nil, nil }
func (s *stubBackend) GetClusterStatus() *ClusterStatus {
	return &ClusterStatus{
		NodeID:         "test-node",
		Mode:           "consensus",
		ExpectedPeers:  3,
		ConnectedPeers: 3,
		Ready:          true,
		Threshold:      2,
		Version:        "test",
	}
}

// pickPort grabs a free TCP port from the kernel and returns it as a string.
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

// startServer spins a KMSZapServer on a free port and returns the address +
// a cleanup function.
func startServer(t *testing.T) (*KMSZapServer, string, func()) {
	t.Helper()
	addr := pickPort(t)
	srv, err := StartKMSZAP(&stubBackend{}, "test-server", addr)
	if err != nil {
		t.Fatalf("StartKMSZAP: %v", err)
	}
	// Give the listener a moment to come up before clients dial.
	time.Sleep(50 * time.Millisecond)
	return srv, addr, func() { srv.Stop() }
}

// dialClient creates a luxfi/zap.Node, dials the server, and returns the
// peer ID once a connection is up.
func dialClient(t *testing.T, addr string) (*zap.Node, string) {
	t.Helper()
	client := zap.NewNode(zap.NodeConfig{
		NodeID:      "test-client",
		ServiceType: "_mpc-kms._tcp",
		NoDiscovery: true,
	})
	if err := client.ConnectDirect(addr); err != nil {
		t.Fatalf("ConnectDirect %s: %v", addr, err)
	}
	peers := client.Peers()
	if len(peers) == 0 {
		t.Fatal("no peers after ConnectDirect")
	}
	return client, peers[0]
}

// callOp builds opcode(2 LE) || jsonPayload, sends it to the server, and
// returns the response opcode + body.
func callOp(t *testing.T, client *zap.Node, peerID string, op uint16, payload any) (uint16, []byte) {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := make([]byte, 2+len(data))
	binary.LittleEndian.PutUint16(body[0:2], op)
	copy(body[2:], data)

	b := zap.NewBuilder(len(body) + 64)
	b.WriteBytes(body)
	msg, err := zap.Parse(b.Finish())
	if err != nil {
		t.Fatalf("parse req: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := client.Call(ctx, peerID, msg)
	if err != nil {
		t.Fatalf("Call op=0x%04x: %v", op, err)
	}
	raw := resp.Bytes()
	if len(raw) < zap.HeaderSize+2 {
		t.Fatalf("response too short: %d bytes", len(raw))
	}
	respBody := raw[zap.HeaderSize:]
	respOp := binary.LittleEndian.Uint16(respBody[0:2])
	return respOp, respBody[2:]
}

// TestKMSZAP_StatusRoundTrip exercises the smallest-possible RPC: status, no
// payload, no auth. Asserts the server frames the response correctly and the
// stub backend's data flows back.
func TestKMSZAP_StatusRoundTrip(t *testing.T) {
	_, addr, stop := startServer(t)
	defer stop()
	client, peer := dialClient(t, addr)
	defer client.Stop()

	respOp, body := callOp(t, client, peer, OpKMSStatus, nil)
	if respOp != OpKMSStatus {
		t.Fatalf("response opcode: want 0x%04x got 0x%04x", OpKMSStatus, respOp)
	}
	var st kmsZapStatusResponse
	if err := json.Unmarshal(body, &st); err != nil {
		t.Fatalf("unmarshal status: %v body=%s", err, string(body))
	}
	if st.NodeID != "test-node" {
		t.Errorf("NodeID: want test-node got %q", st.NodeID)
	}
	if st.Threshold != 2 {
		t.Errorf("Threshold: want 2 got %d", st.Threshold)
	}
	if !st.Ready {
		t.Errorf("Ready: want true got false")
	}
}

// TestKMSZAP_SignRoundTrip drives a sign call through the wire and asserts
// the backend was actually invoked.
func TestKMSZAP_SignRoundTrip(t *testing.T) {
	srv, addr, stop := startServer(t)
	defer stop()
	client, peer := dialClient(t, addr)
	defer client.Stop()

	req := kmsZapSignRequest{
		VaultID:  "vault-1",
		WalletID: "wallet-1",
		Payload:  []byte("hello-mpc"),
	}
	respOp, body := callOp(t, client, peer, OpKMSSign, req)
	if respOp != OpKMSSign {
		t.Fatalf("response opcode: want 0x%04x got 0x%04x", OpKMSSign, respOp)
	}
	var sr SignResult
	if err := json.Unmarshal(body, &sr); err != nil {
		t.Fatalf("unmarshal sign: %v body=%s", err, string(body))
	}
	if sr.R != "aa" || sr.S != "bb" {
		t.Errorf("sign: got R=%q S=%q want aa/bb", sr.R, sr.S)
	}
	stub := srv.backend.(*stubBackend)
	stub.mu.Lock()
	calls := stub.signCalls
	stub.mu.Unlock()
	if calls != 1 {
		t.Errorf("backend sign calls: want 1 got %d", calls)
	}
}

// TestKMSZAP_KeygenRoundTrip drives keygen + asserts the wallet ID pass-thru.
func TestKMSZAP_KeygenRoundTrip(t *testing.T) {
	_, addr, stop := startServer(t)
	defer stop()
	client, peer := dialClient(t, addr)
	defer client.Stop()

	req := kmsZapKeygenRequest{VaultID: "vault-1"}
	req.Request.WalletID = "wallet-2"
	respOp, body := callOp(t, client, peer, OpKMSKeygen, req)
	if respOp != OpKMSKeygen {
		t.Fatalf("response opcode: want 0x%04x got 0x%04x", OpKMSKeygen, respOp)
	}
	var kr KeygenResult
	if err := json.Unmarshal(body, &kr); err != nil {
		t.Fatalf("unmarshal keygen: %v body=%s", err, string(body))
	}
	if kr.WalletID != "wallet-2" {
		t.Errorf("WalletID: want wallet-2 got %q", kr.WalletID)
	}
	if kr.ECDSAPubKey == "" {
		t.Errorf("ECDSAPubKey empty")
	}
}

// TestKMSZAP_HybridHandshake runs the full ML-KEM-768 hybrid handshake and
// confirms a session is installed for the peer afterwards.
func TestKMSZAP_HybridHandshake(t *testing.T) {
	srv, addr, stop := startServer(t)
	defer stop()
	client, peer := dialClient(t, addr)
	defer client.Stop()

	cliState, helloWire, err := kmszap.NewClient(kmszap.CapMLKEM768)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	// Frame: opcode || helloWire
	body := make([]byte, 2+len(helloWire))
	binary.LittleEndian.PutUint16(body[0:2], kmszap.OpClientHello)
	copy(body[2:], helloWire)
	b := zap.NewBuilder(len(body) + 64)
	b.WriteBytes(body)
	msg, err := zap.Parse(b.Finish())
	if err != nil {
		t.Fatalf("parse hello: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := client.Call(ctx, peer, msg)
	if err != nil {
		t.Fatalf("handshake call: %v", err)
	}
	raw := resp.Bytes()
	respBody := raw[zap.HeaderSize:]
	respOp := binary.LittleEndian.Uint16(respBody[0:2])
	if respOp != kmszap.OpServerHello {
		t.Fatalf("handshake opcode: want 0x%04x got 0x%04x", kmszap.OpServerHello, respOp)
	}
	result, err := cliState.ClientFinish(respBody[2:])
	if err != nil {
		t.Fatalf("ClientFinish: %v", err)
	}
	if !result.Hybrid {
		t.Errorf("expected hybrid (ML-KEM-768) negotiation")
	}
	if len(result.SessionKey) != 32 {
		t.Errorf("session key length: want 32 got %d", len(result.SessionKey))
	}

	// Server-side: peer should have an installed session keyed by client peer ID.
	// The client peer ID as seen by the server is the test-client node ID.
	srv.sessionsMu.RLock()
	count := len(srv.sessions)
	srv.sessionsMu.RUnlock()
	if count == 0 {
		t.Errorf("expected server to have installed a session after handshake")
	}
}

// TestKMSZAP_UnknownOpcode confirms the server returns a structured error for
// unknown opcodes rather than dropping the connection.
func TestKMSZAP_UnknownOpcode(t *testing.T) {
	_, addr, stop := startServer(t)
	defer stop()
	client, peer := dialClient(t, addr)
	defer client.Stop()

	respOp, body := callOp(t, client, peer, 0x9999, nil)
	if respOp != 0x9999 {
		t.Errorf("unknown opcode echo: want 0x9999 got 0x%04x", respOp)
	}
	var e map[string]string
	if err := json.Unmarshal(body, &e); err != nil {
		t.Fatalf("unmarshal err: %v body=%s", err, string(body))
	}
	if e["error"] == "" {
		t.Errorf("expected error string in body, got %v", e)
	}
}
