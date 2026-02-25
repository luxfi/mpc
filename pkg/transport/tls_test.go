package transport

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func TestPQTLSHandshake(t *testing.T) {
	// Generate two Ed25519 keypairs (server + client)
	_, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	serverPub := serverPriv.Public().(ed25519.PublicKey)

	_, clientPriv, _ := ed25519.GenerateKey(rand.Reader)
	clientPub := clientPriv.Public().(ed25519.PublicKey)

	// Start TLS server
	serverTLS, err := NewServerTLSConfig("server", serverPriv, serverPub)
	if err != nil {
		t.Fatal(err)
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	addr := listener.Addr().String()
	done := make(chan string, 1)

	// Server goroutine
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- fmt.Sprintf("accept error: %v", err)
			return
		}
		defer conn.Close()

		tlsConn := conn.(*tls.Conn)
		if err := tlsConn.Handshake(); err != nil {
			done <- fmt.Sprintf("server handshake error: %v", err)
			return
		}

		state := tlsConn.ConnectionState()
		done <- state.NegotiatedProtocol

		// Echo one message
		buf := make([]byte, 128)
		n, _ := conn.Read(buf)
		conn.Write(buf[:n])
	}()

	// Client connects with PQ TLS
	clientTLS, err := NewClientTLSConfig("client", clientPriv, clientPub)
	if err != nil {
		t.Fatal(err)
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, clientTLS)
	if err != nil {
		t.Fatalf("client dial failed: %v", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()

	// Verify TLS 1.3
	if state.Version != tls.VersionTLS13 {
		t.Errorf("expected TLS 1.3, got 0x%04x", state.Version)
	}

	// Log the negotiated curve (should be X25519MLKEM768 or similar)
	t.Logf("TLS version: 0x%04x", state.Version)
	t.Logf("Cipher suite: %s", tls.CipherSuiteName(state.CipherSuite))
	t.Logf("Curve ID: %s", state.CurveID.String())
	t.Logf("Server name: %s", state.ServerName)

	// Check PQ was negotiated
	isPQ := state.CurveID == tls.X25519MLKEM768 ||
		state.CurveID == tls.SecP256r1MLKEM768 ||
		state.CurveID == tls.SecP384r1MLKEM1024
	if !isPQ {
		t.Errorf("expected post-quantum curve, got %s (%d)", state.CurveID.String(), state.CurveID)
	} else {
		t.Logf("Post-quantum key exchange confirmed: %s", state.CurveID.String())
	}

	// Verify data flows
	msg := []byte("hello PQ MPC")
	conn.Write(msg)
	resp := make([]byte, 128)
	n, err := conn.Read(resp)
	if err != nil && err != io.EOF {
		t.Fatalf("read error: %v", err)
	}
	if string(resp[:n]) != string(msg) {
		t.Errorf("echo mismatch: got %q, want %q", resp[:n], msg)
	}

	<-done
}
