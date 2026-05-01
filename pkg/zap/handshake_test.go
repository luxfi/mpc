// Smoke test for the vendored ML-KEM-768 hybrid handshake. The audited
// reference suite lives in luxfi/kms/pkg/zap. This file pins three
// invariants that MUST hold for KMS↔MPC interop:
//
//  1. NewClient → ServerRespond → ClientFinish round-trips with hybrid=true
//     when both sides advertise CapMLKEM768.
//  2. Both sides derive the same 32-byte session key.
//  3. Sealing under that key on one side opens on the other.
//
// If any of these break, KMS clients can no longer talk to MPC servers
// and the secrets-only mode regression returns.
package zap

import (
	"bytes"
	"testing"
)

func TestHandshakeHybridRoundTrip(t *testing.T) {
	cli, helloWire, err := NewClient(CapMLKEM768)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	replyWire, srvResult, err := ServerRespond(CapMLKEM768, helloWire)
	if err != nil {
		t.Fatalf("ServerRespond: %v", err)
	}
	cliResult, err := cli.ClientFinish(replyWire)
	if err != nil {
		t.Fatalf("ClientFinish: %v", err)
	}
	if !srvResult.Hybrid || !cliResult.Hybrid {
		t.Fatalf("expected hybrid both sides; srv=%v cli=%v", srvResult.Hybrid, cliResult.Hybrid)
	}
	if !bytes.Equal(srvResult.SessionKey, cliResult.SessionKey) {
		t.Fatalf("session key mismatch")
	}
	if len(srvResult.SessionKey) != SessionKeySize {
		t.Fatalf("session key size: want %d got %d", SessionKeySize, len(srvResult.SessionKey))
	}
}

func TestSessionSealOpen(t *testing.T) {
	cli, helloWire, err := NewClient(CapMLKEM768)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	replyWire, srv, err := ServerRespond(CapMLKEM768, helloWire)
	if err != nil {
		t.Fatalf("ServerRespond: %v", err)
	}
	cliRes, err := cli.ClientFinish(replyWire)
	if err != nil {
		t.Fatalf("ClientFinish: %v", err)
	}
	cliSess, err := NewSession(cliRes.SessionKey, cliRes.Hybrid)
	if err != nil {
		t.Fatalf("NewSession cli: %v", err)
	}
	srvSess, err := NewSession(srv.SessionKey, srv.Hybrid)
	if err != nil {
		t.Fatalf("NewSession srv: %v", err)
	}

	// C → S
	plaintext := []byte("threshold-sign-payload")
	sealed, err := cliSess.Seal(DirClientToServer, plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	pt, err := srvSess.Open(DirClientToServer, sealed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("plaintext mismatch")
	}

	// S → C uses the opposite direction tag.
	srvReply := []byte("ok")
	sealedReply, err := srvSess.Seal(DirServerToClient, srvReply)
	if err != nil {
		t.Fatalf("Seal reply: %v", err)
	}
	openedReply, err := cliSess.Open(DirServerToClient, sealedReply)
	if err != nil {
		t.Fatalf("Open reply: %v", err)
	}
	if !bytes.Equal(openedReply, srvReply) {
		t.Fatalf("reply mismatch")
	}
}
