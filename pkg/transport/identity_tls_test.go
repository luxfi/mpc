// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package transport

import (
	"crypto/ed25519"
	"crypto/rand"
	"sync"
	"testing"
	"time"
)

// TestLearnPeerIdentityFromTLS verifies that BOTH the dialer and the acceptor
// learn each other's Ed25519 identity directly from the mutually-authenticated
// TLS certificate. The acceptor->dialer direction is the one the previous
// `ClientAuth: tls.NoClientCert` server config broke: without a client cert the
// acceptor never saw the dialer's key, so keygen/sign signature verification
// dropped every message as "public key not found for node …". This test pins
// the fix (RequireAnyClientCert + learnPeerIdentityFromTLS).
func TestLearnPeerIdentityFromTLS(t *testing.T) {
	srvPub, srvPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen server key: %v", err)
	}
	cliPub, cliPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen client key: %v", err)
	}

	ln, err := ListenTLS("127.0.0.1:0", "server", srvPriv, srvPub)
	if err != nil {
		t.Fatalf("ListenTLS: %v", err)
	}
	defer ln.Close()

	var mu sync.Mutex
	learned := map[string]ed25519.PublicKey{}
	record := func(who string) func(string, ed25519.PublicKey) {
		return func(id string, pk ed25519.PublicKey) {
			mu.Lock()
			learned[who+":"+id] = pk
			mu.Unlock()
		}
	}
	srvT := &Transport{config: &Config{NodeID: "server", OnPeerIdentity: record("server-saw")}}
	cliT := &Transport{config: &Config{NodeID: "client", OnPeerIdentity: record("client-saw")}}

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, aerr := ln.Accept()
		if aerr != nil {
			t.Errorf("Accept: %v", aerr)
			return
		}
		defer conn.Close()
		srvT.learnPeerIdentityFromTLS(conn)
	}()

	conn, err := DialTLS(ln.Addr().String(), "client", cliPriv, cliPub, 5*time.Second)
	if err != nil {
		t.Fatalf("DialTLS: %v", err)
	}
	defer conn.Close()
	cliT.learnPeerIdentityFromTLS(conn)

	<-done

	mu.Lock()
	defer mu.Unlock()

	if pk, ok := learned["client-saw:server"]; !ok || !pk.Equal(srvPub) {
		t.Errorf("dialer did not learn acceptor identity from TLS server cert (ok=%v)", ok)
	}
	if pk, ok := learned["server-saw:client"]; !ok || !pk.Equal(cliPub) {
		t.Errorf("acceptor did not learn dialer identity from TLS client cert — the NoClientCert regression (ok=%v)", ok)
	}
}
