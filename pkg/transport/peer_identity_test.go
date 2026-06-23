// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Unit tests for the consensus peer-identity propagation fix.
//
// Bug (pre-fix): in consensus mode each node's identity store only knew its
// OWN Ed25519 public key. Peer keys arrive in ReadySignal.PublicKey during the
// transport identity handshake (sendIdentity) but were discarded — never fed to
// the identity store. Result: VerifyWireMessage could not resolve a peer's key,
// so every inbound CGGMP21/FROST/signing wire message was dropped
// ("public key not found for node: …") and keygen/signing stalled until timeout.
//
// Fix: transport.Config.OnPeerIdentity is invoked (via notifyPeerIdentity)
// whenever a peer's key is learned from the handshake, with boundary guards.
// main.go wires it to ConsensusIdentityStore.AddPeerPublicKey — the
// consensus-mode analog of the legacy NATS path's peers.json + *_identity.json
// seeding (pkg/identity.fileStore).
//
// These tests pin the guard logic of notifyPeerIdentity without standing up a
// real TLS mesh (that path is exercised end-to-end by ../../e2e
// live_http_sign_test.go).
package transport

import (
	"crypto/ed25519"
	"testing"
)

// newTestTransport builds a Transport with just enough config to exercise
// notifyPeerIdentity. No listener, no peers — we only call the helper directly.
func newTestTransport(t *testing.T, nodeID string, onPeer func(string, ed25519.PublicKey)) *Transport {
	t.Helper()
	return &Transport{
		config: &Config{
			NodeID:         nodeID,
			OnPeerIdentity: onPeer,
		},
	}
}

func freshPubKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub
}

// Test_NotifyPeerIdentity_ForwardsValidPeerKey is the core of the fix: a real
// peer key for a different node reaches the observer, and the observer receives
// a COPY (mutating the source afterwards must not change what was delivered).
func Test_NotifyPeerIdentity_ForwardsValidPeerKey(t *testing.T) {
	var gotID string
	var gotKey ed25519.PublicKey
	calls := 0
	tr := newTestTransport(t, "node0", func(id string, key ed25519.PublicKey) {
		calls++
		gotID = id
		gotKey = key
	})

	peerKey := freshPubKey(t)
	tr.notifyPeerIdentity("node1", peerKey)

	if calls != 1 {
		t.Fatalf("expected observer called once, got %d", calls)
	}
	if gotID != "node1" {
		t.Fatalf("expected nodeID=node1, got %q", gotID)
	}
	if len(gotKey) != ed25519.PublicKeySize {
		t.Fatalf("expected %d-byte key, got %d", ed25519.PublicKeySize, len(gotKey))
	}
	if !gotKey.Equal(peerKey) {
		t.Fatal("delivered key does not match source key")
	}

	// Defensive-copy proof: mutating the source slice must not affect the
	// already-delivered key (the wire buffer can be reused by the caller).
	peerKey[0] ^= 0xFF
	if gotKey.Equal(peerKey) {
		t.Fatal("observer received a reference to the caller's slice, not a copy")
	}
}

// Test_NotifyPeerIdentity_Guards covers every short-circuit: self, empty
// nodeID, and a wrong-length key must NOT reach the observer. This is what
// keeps the identity store from ever being polluted with a non-peer or a
// malformed key.
func Test_NotifyPeerIdentity_Guards(t *testing.T) {
	good := freshPubKey(t)
	short := make(ed25519.PublicKey, 16) // too short to be a real Ed25519 key

	cases := []struct {
		name      string
		nodeID    string
		key       ed25519.PublicKey
		wantCalls int
	}{
		{"valid peer", "node1", good, 1},
		{"self is skipped", "node0", good, 0},
		{"empty nodeID skipped", "", good, 0},
		{"wrong-length key skipped", "node1", short, 0},
		{"nil key skipped", "node1", nil, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			tr := newTestTransport(t, "node0", func(string, ed25519.PublicKey) { calls++ })
			tr.notifyPeerIdentity(tc.nodeID, tc.key)
			if calls != tc.wantCalls {
				t.Fatalf("nodeID=%q keyLen=%d → observer calls=%d, want %d",
					tc.nodeID, len(tc.key), calls, tc.wantCalls)
			}
		})
	}
}

// Test_NotifyPeerIdentity_NilObserver proves the helper is a safe no-op when no
// observer is configured (e.g. a standalone node, or a caller that does not
// need dynamic peer-key learning). Must not panic.
func Test_NotifyPeerIdentity_NilObserver(t *testing.T) {
	tr := newTestTransport(t, "node0", nil)
	// Should not panic and should do nothing observable.
	tr.notifyPeerIdentity("node1", freshPubKey(t))
}
