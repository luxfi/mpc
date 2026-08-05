package main

import (
	"strings"
	"testing"
)

// The k8s deployment shape: ONE StatefulSet command for every replica, so each
// node is handed the WHOLE ensemble — including itself. Self must be dropped
// from the peer set or it is counted twice (as nodeID and as a synthetic
// peer-N), and the all-ready equality that gates keygen can never be satisfied.
// Measured on hanzo-mpc before this fix: ready=5, expected=4, forever.
func TestIsSelfAddr(t *testing.T) {
	const (
		nodeID = "mpc-node-0"
		listen = ":9999"
	)
	cases := []struct {
		name string
		addr string
		want bool
	}{
		{"the pod's own headless address", "mpc-node-0.mpc-node-headless.hanzo-mpc.svc.cluster.local:9999", true},
		{"identical to --listen", ":9999", true},
		{"a real peer", "mpc-node-1.mpc-node-headless.hanzo-mpc.svc.cluster.local:9999", false},
		{"a real peer, other index", "mpc-node-2.mpc-node-headless.hanzo-mpc.svc.cluster.local:9999", false},
		// The label is compared WHOLE. A prefix test would swallow node 10 into
		// node 1's identity and silently shrink a ten-node ensemble.
		{"mpc-node-10 is not mpc-node-1", "mpc-node-10.mpc-node-headless.svc:9999", false},
		{"bare host, self", "mpc-node-0:9999", true},
		{"bare host, peer", "mpc-node-1:9999", false},
		{"no port, self", "mpc-node-0.mpc-node-headless.svc", true},
		{"empty is never self", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isSelfAddr(tc.addr, nodeID, listen); got != tc.want {
				t.Fatalf("isSelfAddr(%q, %q, %q) = %v, want %v", tc.addr, nodeID, listen, got, tc.want)
			}
		})
	}
}

// A node id that is empty (identity not yet resolved) must never make every
// address look like self — that would drop the whole ensemble and leave a node
// alone with a quorum of one.
func TestIsSelfAddrEmptyNodeIDMatchesNothing(t *testing.T) {
	for _, addr := range []string{
		"mpc-node-1.mpc-node-headless.svc:9999",
		":9999",
		"host:1",
	} {
		if isSelfAddr(addr, "", "") {
			t.Fatalf("isSelfAddr(%q, \"\", \"\") = true, want false", addr)
		}
	}
}

// TestPeerIDFromAddr — every party must agree on the NAME of every other party,
// because the keygen handler admits a message only from an id in its own party
// set. A positional id cannot match a real node id, so unprefixed --peer flags
// built three disagreeing sets and every round-2 message was refused.
func TestPeerIDFromAddr(t *testing.T) {
	for _, tc := range []struct {
		name, addr, want string
		index            int
	}{
		{"statefulset fqdn", "mpc-node-2.mpc-node-headless.hanzo-mpc.svc.cluster.local:9999", "mpc-node-2", 2},
		{"short host", "mpc-node-0:9999", "mpc-node-0", 0},
		{"no port", "mpc-node-1.mpc-node-headless.hanzo-mpc.svc.cluster.local", "mpc-node-1", 1},
		// A bare IP carries no name, so the positional id remains and the caller
		// must use nodeID@host:port to say who it is.
		{"bare ipv4 keeps positional", "10.0.0.5:9999", "peer-3", 3},
		{"bare ipv6 keeps positional", "[fd00::1]:9999", "peer-4", 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := peerIDFromAddr(tc.addr, tc.index); got != tc.want {
				t.Fatalf("peerIDFromAddr(%q, %d) = %q, want %q", tc.addr, tc.index, got, tc.want)
			}
		})
	}
}

// TestPeerIDMatchesSelfRecognition is the invariant that was violated in
// production: the id a node derives for a peer must equal the id that peer uses
// for ITSELF. isSelfAddr reads the first DNS label to recognise self, so
// peerIDFromAddr must read it the same way or the two disagree.
func TestPeerIDMatchesSelfRecognition(t *testing.T) {
	fleet := []string{
		"mpc-node-0.mpc-node-headless.hanzo-mpc.svc.cluster.local:9999",
		"mpc-node-1.mpc-node-headless.hanzo-mpc.svc.cluster.local:9999",
		"mpc-node-2.mpc-node-headless.hanzo-mpc.svc.cluster.local:9999",
	}
	for _, self := range []string{"mpc-node-0", "mpc-node-1", "mpc-node-2"} {
		for i, addr := range fleet {
			id := peerIDFromAddr(addr, i)
			if isSelfAddr(addr, self, ":9999") {
				if id != self {
					t.Fatalf("%s: recognises %q as self but would name it %q", self, addr, id)
				}
				continue
			}
			if id == self {
				t.Fatalf("%s: named a PEER with its own id (%q)", self, id)
			}
			if strings.HasPrefix(id, "peer-") {
				t.Fatalf("%s: peer %q got positional id %q — no other node answers to that name", self, addr, id)
			}
		}
	}
}
