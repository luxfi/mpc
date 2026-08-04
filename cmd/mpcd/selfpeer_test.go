package main

import "testing"

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
