// Unit tests for Registry quorum semantics — P0-1 from the 2026-04-20
// Red/Scientist evidence report.
//
// Repro: Scientist scaled  from 3 → 2 replicas. Surviving nodes
// returned HTTP 503 because ArePeersReady() reported false (not all peers
// connected), even though 2 nodes were sufficient to form a 2-of-3 signing
// quorum. The fix added HasSigningQuorum(threshold) which is true when
// readyCount >= threshold+1 (CGGMP21/FROST signers-required count).
package transport

import (
	"sync/atomic"
	"testing"
)

// newTestRegistry constructs a Registry with the given node and peer IDs
// without wiring any transport/consensus plumbing. readyCount starts at 1
// (self).
func newTestRegistry(nodeID string, peerIDs []string) *Registry {
	r := &Registry{
		nodeID:      nodeID,
		peerNodeIDs: filterSelf(nodeID, peerIDs),
		readyMap:    make(map[string]bool),
		readyCount:  1, // self
	}
	return r
}

// markPeerReady simulates a peer-ready signal without invoking the
// transport layer. Mirrors what checkPeerConnections() does atomically.
func markPeerReady(r *Registry, peerID string) {
	r.readyMu.Lock()
	defer r.readyMu.Unlock()
	if !r.readyMap[peerID] {
		r.readyMap[peerID] = true
		atomic.AddInt64(&r.readyCount, 1)
	}
}

func markPeerDisconnected(r *Registry, peerID string) {
	r.readyMu.Lock()
	defer r.readyMu.Unlock()
	if r.readyMap[peerID] {
		r.readyMap[peerID] = false
		atomic.AddInt64(&r.readyCount, -1)
	}
}

// Test_HasSigningQuorum_3Node_2of3 — the Scientist repro.
// 3 nodes total, threshold=1 (i.e. 2-of-3: need 2 signers = threshold+1).
// Kill 1 peer → 2 ready (self + 1). Must still report quorum.
func Test_HasSigningQuorum_3Node_2of3(t *testing.T) {
	r := newTestRegistry("node0", []string{"node0", "node1", "node2"})
	threshold := 1 // "2-of-3" in CGGMP21 semantics (signers = threshold+1 = 2)

	// Bootstrap: only self ready.
	if r.HasSigningQuorum(threshold) {
		t.Fatal("alone: 1 peer ready, threshold=1, required=2 — expected no quorum")
	}

	// Peer 1 joins → 2 ready. Should form quorum.
	markPeerReady(r, "node1")
	if !r.HasSigningQuorum(threshold) {
		t.Fatalf("2 ready, threshold=1, required=2 — expected quorum, got none. readyCount=%d",
			r.GetReadyPeersCount())
	}

	// Peer 2 joins → 3 ready. Still quorum (no regression).
	markPeerReady(r, "node2")
	if !r.HasSigningQuorum(threshold) {
		t.Fatalf("3 ready, threshold=1 — expected quorum")
	}

	// Peer 2 disconnects → back to 2 ready. This is the Scientist repro:
	// survivors must still report quorum.
	markPeerDisconnected(r, "node2")
	if got := r.GetReadyPeersCount(); got != 2 {
		t.Fatalf("after peer disconnect expected readyCount=2, got %d", got)
	}
	if !r.HasSigningQuorum(threshold) {
		t.Fatal("REGRESSION (Scientist P0-1): 2 ready, threshold=1 — quorum lost on single peer loss")
	}

	// Peer 1 also disconnects → 1 ready. Now we genuinely have no quorum.
	markPeerDisconnected(r, "node1")
	if r.HasSigningQuorum(threshold) {
		t.Fatal("1 ready alone, threshold=1, required=2 — expected no quorum")
	}
}

// Test_HasSigningQuorum_5Node_3of5 — larger ensemble.
// 5 nodes, threshold=2 (3-of-5: signers = threshold+1 = 3).
func Test_HasSigningQuorum_5Node_3of5(t *testing.T) {
	r := newTestRegistry("node0", []string{"node0", "node1", "node2", "node3", "node4"})
	threshold := 2

	// 1 ready (self only) — no quorum.
	if r.HasSigningQuorum(threshold) {
		t.Fatal("1 ready alone — expected no quorum")
	}

	// 2 ready — still below required=3.
	markPeerReady(r, "node1")
	if r.HasSigningQuorum(threshold) {
		t.Fatal("2 ready — expected no quorum (required=3)")
	}

	// 3 ready — exactly at required. Quorum.
	markPeerReady(r, "node2")
	if !r.HasSigningQuorum(threshold) {
		t.Fatalf("3 ready, threshold=2, required=3 — expected quorum, got none. readyCount=%d",
			r.GetReadyPeersCount())
	}

	// 4 ready — above required. Quorum.
	markPeerReady(r, "node3")
	if !r.HasSigningQuorum(threshold) {
		t.Fatal("4 ready, threshold=2 — expected quorum")
	}

	// 5 ready — all ready. Quorum AND ArePeersReady would be true if transport set it.
	markPeerReady(r, "node4")
	if !r.HasSigningQuorum(threshold) {
		t.Fatal("5 ready, threshold=2 — expected quorum")
	}

	// Two simultaneous failures → 3 ready. Still quorum (no regression).
	markPeerDisconnected(r, "node3")
	markPeerDisconnected(r, "node4")
	if got := r.GetReadyPeersCount(); got != 3 {
		t.Fatalf("after 2 disconnects expected readyCount=3, got %d", got)
	}
	if !r.HasSigningQuorum(threshold) {
		t.Fatal("3 ready after 2 failures, threshold=2 — expected quorum")
	}

	// Third failure → 2 ready. Quorum lost (correctly).
	markPeerDisconnected(r, "node2")
	if r.HasSigningQuorum(threshold) {
		t.Fatal("2 ready, threshold=2, required=3 — expected NO quorum (f-1 tolerance exceeded)")
	}
}

// Test_HasSigningQuorum_ArePeersReady_Decoupled proves the two APIs do
// NOT gate each other. ArePeersReady remains strict (all peers required);
// HasSigningQuorum is the relaxed check used by /healthz.
func Test_HasSigningQuorum_ArePeersReady_Decoupled(t *testing.T) {
	r := newTestRegistry("node0", []string{"node0", "node1", "node2"})
	threshold := 1

	// Two peers ready, one missing. HasSigningQuorum=true, ArePeersReady=false.
	markPeerReady(r, "node1")

	if !r.HasSigningQuorum(threshold) {
		t.Fatal("expected quorum with 2 of 3 ready")
	}

	// ArePeersReady derives from r.ready which is set via checkPeerConnections;
	// we didn't call that, so it stays false. That's the point — these two
	// booleans are deliberately decoupled.
	if r.ArePeersReady() {
		t.Fatal("ArePeersReady must stay false when not all peers connected")
	}
}

// Test_HasSigningQuorum_BoundaryCheck covers the exact threshold arithmetic
// to pin the semantics: required = threshold + 1, NOT threshold.
func Test_HasSigningQuorum_BoundaryCheck(t *testing.T) {
	cases := []struct {
		name        string
		readyCount  int64
		threshold   int
		wantQuorum  bool
	}{
		{"threshold=0, ready=0 → no quorum (need >=1)", 0, 0, false},
		{"threshold=0, ready=1 → quorum (single-party sign)", 1, 0, true},
		{"threshold=1, ready=1 → no quorum (need >=2)", 1, 1, false},
		{"threshold=1, ready=2 → quorum", 2, 1, true},
		{"threshold=2, ready=2 → no quorum (need >=3)", 2, 2, false},
		{"threshold=2, ready=3 → quorum", 3, 2, true},
		{"threshold=2, ready=4 → quorum", 4, 2, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &Registry{
				readyCount: tc.readyCount,
				readyMap:   make(map[string]bool),
			}
			got := r.HasSigningQuorum(tc.threshold)
			if got != tc.wantQuorum {
				t.Fatalf("readyCount=%d threshold=%d → HasSigningQuorum=%v, want %v",
					tc.readyCount, tc.threshold, got, tc.wantQuorum)
			}
		})
	}
}
