package main

import "testing"

// TestKeygenDegreeForThreshold pins the security-critical off-by-one that keeps
// t-of-n keys honest. Before this mapping was wired, the CGGMP21 keygen degree
// defaulted to 0 (1-of-n: any single share signs) because nothing connected the
// --threshold flag to viper key "mpc_threshold".
func TestKeygenDegreeForThreshold(t *testing.T) {
	cases := []struct {
		name        string
		threshold   int // operator-facing --threshold = signers required (N in N-of-M)
		wantDegree  int // cmp.Keygen polynomial degree
		wantSigners int // degree+1 = parties needed to sign
	}{
		{"3-of-5", 3, 2, 3},
		{"2-of-3", 2, 1, 2},
		{"4-of-7", 4, 3, 4},
		{"single-signer-dev", 1, 0, 1},
		{"guard-zero", 0, 0, 0},
		{"guard-negative", -1, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := keygenDegreeForThreshold(tc.threshold)
			if got != tc.wantDegree {
				t.Fatalf("keygenDegreeForThreshold(%d) = %d, want %d", tc.threshold, got, tc.wantDegree)
			}
			// The whole point: degree 0 is 1-of-n. Anything the operator asked
			// to be >=2-of-n MUST produce degree >= 1.
			if tc.threshold >= 2 && got < 1 {
				t.Fatalf("threshold=%d produced degree %d (1-of-n) — threshold security lost", tc.threshold, got)
			}
			if tc.threshold >= 1 {
				if signers := got + 1; signers != tc.wantSigners {
					t.Fatalf("threshold=%d: signers=%d, want %d", tc.threshold, signers, tc.wantSigners)
				}
			}
		})
	}
}

// TestConfiguredParticipants pins the OTHER half of an honest threshold claim:
// who the parties are. A caller can only verify it got the t-of-n it asked for
// if keygen reports both t and n, and n must be the CONFIGURED set — not
// whoever happens to be ready, which changes when a pod restarts.
//
// This closes a real hole: mpcd's KeygenResult carried neither field, so
// luxfi/kms stored Threshold:0 Parties:0 for every validator key set while its
// caller had requested 3-of-5 and passed validation.
func TestConfiguredParticipants(t *testing.T) {
	cases := []struct {
		name    string
		nodeID  string
		peerIDs []string
		want    []string
	}{
		{"three-node ring", "node0", []string{"node1", "node2"}, []string{"node0", "node1", "node2"}},
		{"unsorted input is normalized", "node1", []string{"node2", "node0"}, []string{"node0", "node1", "node2"}},
		{"five-node ring", "node4", []string{"node0", "node1", "node2", "node3"},
			[]string{"node0", "node1", "node2", "node3", "node4"}},
		{"solo node still reports itself", "node0", nil, []string{"node0"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &ConsensusPeerRegistry{nodeID: tc.nodeID, peerIDs: tc.peerIDs}
			got := r.ConfiguredParticipants()
			if len(got) != len(tc.want) {
				t.Fatalf("ConfiguredParticipants() = %v (len %d), want %v (len %d)",
					got, len(got), tc.want, len(tc.want))
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("ConfiguredParticipants() = %v, want %v", got, tc.want)
				}
			}
			// Every node in a ring must report the SAME list for the same key,
			// so the order cannot depend on which node you asked.
			other := (&ConsensusPeerRegistry{nodeID: tc.nodeID, peerIDs: tc.peerIDs}).ConfiguredParticipants()
			for i := range other {
				if other[i] != got[i] {
					t.Fatalf("non-deterministic participant order: %v vs %v", got, other)
				}
			}
		})
	}
}

// TestConfiguredParticipantsDoesNotAliasPeerIDs guards a subtle aliasing bug:
// appending self must not write into the caller's peerIDs backing array.
func TestConfiguredParticipantsDoesNotAliasPeerIDs(t *testing.T) {
	peers := make([]string, 2, 8) // spare capacity => append would scribble in place
	peers[0], peers[1] = "node1", "node2"
	r := &ConsensusPeerRegistry{nodeID: "node0", peerIDs: peers}

	_ = r.ConfiguredParticipants()

	if len(peers) != 2 || peers[0] != "node1" || peers[1] != "node2" {
		t.Fatalf("ConfiguredParticipants mutated peerIDs: %v", peers)
	}
}
