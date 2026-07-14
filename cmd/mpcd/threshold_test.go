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
