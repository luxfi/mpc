// SPDX-License-Identifier: BSD-3-Clause
package main

import (
	"errors"
	"testing"

	"github.com/luxfi/threshold/pkg/thresholdd"
)

func TestChainProfileFromString(t *testing.T) {
	cases := []struct {
		in      string
		want    thresholdd.Profile
		wantErr bool
	}{
		{"", thresholdd.ProfileStrictPQ, false},          // unset → fail-secure default
		{"strict-pq", thresholdd.ProfileStrictPQ, false}, //
		{"STRICT-PQ", thresholdd.ProfileStrictPQ, false}, // case-insensitive
		{" strict ", thresholdd.ProfileStrictPQ, false},  // trimmed alias
		{"pq", thresholdd.ProfileStrictPQ, false},        // alias
		{"fips", thresholdd.ProfileStrictPQ, false},      // FIPS is IsPQ → strict
		{"legacy-compat", thresholdd.ProfileLegacyCompat, false},
		{"legacy", thresholdd.ProfileLegacyCompat, false},
		{"permissive", thresholdd.ProfileLegacyCompat, false},
		{"unknown", thresholdd.ProfileUnknown, false},
		{"open", thresholdd.ProfileUnknown, false},
		{"garbage", thresholdd.ProfileUnknown, true},
	}
	for _, tc := range cases {
		got, err := chainProfileFromString(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("chainProfileFromString(%q): want error, got nil", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("chainProfileFromString(%q): unexpected error %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("chainProfileFromString(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestSplitCSV(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"  ", nil},
		{"96369", []string{"96369"}},
		{"96369,96368", []string{"96369", "96368"}},
		{" 96369 , 96368 ", []string{"96369", "96368"}},
		{"96369 96368", []string{"96369", "96368"}},
		{",,96369,,", []string{"96369"}},
	}
	for _, tc := range cases {
		got := splitCSV(tc.in)
		if len(got) != len(tc.want) {
			t.Fatalf("splitCSV(%q) = %v, want %v", tc.in, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("splitCSV(%q)[%d] = %q, want %q", tc.in, i, got[i], tc.want[i])
			}
		}
	}
}

// TestStrictPQGate_FailClosed drives the real threshold gate
// (thresholdd.RefuseUnderStrictPQ) with the resolver mpcd wires, proving
// the M-2 fix: a strict-PQ node refuses the dealer shortcut for every
// non-empty chainID it does not explicitly allow-list.
func TestStrictPQGate_FailClosed(t *testing.T) {
	def, err := chainProfileFromString("strict-pq")
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	resolver := buildChainProfileResolver(def, []string{"96369"}) // 96369 = legacy allow-listed

	// 1. nil resolver (pre-fix wiring) → gate fails OPEN. This is the M-2
	//    hole the wiring closes; asserted here so a regression that drops
	//    the SetChainProfileResolver call is caught by the contrast below.
	if err := thresholdd.RefuseUnderStrictPQ("99999", "pulsar.sign_ctx", nil); err != nil {
		t.Fatalf("nil-resolver gate must pass (documented fail-open), got %v", err)
	}

	// 2. unknown non-empty chain on a strict-PQ node → REFUSED (fail-closed).
	if err := thresholdd.RefuseUnderStrictPQ("99999", "pulsar.sign_ctx", resolver); err == nil {
		t.Error("strict-PQ node must REFUSE sign_ctx for unknown chain 99999, gate passed")
	} else if !errors.Is(err, thresholdd.ErrRefusedUnderStrictPQ) {
		t.Errorf("want ErrRefusedUnderStrictPQ, got %v", err)
	}

	// 3. explicitly allow-listed legacy chain → PASS (operator opt-out honoured).
	if err := thresholdd.RefuseUnderStrictPQ("96369", "pulsar.sign_ctx", resolver); err != nil {
		t.Errorf("allow-listed legacy chain 96369 must pass, got %v", err)
	}

	// 4. The resolver itself is fail-closed for the EMPTY chainID: once the
	//    threshold gate routes "" through the resolver (the reported one-line
	//    change) the context-less sign_ctx is refused. Proven at the resolver
	//    boundary because RefuseUnderStrictPQ today still short-circuits ""
	//    to PASS before consulting the resolver (threshold-owned residual).
	if got := resolver.ResolveChainProfile(""); got != thresholdd.ProfileStrictPQ {
		t.Errorf("resolver must map empty chainID → ProfileStrictPQ (fail-closed), got %v", got)
	}
	if got := resolver.ResolveChainProfile("unmapped"); got != thresholdd.ProfileStrictPQ {
		t.Errorf("resolver must map unknown chainID → ProfileStrictPQ (fail-closed), got %v", got)
	}
}

// TestStrictPQGate_LegacyDefaultPermissive proves a deliberately
// downgraded node (legacy-compat default) lets ctx-bound signing through
// — the documented dev / non-PQ posture, opt-in only.
func TestStrictPQGate_LegacyDefaultPermissive(t *testing.T) {
	def, err := chainProfileFromString("legacy-compat")
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	resolver := buildChainProfileResolver(def, nil)
	if err := thresholdd.RefuseUnderStrictPQ("99999", "magnetar.sign_ctx", resolver); err != nil {
		t.Errorf("legacy-compat node must pass sign_ctx, got %v", err)
	}
	if got := resolver.ResolveChainProfile(""); got != thresholdd.ProfileLegacyCompat {
		t.Errorf("legacy default must map empty chainID → ProfileLegacyCompat, got %v", got)
	}
}
