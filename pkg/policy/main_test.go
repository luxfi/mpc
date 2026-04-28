// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause
//
// TestMain opts the policy-package tests that touch
// luxfi/threshold/protocols/tfhe (RealThresholdDecryptor wires its
// PartialDecrypter / ShareAggregator) into the placeholder UNSAFE primitive
// by setting LUX_ALLOW_FAKE_TFHE_FOR_TESTING_ONLY=1 for the duration of the
// test binary. Production paths in luxfi/threshold/protocols/tfhe are
// guarded by guardUnsafe() and panic when this env var is unset (by design).
//
// These tests verify dispatcher fan-out and aggregator wiring shape only —
// they do NOT verify any threshold security property because the
// underlying scheme has none. Real-threshold wiring (luxfi/lattice
// Shamir/LWE) is tracked as a separate multi-week task per
// lps/LP-137-TFHE-REAL-THRESHOLD-SPEC.md §2.6.

package policy

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	if err := os.Setenv("LUX_ALLOW_FAKE_TFHE_FOR_TESTING_ONLY", "1"); err != nil {
		panic("policy test setup: cannot set LUX_ALLOW_FAKE_TFHE_FOR_TESTING_ONLY: " + err.Error())
	}
	os.Exit(m.Run())
}
