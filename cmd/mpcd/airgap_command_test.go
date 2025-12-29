// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package main

import (
	"testing"

	"github.com/luxfi/hsm"
)

// TestAirgapProvidersRoundTripFactory enforces the contract documented
// on airgapProviders(): every reserved provider name MUST be a known
// factory case in luxfi/hsm. We supply each constructor's required
// fields so we exercise the dispatch table and the per-signer
// validators — the goal is to catch missing factory cases or rename
// drift, not to validate operational config.
func TestAirgapProvidersRoundTripFactory(t *testing.T) {
	t.Parallel()

	cases := map[string]map[string]string{
		"coldcard":   {"device_id": "test"},
		"foundation": {"device_id": "test"},
		"keystone":   {"device_id": "test", "ur_type": "eth-sign-request"},
		"ngrave":     {"device_id": "test", "ur_type": "eth-sign-request"},
	}

	for _, p := range airgapProviders() {
		cfg, ok := cases[p]
		if !ok {
			t.Fatalf("airgap_command_test: missing test config for provider %q — extend cases", p)
		}
		signer, err := hsm.NewSigner(p, cfg)
		if err != nil {
			t.Fatalf("hsm.NewSigner(%q): %v", p, err)
		}
		if signer == nil {
			t.Fatalf("hsm.NewSigner(%q): nil signer with no error", p)
		}
		if got := signer.Provider(); got != p {
			t.Fatalf("hsm.NewSigner(%q).Provider() = %q", p, got)
		}
	}
}
