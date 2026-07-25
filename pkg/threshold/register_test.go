// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package threshold

import (
	"testing"

	cryptothreshold "github.com/luxfi/crypto/threshold"
)

// TestImportDoesNotRegister pins the security-relevant invariant that merely
// importing this package must NOT mutate the process-global crypto/threshold
// registry.
//
// These adapters keep the secret nonce scalar k inside NonceState (k||R). If an
// init() silently bound them to SchemeCMP/SchemeFROST, unrelated code calling
// cryptothreshold.GetScheme(SchemeCMP) would transparently receive a signer with
// that property, and a NonceState serialized across a party boundary leaks the
// private key: x = (s*k - H(m))/r.
//
// A second, blunter hazard: RegisterScheme panics on a duplicate ID
// (crypto@v1.20.2 threshold/registry.go:24-26), so an ambient init() would kill
// the process at startup the day crypto/threshold ships its own CMP/FROST.
//
// If someone re-adds `func init() { RegisterScheme(...) }`, this test fails.
func TestImportDoesNotRegister(t *testing.T) {
	for _, id := range []cryptothreshold.SchemeID{
		cryptothreshold.SchemeCMP,
		cryptothreshold.SchemeFROST,
	} {
		if _, err := cryptothreshold.GetScheme(id); err == nil {
			t.Fatalf("scheme %v is registered merely by importing pkg/threshold; "+
				"registration must stay explicit via Register() — see crypto_adapter.go", id)
		}
	}
}

// TestRegisterIsExplicit proves Register() still does its job when a caller
// deliberately opts in. It runs after TestImportDoesNotRegister (Go executes
// tests in source order within a file, and this is the only caller of
// Register() in the package), so it is also what makes the ordering explicit
// rather than incidental.
func TestRegisterIsExplicit(t *testing.T) {
	Register()

	for _, tc := range []struct {
		id   cryptothreshold.SchemeID
		want string
	}{
		{cryptothreshold.SchemeCMP, "CMP"},
		{cryptothreshold.SchemeFROST, "FROST"},
	} {
		scheme, err := cryptothreshold.GetScheme(tc.id)
		if err != nil {
			t.Fatalf("after Register(), GetScheme(%v) failed: %v", tc.id, err)
		}
		if got := scheme.ID(); got != tc.id {
			t.Fatalf("GetScheme(%v) returned a scheme reporting ID %v", tc.id, got)
		}
	}
}
