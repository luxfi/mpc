// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package main

import (
	"fmt"
	"strings"

	"github.com/urfave/cli/v3"
)

// buildHSMSignerConfig assembles the per-provider configuration map that
// hsm.NewSigner consumes. The luxfi/hsm factory reads each provider's
// config keys from the supplied map first, then falls back to its
// documented MPC_HSM_<PROVIDER>_* environment variables. The job of this
// helper is therefore narrow:
//
//  1. Reject unknown provider names early — a typo at startup is much
//     cheaper to surface here than as a "no signer wired" failure when
//     the first co-signing intent arrives.
//  2. Promote the operator-facing CLI flags (--hsm-signer-key-id) into
//     the canonical config keys for the providers that consume a single
//     opaque key reference (cloud KMS).
//  3. Leave the remaining provider-specific knobs (slot/pin/library for
//     PKCS#11, work-dir for airgap wallets, vault URL for Azure) to the
//     factory's environment-variable fallback. We do NOT mint new CLI
//     flags for every provider's tuning surface — there is one and only
//     one place those values live, the documented MPC_HSM_<P>_* names.
//
// The returned map is always non-nil so the factory cannot observe an
// ambiguous "provider configured but no overrides" state.
func buildHSMSignerConfig(c *cli.Command, provider string) (map[string]string, error) {
	provider = strings.TrimSpace(strings.ToLower(provider))
	if provider == "" {
		return nil, fmt.Errorf("hsm signer: provider not specified")
	}
	if !isSupportedHSMSignerProvider(provider) {
		return nil, fmt.Errorf("hsm signer: unsupported provider %q (supported: %s)",
			provider, strings.Join(supportedHSMSignerProviders(), ", "))
	}

	cfg := map[string]string{}
	keyID := strings.TrimSpace(c.String("hsm-signer-key-id"))

	switch provider {
	case "aws":
		// AWS KMS signer reads region from config or AWS_REGION; the key
		// ARN is identified at sign-time via the operator-supplied
		// hsm-signer-key-id. We pass it through under the canonical key
		// name AWSKMSSigner consults.
		if keyID != "" {
			cfg["key_id"] = keyID
		}
	case "gcp":
		// GCP KMS signer derives project/location/keyring/key from env
		// (GCP_PROJECT_ID, GCP_KMS_LOCATION, GCP_KMS_KEYRING, GCP_KMS_KEY).
		// hsm-signer-key-id, when supplied, becomes the crypto key name
		// override.
		if keyID != "" {
			cfg["crypto_key"] = keyID
		}
	case "azure":
		// Azure Key Vault signer reads vault_url from env (AZURE_VAULT_URL).
		// hsm-signer-key-id maps to the key name within the vault.
		if keyID != "" {
			cfg["key_name"] = keyID
		}
	case "zymbit", "yubihsm", "yubico", "yubi", "nitrokey",
		"coldcard", "foundation", "keystone", "ngrave",
		"gridplus", "lattice", "ledger", "trezor",
		"pkcs11", "kmip", "tr31",
		"mldsa", "pq", "post-quantum",
		"local":
		// Each of these providers reads its full configuration surface
		// from the documented MPC_HSM_<PROVIDER>_* environment variables.
		// The factory handles env fallback per key, so we deliberately
		// do not duplicate that surface as CLI flags. Operators wire
		// vendor-specific knobs (slots, pins, library paths, vault URLs,
		// transport implementations) through env vars provisioned out of
		// band, typically via KMS-synced secrets.
	default:
		// isSupportedHSMSignerProvider guards this path; this is dead
		// code retained as a defensive switch fall-through so the
		// compiler proves exhaustiveness when the provider list grows.
		return nil, fmt.Errorf("hsm signer: provider %q passed validation but has no config branch", provider)
	}

	return cfg, nil
}

// supportedHSMSignerProviders lists the canonical signer provider names
// accepted by luxfi/hsm.NewSigner. Kept in lockstep with that factory's
// switch — adding an entry here without a matching factory case is a
// configuration lie.
func supportedHSMSignerProviders() []string {
	return []string{
		"aws", "gcp", "azure",
		"zymbit",
		"yubihsm", "nitrokey",
		"pkcs11", "kmip",
		"coldcard", "foundation", "keystone", "ngrave",
		"gridplus", "ledger", "trezor",
		"tr31", "mldsa",
		"local",
	}
}

// isSupportedHSMSignerProvider returns true when the given provider name
// (already lower-cased + trimmed) is one luxfi/hsm.NewSigner will accept.
// Aliases honored by the factory (yubico/yubi for yubihsm, lattice for
// gridplus, pq/post-quantum for mldsa) are accepted here so the surface
// stays consistent between the helper and the factory.
func isSupportedHSMSignerProvider(provider string) bool {
	switch provider {
	case "aws", "gcp", "azure",
		"zymbit",
		"yubihsm", "yubico", "yubi",
		"nitrokey",
		"pkcs11", "kmip",
		"coldcard", "foundation", "keystone", "ngrave",
		"gridplus", "lattice",
		"ledger", "trezor",
		"tr31",
		"mldsa", "pq", "post-quantum",
		"local":
		return true
	}
	return false
}
