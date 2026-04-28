// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package main

import (
	"context"
	"testing"

	"github.com/urfave/cli/v3"
)

// newCmdWithFlags builds an *cli.Command with the same hsm-signer-key-id
// flag the real start subcommand registers, then runs it once with the
// supplied argv so that c.String("hsm-signer-key-id") returns the value
// the test wired in. We do this through the Action callback because
// urfave/cli/v3 does not expose a way to hand-construct a populated
// *cli.Command outside of an invocation.
func newCmdWithFlags(t *testing.T, keyID string) *cli.Command {
	t.Helper()
	var captured *cli.Command
	cmd := &cli.Command{
		Name: "test",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "hsm-signer-key-id"},
		},
		Action: func(_ context.Context, c *cli.Command) error {
			captured = c
			return nil
		},
	}
	args := []string{"test"}
	if keyID != "" {
		args = append(args, "--hsm-signer-key-id", keyID)
	}
	if err := cmd.Run(context.Background(), args); err != nil {
		t.Fatalf("cli run: %v", err)
	}
	if captured == nil {
		t.Fatalf("cli action did not fire")
	}
	return captured
}

func TestBuildHSMSignerConfig_AWSPromotesKeyID(t *testing.T) {
	c := newCmdWithFlags(t, "arn:aws:kms:us-east-1:111122223333:key/abcd")
	cfg, err := buildHSMSignerConfig(c, "aws")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := cfg["key_id"]; got != "arn:aws:kms:us-east-1:111122223333:key/abcd" {
		t.Fatalf("aws key_id = %q", got)
	}
}

func TestBuildHSMSignerConfig_GCPPromotesKeyID(t *testing.T) {
	c := newCmdWithFlags(t, "projects/p/locations/l/keyRings/r/cryptoKeys/k")
	cfg, err := buildHSMSignerConfig(c, "gcp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := cfg["crypto_key"]; got != "projects/p/locations/l/keyRings/r/cryptoKeys/k" {
		t.Fatalf("gcp crypto_key = %q", got)
	}
}

func TestBuildHSMSignerConfig_AzurePromotesKeyID(t *testing.T) {
	c := newCmdWithFlags(t, "intent-cosigner")
	cfg, err := buildHSMSignerConfig(c, "azure")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := cfg["key_name"]; got != "intent-cosigner" {
		t.Fatalf("azure key_name = %q", got)
	}
}

func TestBuildHSMSignerConfig_HardwareWalletReturnsEmptyMap(t *testing.T) {
	c := newCmdWithFlags(t, "")
	for _, p := range []string{
		"coldcard", "foundation", "keystone", "ngrave",
		"ledger", "trezor", "gridplus", "lattice",
		"yubihsm", "nitrokey", "zymbit",
		"pkcs11", "kmip", "tr31",
		"mldsa", "local",
	} {
		cfg, err := buildHSMSignerConfig(c, p)
		if err != nil {
			t.Fatalf("provider %s: %v", p, err)
		}
		if cfg == nil {
			t.Fatalf("provider %s: nil cfg", p)
		}
		if len(cfg) != 0 {
			t.Fatalf("provider %s: expected empty cfg, got %v", p, cfg)
		}
	}
}

func TestBuildHSMSignerConfig_EmptyProviderRejected(t *testing.T) {
	c := newCmdWithFlags(t, "")
	if _, err := buildHSMSignerConfig(c, ""); err == nil {
		t.Fatalf("expected error for empty provider")
	}
}

func TestBuildHSMSignerConfig_UnknownProviderRejected(t *testing.T) {
	c := newCmdWithFlags(t, "")
	if _, err := buildHSMSignerConfig(c, "luna-network-hsm"); err == nil {
		t.Fatalf("expected error for unknown provider")
	}
}

func TestBuildHSMSignerConfig_ProviderCaseInsensitive(t *testing.T) {
	c := newCmdWithFlags(t, "key-1")
	cfg, err := buildHSMSignerConfig(c, "  AWS ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := cfg["key_id"]; got != "key-1" {
		t.Fatalf("aws key_id = %q", got)
	}
}

func TestSupportedHSMSignerProviders_NonEmpty(t *testing.T) {
	if len(supportedHSMSignerProviders()) == 0 {
		t.Fatalf("supportedHSMSignerProviders returned empty list")
	}
}

func TestIsSupportedHSMSignerProvider_AcceptsAliases(t *testing.T) {
	for _, alias := range []string{"yubico", "yubi", "lattice", "pq", "post-quantum"} {
		if !isSupportedHSMSignerProvider(alias) {
			t.Fatalf("alias %q rejected", alias)
		}
	}
}
