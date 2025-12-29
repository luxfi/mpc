// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/urfave/cli/v3"
)

// airgapCommand returns the `mpcd airgap` subcommand tree, the operator
// surface for working with airgapped hardware wallets (Coldcard,
// Foundation Passport, Keystone Pro, NGRAVE Zero).
//
// The signing ceremony is file-mediated by design: Coldcard's canonical
// product flow uses microSD, Foundation Passport uses BBQr-encoded QR,
// and Keystone/NGRAVE use UR-encoded animated QR — all of which surface
// as challenge bytes the host writes to disk for the operator to ferry
// to the offline device. The response file is signed bytes the operator
// drops back into the same directory. mpcd owns the ceremony I/O; the
// per-vendor envelope semantics (PSBT vs UR vs BBQr) are owned by the
// luxfi/hsm Signer, which is constructible since v1.1.3 via NewSigner.
//
// The subcommands here are intentionally narrow:
//
//	mpcd airgap devices                — list reserved provider names
//	mpcd airgap fips-check <provider>  — verify FIPS validation status
//	mpcd airgap sign --provider X ...  — drive a file-mediated ceremony
//
// Real key material never leaves the offline device. The host only sees
// challenge/response bytes.
func airgapCommand() *cli.Command {
	return &cli.Command{
		Name:  "airgap",
		Usage: "Operator workflows for airgapped hardware wallet signers",
		Commands: []*cli.Command{
			airgapDevicesCommand(),
			airgapFIPSCheckCommand(),
			airgapSignCommand(),
		},
	}
}

// airgapProviders is the canonical set of airgap-capable provider names
// reserved by luxfi/hsm. Adding entries here is a contract change —
// every name MUST round-trip through hsm.NewSigner. Coverage lives in
// airgap_command_test.go so the dispatch table is exercised by `go test`
// rather than crashing the daemon at boot when an operator probes with
// an unconfigured provider.
func airgapProviders() []string {
	return []string{"coldcard", "foundation", "keystone", "ngrave"}
}

func isAirgapProvider(p string) bool {
	for _, candidate := range airgapProviders() {
		if candidate == p {
			return true
		}
	}
	return false
}

func airgapDevicesCommand() *cli.Command {
	return &cli.Command{
		Name:  "devices",
		Usage: "List supported airgapped wallet providers",
		Action: func(_ context.Context, _ *cli.Command) error {
			for _, p := range airgapProviders() {
				fmt.Println(p)
			}
			return nil
		},
	}
}

// airgapFIPSCheckCommand surfaces the documented luxfi/hsm FIPS policy.
// Personal hardware wallets (the airgap set, plus ledger/trezor/gridplus)
// are NEVER FIPS 140 validated — operators preparing a FIPS-restricted
// deployment must select a different provider. We fail closed so
// misconfiguration shows up at provisioning, not on the first signature.
func airgapFIPSCheckCommand() *cli.Command {
	return &cli.Command{
		Name:      "fips-check",
		Usage:     "Verify a signer provider is FIPS 140 validated",
		ArgsUsage: "<provider>",
		Action: func(_ context.Context, c *cli.Command) error {
			if c.NArg() != 1 {
				return errors.New("airgap fips-check: exactly one provider name required")
			}
			provider := strings.ToLower(strings.TrimSpace(c.Args().Get(0)))
			validated := map[string]string{
				"aws":      "AWS KMS / CloudHSM, CMVP cert #4523 / #3380",
				"gcp":      "Google Cloud HSM (Marvell LiquidSecurity), CMVP cert #4399",
				"azure":    "Azure Key Vault Premium / Managed HSM, CMVP cert #4399 / #4153",
				"yubihsm":  "YubiHSM 2 (FIPS firmware), CMVP cert #4148",
				"pkcs11":   "validation depends on configured vendor library — verify CMVP listing",
				"kmip":     "validation depends on configured KMS server — verify CMVP listing",
			}
			if cert, ok := validated[provider]; ok {
				fmt.Printf("OK: %s — %s\n", provider, cert)
				return nil
			}
			rejected := map[string]string{
				"local":      "in-memory ECDSA, dev only",
				"mldsa":      "ML-DSA / FIPS 204 module validation in progress (not yet on CMVP active list)",
				"tr31":       "key-block adapter — backing KBPK must come from a FIPS provider",
				"nitrokey":   "Nitrokey HSM 2 holds CC EAL4+ but is not FIPS 140 validated",
				"zymbit":     "Zymbit SCM is not FIPS 140 validated",
				"coldcard":   "personal hardware wallet, not FIPS 140 validated",
				"foundation": "personal hardware wallet, not FIPS 140 validated",
				"keystone":   "personal hardware wallet, not FIPS 140 validated",
				"ngrave":     "personal hardware wallet, not FIPS 140 validated",
				"ledger":     "personal hardware wallet, not FIPS 140 validated",
				"trezor":     "personal hardware wallet, not FIPS 140 validated",
				"gridplus":   "personal hardware wallet, not FIPS 140 validated",
				"lattice":    "personal hardware wallet, not FIPS 140 validated",
			}
			if reason, ok := rejected[provider]; ok {
				return fmt.Errorf("%s is not FIPS 140 validated: %s", provider, reason)
			}
			return fmt.Errorf("unknown provider %q", provider)
		},
	}
}

// airgapSignCommand orchestrates a file-mediated signing ceremony. The
// challenge bytes (PSBT for Coldcard/Foundation, UR-encoded CBOR for
// Keystone/NGRAVE, or raw payload for generic flows) are written to
// <work-dir>/<session>.req. The operator carries the file to the offline
// device, signs, and drops the response at <work-dir>/<session>.resp.
// We poll for the response file until --timeout or context cancellation.
//
// On success the response bytes are written to --signature-out (or hex
// to stdout if unspecified). The work directory is cleaned of the
// session's req/resp pair on exit.
func airgapSignCommand() *cli.Command {
	return &cli.Command{
		Name:  "sign",
		Usage: "Drive a file-mediated signing ceremony with an airgapped wallet",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "provider",
				Usage:    "Airgapped provider: coldcard|foundation|keystone|ngrave",
				Required: true,
				Sources:  cli.EnvVars("MPC_HSM_SIGNER"),
			},
			&cli.StringFlag{
				Name:    "device-id",
				Usage:   "Operator-facing device identifier (routes concurrent ceremonies)",
				Sources: cli.EnvVars("MPC_HSM_AIRGAP_DEVICE_ID"),
			},
			&cli.StringFlag{
				Name:     "challenge-file",
				Usage:    "Path to the challenge payload to sign (PSBT/UR/raw)",
				Required: true,
			},
			&cli.StringFlag{
				Name:  "work-dir",
				Usage: "Directory used to ferry challenge/response files",
				Value: filepath.Join(os.TempDir(), "mpcd-airgap"),
			},
			&cli.StringFlag{
				Name:  "format",
				Usage: "Wire format hint: psbt|bbqr|ur|json (advisory only)",
			},
			&cli.StringFlag{
				Name:  "signature-out",
				Usage: "Path to write the resulting signature (default: stdout, hex)",
			},
			&cli.DurationFlag{
				Name:  "timeout",
				Usage: "Maximum time to wait for the operator to return the signed response",
				Value: 30 * time.Minute,
			},
		},
		Action: runAirgapSign,
	}
}

func runAirgapSign(ctx context.Context, c *cli.Command) error {
	provider := strings.ToLower(strings.TrimSpace(c.String("provider")))
	if !isAirgapProvider(provider) {
		return fmt.Errorf("airgap sign: provider %q is not airgapped (use one of %v)",
			provider, airgapProviders())
	}

	challengeBytes, err := os.ReadFile(c.String("challenge-file"))
	if err != nil {
		return fmt.Errorf("airgap sign: read challenge: %w", err)
	}
	if len(challengeBytes) == 0 {
		return errors.New("airgap sign: challenge file is empty")
	}

	workDir := c.String("work-dir")
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return fmt.Errorf("airgap sign: create work dir: %w", err)
	}

	sessionID, err := newAirgapSessionID()
	if err != nil {
		return fmt.Errorf("airgap sign: %w", err)
	}

	reqPath := filepath.Join(workDir, sessionID+".req")
	respPath := filepath.Join(workDir, sessionID+".resp")
	metaPath := reqPath + ".meta"

	if err := os.WriteFile(reqPath, challengeBytes, 0o600); err != nil {
		return fmt.Errorf("airgap sign: write challenge: %w", err)
	}
	defer func() {
		_ = os.Remove(reqPath)
		_ = os.Remove(metaPath)
		_ = os.Remove(respPath)
	}()

	meta := fmt.Sprintf("session=%s\nprovider=%s\ndevice=%s\nformat=%s\nbytes=%d\n",
		sessionID, provider, c.String("device-id"), c.String("format"), len(challengeBytes))
	if err := os.WriteFile(metaPath, []byte(meta), 0o600); err != nil {
		return fmt.Errorf("airgap sign: write metadata: %w", err)
	}

	fmt.Fprintf(os.Stderr,
		"airgap: challenge written to %s\nairgap: drop signed response at %s\nairgap: timeout %s\n",
		reqPath, respPath, c.Duration("timeout"))

	signCtx, cancel := context.WithTimeout(ctx, c.Duration("timeout"))
	defer cancel()

	signature, err := awaitAirgapResponse(signCtx, respPath)
	if err != nil {
		return fmt.Errorf("airgap sign: ceremony failed: %w", err)
	}

	if out := c.String("signature-out"); out != "" {
		if err := os.WriteFile(out, signature, 0o600); err != nil {
			return fmt.Errorf("airgap sign: write signature: %w", err)
		}
		fmt.Printf("Signature written to %s (%d bytes)\n", out, len(signature))
		return nil
	}
	fmt.Println(hex.EncodeToString(signature))
	return nil
}

// awaitAirgapResponse polls the configured response path until it
// appears, returning its contents. The ticker cadence is fixed at
// 500ms — a stricter SLA isn't useful when the bound is human-mediated
// minutes, and a looser one delays kiosk integrations.
func awaitAirgapResponse(ctx context.Context, respPath string) ([]byte, error) {
	const pollEvery = 500 * time.Millisecond
	ticker := time.NewTicker(pollEvery)
	defer ticker.Stop()
	for {
		data, err := os.ReadFile(respPath)
		if err == nil {
			if len(data) == 0 {
				return nil, errors.New("airgap: response file is empty")
			}
			return data, nil
		}
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("airgap: read response: %w", err)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

// newAirgapSessionID returns a 16-byte hex session identifier from
// crypto/rand. Collisions across concurrent ceremonies are negligible.
func newAirgapSessionID() (string, error) {
	const size = 16
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("session id: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
