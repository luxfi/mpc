// Copyright © 2026 Lux Industries Inc. All rights reserved.

package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/urfave/cli/v3"

	"github.com/luxfi/mpc/pkg/reveal"
)

// sealCommand writes a secret that only a quorum of the ring can read.
//
// It runs nowhere near the ring, and that is the point. Sealing needs the group
// key and nothing else — no share, no node, no round — so this is a local tool
// that takes 32 published bytes and hands back ciphertext. Without it the
// protocol has no beginning: kms wants a sealed root to bring, and until now
// nothing in the estate could produce one.
//
// The secret arrives on stdin so it never becomes a process argument, where it
// would be readable from the process table for as long as the command ran.
var sealCommand = &cli.Command{
	Name:      "seal",
	Usage:     "Seal stdin to a wallet's group key; only a quorum can open it",
	ArgsUsage: " ",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:     "key",
			Usage:    "the wallet's group key, hex (eddsa_pub_key from keygen)",
			Required: true,
		},
		&cli.StringFlag{
			Name:  "out",
			Usage: "hex or base64",
			Value: "base64",
		},
	},
	Action: func(_ context.Context, c *cli.Command) error {
		key, err := hex.DecodeString(strings.TrimSpace(c.String("key")))
		if err != nil {
			return fmt.Errorf("seal: --key is not hex: %w", err)
		}

		secret, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("seal: read the secret: %w", err)
		}
		// A trailing newline is what a shell adds, not what the caller meant to
		// seal. Sealing it would mean the opened secret does not equal the one
		// that went in, which surfaces much later as a key that does not work.
		secret = []byte(strings.TrimRight(string(secret), "\r\n"))

		sealed, err := reveal.Seal(key, secret)
		if err != nil {
			return err
		}

		switch c.String("out") {
		case "hex":
			fmt.Println(hex.EncodeToString(sealed))
		case "base64":
			fmt.Println(base64.StdEncoding.EncodeToString(sealed))
		default:
			return fmt.Errorf("seal: --out is hex or base64, not %q", c.String("out"))
		}
		return nil
	},
}
