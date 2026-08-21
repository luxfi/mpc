package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/urfave/cli/v3"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/types"

	"github.com/luxfi/mpc/pkg/evm"
)

// evmCommand groups the operator tools for signing Lux (and any EVM) transactions
// with a wallet whose key is held by the MPC quorum. It replaces `cast
// --mnemonic` and the practice of mounting a plaintext key into a pod: the
// account is derived from a public key, the digest is signed by the quorum, and
// the signed transaction is assembled from the returned (r, s, v). No private
// key or mnemonic is ever read.
//
// The deploy flow is three composable steps:
//
//	addr=$(mpc evm address --pubkey <ecdsa_pub_key from keygen>)
//	digest=$(mpc evm tx --chainid 96369 --nonce N --to 0x.. --value W --gas G --gasprice P)
//	# sign `digest` through the quorum (mpc evm sign, or the MPC /v1/mpc/sign oracle)
//	raw=$(mpc evm tx --chainid 96369 --nonce N --to 0x.. --value W --gas G --gasprice P --sig <r,s,v>)
//	cast publish "$raw"
func evmCommand() *cli.Command {
	return &cli.Command{
		Name:  "evm",
		Usage: "Derive accounts and sign EVM transactions with an MPC-held key (no plaintext key)",
		Commands: []*cli.Command{
			{
				Name:   "address",
				Usage:  "Derive the EVM account from a secp256k1 public key (as reported by keygen)",
				Action: evmAddress,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "pubkey", Aliases: []string{"p"}, Required: true,
						Usage: "secp256k1 public key, hex (33, 64, or 65 bytes)"},
				},
			},
			{
				Name:   "recover",
				Usage:  "Recover the EVM account a signature binds to (verification)",
				Action: evmRecover,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "digest", Aliases: []string{"d"}, Required: true, Usage: "32-byte signing digest, hex"},
					&cli.StringFlag{Name: "sig", Aliases: []string{"s"}, Required: true, Usage: "signature as r,s,v or 65-byte hex"},
				},
			},
			{
				Name:  "sign",
				Usage: "Sign a 32-byte digest and print r,s,v (offline/air-gapped key; the quorum path is `mpc evm tx`)",
				Description: "Signs with a local secp256k1 key for development, air-gapped signing, and tests. " +
					"Production keys never leave the MPC quorum: sign a digest through the /v1/mpc/sign oracle " +
					"(network \"evm\") and feed the result to `mpc evm tx --sig`.",
				Action: evmSign,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "digest", Aliases: []string{"d"}, Required: true, Usage: "32-byte digest, hex"},
					&cli.StringFlag{Name: "key", Aliases: []string{"k"}, Required: true, Usage: "secp256k1 private key, hex (dev/air-gap only)"},
				},
			},
			{
				Name:  "tx",
				Usage: "Build an EVM transaction's signing digest, or assemble the signed transaction from a signature",
				Description: "With neither --sig nor --key, prints the 32-byte digest to sign through the quorum. " +
					"With --sig (from the quorum) or --key (local), prints the 0x raw signed transaction ready for `cast publish`. " +
					"An empty --to means contract creation (a deploy).",
				Action: evmTx,
				Flags: []cli.Flag{
					&cli.IntFlag{Name: "chainid", Required: true, Usage: "EVM chain id (Lux mainnet 96369)"},
					&cli.IntFlag{Name: "nonce", Required: true, Usage: "account nonce"},
					&cli.IntFlag{Name: "gas", Required: true, Usage: "gas limit"},
					&cli.StringFlag{Name: "to", Usage: "recipient (empty = contract creation)"},
					&cli.StringFlag{Name: "value", Value: "0", Usage: "value in wei (decimal or 0x hex)"},
					&cli.StringFlag{Name: "data", Usage: "calldata / init code, hex"},
					&cli.StringFlag{Name: "gasprice", Usage: "legacy gas price in wei"},
					&cli.StringFlag{Name: "maxfee", Usage: "EIP-1559 max fee per gas in wei"},
					&cli.StringFlag{Name: "tip", Usage: "EIP-1559 max priority fee per gas in wei"},
					&cli.StringFlag{Name: "sig", Usage: "quorum signature as r,s,v or 65-byte hex; assembles the signed tx"},
					&cli.StringFlag{Name: "key", Usage: "local secp256k1 key, hex (dev/air-gap); signs and assembles in one step"},
					&cli.StringFlag{Name: "from", Usage: "expected account; assembly fails if the signature binds elsewhere"},
				},
			},
		},
	}
}

func evmAddress(_ context.Context, c *cli.Command) error {
	pub, err := decodeHex(c.String("pubkey"))
	if err != nil {
		return fmt.Errorf("pubkey: %w", err)
	}
	addr, err := evm.Account(pub)
	if err != nil {
		return err
	}
	fmt.Println(addr.Hex())
	return nil
}

func evmRecover(_ context.Context, c *cli.Command) error {
	digest, err := decodeHex(c.String("digest"))
	if err != nil {
		return fmt.Errorf("digest: %w", err)
	}
	sig, err := parseSig(c.String("sig"))
	if err != nil {
		return err
	}
	addr, err := evm.Recover(digest, sig)
	if err != nil {
		return err
	}
	fmt.Println(addr.Hex())
	return nil
}

func evmSign(ctx context.Context, c *cli.Command) error {
	digest, err := decodeHex(c.String("digest"))
	if err != nil {
		return fmt.Errorf("digest: %w", err)
	}
	signer, err := evm.LocalFromHex(c.String("key"))
	if err != nil {
		return err
	}
	sig, err := signer.Sign(ctx, digest)
	if err != nil {
		return err
	}
	// r,s,v to stderr for the human; the packed 65-byte signature to stdout so it
	// pipes straight into `mpc evm tx --sig`.
	fmt.Fprintf(os.Stderr, "account: %s\nr: 0x%x\ns: 0x%x\nv: %d\n", signer.Account().Hex(), sig.R, sig.S, sig.V)
	fmt.Printf("0x%x\n", sig.Bytes())
	return nil
}

func evmTx(ctx context.Context, c *cli.Command) error {
	chainID := big.NewInt(int64(c.Int("chainid")))
	tx, err := buildTx(c, chainID)
	if err != nil {
		return err
	}

	// No signature yet: print the digest to sign through the quorum.
	if c.String("sig") == "" && c.String("key") == "" {
		digest, err := evm.Digest(tx, chainID)
		if err != nil {
			return err
		}
		fmt.Printf("0x%x\n", digest)
		return nil
	}

	// Local key: sign and assemble in one step (dev/air-gap).
	if key := c.String("key"); key != "" {
		signer, err := evm.LocalFromHex(key)
		if err != nil {
			return err
		}
		signed, err := evm.SignTx(ctx, signer, tx, chainID)
		if err != nil {
			return err
		}
		return printSignedTx(signed, signer.Account())
	}

	// Quorum signature: assemble and verify which account it binds to.
	sig, err := parseSig(c.String("sig"))
	if err != nil {
		return err
	}
	digest, err := evm.Digest(tx, chainID)
	if err != nil {
		return err
	}
	want, err := evm.Recover(digest, sig)
	if err != nil {
		return err
	}
	if from := c.String("from"); from != "" && !strings.EqualFold(from, want.Hex()) {
		return fmt.Errorf("signature binds tx to %s, want %s", want.Hex(), from)
	}
	signed, err := evm.Apply(tx, chainID, sig, want)
	if err != nil {
		return err
	}
	return printSignedTx(signed, want)
}

// buildTx assembles the unsigned transaction from the flags. Legacy when a gas
// price is given, EIP-1559 when a max fee and tip are given; an empty recipient
// is contract creation.
func buildTx(c *cli.Command, chainID *big.Int) (*types.Transaction, error) {
	value, err := parseWei(c.String("value"))
	if err != nil {
		return nil, fmt.Errorf("value: %w", err)
	}
	var data []byte
	if d := c.String("data"); d != "" {
		if data, err = decodeHex(d); err != nil {
			return nil, fmt.Errorf("data: %w", err)
		}
	}
	var to *common.Address
	if t := c.String("to"); t != "" {
		addr := common.HexToAddress(t)
		to = &addr
	}
	nonce := uint64(c.Int("nonce"))
	gas := uint64(c.Int("gas"))

	maxfee, tip := c.String("maxfee"), c.String("tip")
	if maxfee != "" || tip != "" {
		feeCap, err := parseWei(maxfee)
		if err != nil {
			return nil, fmt.Errorf("maxfee: %w", err)
		}
		tipCap, err := parseWei(tip)
		if err != nil {
			return nil, fmt.Errorf("tip: %w", err)
		}
		return types.NewTx(&types.DynamicFeeTx{
			ChainID: chainID, Nonce: nonce, GasTipCap: tipCap, GasFeeCap: feeCap,
			Gas: gas, To: to, Value: value, Data: data,
		}), nil
	}

	gasPrice, err := parseWei(c.String("gasprice"))
	if err != nil {
		return nil, fmt.Errorf("gasprice: %w", err)
	}
	if gasPrice.Sign() == 0 {
		return nil, fmt.Errorf("a fee is required: pass --gasprice (legacy) or --maxfee and --tip (EIP-1559)")
	}
	return types.NewTx(&types.LegacyTx{
		Nonce: nonce, GasPrice: gasPrice, Gas: gas, To: to, Value: value, Data: data,
	}), nil
}

func printSignedTx(signed *types.Transaction, from common.Address) error {
	raw, err := signed.MarshalBinary()
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "from: %s\nhash: %s\n", from.Hex(), signed.Hash().Hex())
	fmt.Printf("0x%x\n", raw)
	return nil
}

func parseSig(s string) (evm.Signature, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, ",") {
		parts := strings.Split(s, ",")
		if len(parts) != 3 {
			return evm.Signature{}, fmt.Errorf("signature must be r,s,v (three comma-separated values)")
		}
		r, err := decodeHex(parts[0])
		if err != nil {
			return evm.Signature{}, fmt.Errorf("signature r: %w", err)
		}
		sv, err := decodeHex(parts[1])
		if err != nil {
			return evm.Signature{}, fmt.Errorf("signature s: %w", err)
		}
		v := strings.TrimSpace(trimHexPrefix(parts[2]))
		var vb byte
		switch v {
		case "0", "00":
			vb = 0
		case "1", "01":
			vb = 1
		case "27", "1b":
			vb = 0
		case "28", "1c":
			vb = 1
		default:
			return evm.Signature{}, fmt.Errorf("signature v must be 0, 1, 27, or 28, got %q", v)
		}
		return evm.SignatureFromRSV(r, sv, vb)
	}
	b, err := decodeHex(s)
	if err != nil {
		return evm.Signature{}, fmt.Errorf("signature: %w", err)
	}
	return evm.ParseSignature(b)
}

func parseWei(s string) (*big.Int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return big.NewInt(0), nil
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		n, ok := new(big.Int).SetString(s[2:], 16)
		if !ok {
			return nil, fmt.Errorf("invalid hex integer %q", s)
		}
		return n, nil
	}
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return nil, fmt.Errorf("invalid integer %q", s)
	}
	return n, nil
}

func decodeHex(s string) ([]byte, error) {
	return hex.DecodeString(trimHexPrefix(strings.TrimSpace(s)))
}

func trimHexPrefix(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0:2] == "0x" || s[0:2] == "0X") {
		return s[2:]
	}
	return s
}
