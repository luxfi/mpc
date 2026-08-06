package types

import (
	"errors"
	"fmt"
	"strings"
)

// NetworkCode represents a supported blockchain network
type NetworkCode string

const (
	// Bitcoin networks
	NetworkBTC        NetworkCode = "BTC"
	NetworkBTCTestnet NetworkCode = "BTC-testnet"

	// Ethereum networks
	NetworkETH        NetworkCode = "ETH"
	NetworkETHSepolia NetworkCode = "ETH-sepolia"
	NetworkETHGoerli  NetworkCode = "ETH-goerli"

	// NetworkEVM names the EVM chain family rather than one chain.
	//
	// It exists because some requests are bound to the EVM by construction and
	// not to any particular chain: an EIP-712 Safe hash, an ERC-4337 userOp
	// hash, a keccak256 bridge digest. Those callers know the runtime and the
	// curve with certainty and would otherwise have to name a chain they are
	// not actually on. Every EVM chain signs with secp256k1, so the family is
	// exactly as precise as the curve question requires and no more.
	NetworkEVM NetworkCode = "EVM"

	// Solana networks
	NetworkSOL        NetworkCode = "SOL"
	NetworkSOLDevnet  NetworkCode = "SOL-devnet"
	NetworkSOLTestnet NetworkCode = "SOL-testnet"

	// XRP Ledger networks
	NetworkXRPL        NetworkCode = "XRPL"
	NetworkXRPLTestnet NetworkCode = "XRPL-testnet"
	NetworkXRPLDevnet  NetworkCode = "XRPL-devnet"

	// Lux networks
	NetworkLUX        NetworkCode = "LUX"
	NetworkLUXTestnet NetworkCode = "LUX-testnet"

	// Substrate/Polkadot networks (sr25519)
	NetworkDOT        NetworkCode = "DOT"
	NetworkDOTTestnet NetworkCode = "DOT-testnet"
	NetworkKSM        NetworkCode = "KSM"

	// Other networks
	NetworkTON        NetworkCode = "TON"
	NetworkTONTestnet NetworkCode = "TON-testnet"
)

// networkKeyType is the single table recording which chain signs with which
// curve. Nothing else in this repository may decide a curve.
//
// The table is deliberately total with no default arm. A network that is not
// listed has no curve here and yields ErrUnknownNetwork, because the only
// alternatives to refusing are worse: assuming secp256k1 produces a signature
// Solana rejects, and assuming Ed25519 signs with a key the caller never meant
// to use. Adding a chain is a one-line change here and nowhere else.
var networkKeyType = map[NetworkCode]KeyType{
	// secp256k1 — ECDSA (CGGMP21)
	NetworkBTC:         KeyTypeSecp256k1,
	NetworkBTCTestnet:  KeyTypeSecp256k1,
	NetworkETH:         KeyTypeSecp256k1,
	NetworkETHSepolia:  KeyTypeSecp256k1,
	NetworkETHGoerli:   KeyTypeSecp256k1,
	NetworkEVM:         KeyTypeSecp256k1,
	NetworkXRPL:        KeyTypeSecp256k1,
	NetworkXRPLTestnet: KeyTypeSecp256k1,
	NetworkXRPLDevnet:  KeyTypeSecp256k1,
	NetworkLUX:         KeyTypeSecp256k1,
	NetworkLUXTestnet:  KeyTypeSecp256k1,

	// Ed25519 — PureEdDSA (FROST)
	NetworkSOL:        KeyTypeEd25519,
	NetworkSOLDevnet:  KeyTypeEd25519,
	NetworkSOLTestnet: KeyTypeEd25519,
	NetworkTON:        KeyTypeEd25519,
	NetworkTONTestnet: KeyTypeEd25519,

	// sr25519 — Ristretto255 (generic FROST). Listed because the curve is a
	// fact about the chain, not a claim that a share exists: no keygen leg
	// mints sr25519 today, so these resolve and then fail closed at share load.
	NetworkDOT:        KeyTypeSR25519,
	NetworkDOTTestnet: KeyTypeSR25519,
	NetworkKSM:        KeyTypeSR25519,
}

// networkAlias maps the chain vocabulary this product stores on its own
// records ("evm", "ethereum", "solana", …) onto canonical network codes.
//
// It is a closed lookup, not a normalizer: a name that is absent is refused
// rather than pattern-matched into a family. Chain names arrive from API
// callers and are otherwise unvalidated, so the set of names that can select a
// curve has to be enumerated somewhere, and this is that place. An EVM chain
// missing from this list costs one line to add and, until then, fails closed.
var networkAlias = map[string]NetworkCode{
	"evm":      NetworkEVM,
	"ethereum": NetworkETH,
	"eth":      NetworkETH,
	"sepolia":  NetworkETHSepolia,
	"goerli":   NetworkETHGoerli,
	"polygon":  NetworkEVM,
	"bsc":      NetworkEVM,
	"base":     NetworkEVM,
	"arbitrum": NetworkEVM,
	"optimism": NetworkEVM,
	"bitcoin":  NetworkBTC,
	"btc":      NetworkBTC,
	"solana":   NetworkSOL,
	"sol":      NetworkSOL,
	"lux":      NetworkLUX,
	"xrpl":     NetworkXRPL,
	"xrp":      NetworkXRPL,
	"ton":      NetworkTON,
	"dot":      NetworkDOT,
	"polkadot": NetworkDOT,
	"ksm":      NetworkKSM,
	"kusama":   NetworkKSM,
}

// ErrUnknownNetwork reports that a request named a network whose signing curve
// is not recorded. It is a refusal, never a fallback.
var ErrUnknownNetwork = errors.New("unknown network: no signing curve recorded")

// KeyTypeForNetwork returns the curve a network signs with.
//
// This is the only function in the repository that answers "which curve".
// Callers must propagate the error: there is no safe curve to assume, because
// the two failure directions are producing a signature the chain rejects and
// signing with a key the caller never named.
func KeyTypeForNetwork(network NetworkCode) (KeyType, error) {
	kt, ok := networkKeyType[network]
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrUnknownNetwork, network)
	}
	return kt, nil
}

// ParseNetwork resolves a free-form chain string — the value carried on
// transaction and wallet records, or supplied on the wire — to a canonical
// network code. Matching is case-insensitive against the canonical codes and
// then against the alias table; anything else is refused.
func ParseNetwork(s string) (NetworkCode, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return "", fmt.Errorf("%w: (empty)", ErrUnknownNetwork)
	}
	// Canonical codes are upper-case with a lower-case suffix ("ETH-sepolia"),
	// so compare fold-insensitively rather than upper-casing the input.
	for code := range networkKeyType {
		if strings.EqualFold(string(code), trimmed) {
			return code, nil
		}
	}
	if code, ok := networkAlias[strings.ToLower(trimmed)]; ok {
		return code, nil
	}
	return "", fmt.Errorf("%w: %q", ErrUnknownNetwork, s)
}

// IsNetworkSupported reports whether a network code names a network whose
// curve is recorded — the same question KeyTypeForNetwork answers, phrased for
// callers that only need the boolean.
func IsNetworkSupported(network string) bool {
	_, err := KeyTypeForNetwork(NetworkCode(network))
	return err == nil
}
