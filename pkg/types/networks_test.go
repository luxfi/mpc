package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNetworkConstants(t *testing.T) {
	// Test XRPL network constants
	assert.Equal(t, "XRPL", string(NetworkXRPL))
	assert.Equal(t, "XRPL-testnet", string(NetworkXRPLTestnet))
	assert.Equal(t, "XRPL-devnet", string(NetworkXRPLDevnet))
}

func TestIsNetworkSupported(t *testing.T) {
	testCases := []struct {
		name     string
		network  string
		expected bool
	}{
		// XRPL networks
		{"XRPL mainnet", "XRPL", true},
		{"XRPL testnet", "XRPL-testnet", true},
		{"XRPL devnet", "XRPL-devnet", true},

		// Other networks
		{"Bitcoin", "BTC", true},
		{"Ethereum", "ETH", true},
		{"Solana", "SOL", true},
		{"Lux", "LUX", true},

		// Unsupported
		{"Unknown", "UNKNOWN", false},
		{"Empty", "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := IsNetworkSupported(tc.network)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestKeyTypeForNetwork(t *testing.T) {
	testCases := []struct {
		name     string
		network  NetworkCode
		expected KeyType
	}{
		// XRPL uses secp256k1
		{"XRPL mainnet", NetworkXRPL, KeyTypeSecp256k1},
		{"XRPL testnet", NetworkXRPLTestnet, KeyTypeSecp256k1},
		{"XRPL devnet", NetworkXRPLDevnet, KeyTypeSecp256k1},

		// Solana uses Ed25519
		{"Solana mainnet", NetworkSOL, KeyTypeEd25519},
		{"Solana devnet", NetworkSOLDevnet, KeyTypeEd25519},
		{"Solana testnet", NetworkSOLTestnet, KeyTypeEd25519},

		// Bitcoin uses secp256k1
		{"Bitcoin", NetworkBTC, KeyTypeSecp256k1},

		// Ethereum uses secp256k1
		{"Ethereum", NetworkETH, KeyTypeSecp256k1},

		// The EVM family uses secp256k1
		{"EVM", NetworkEVM, KeyTypeSecp256k1},

		// TON uses Ed25519
		{"TON", NetworkTON, KeyTypeEd25519},
		{"TON testnet", NetworkTONTestnet, KeyTypeEd25519},

		// Polkadot/Kusama use sr25519
		{"Polkadot", NetworkDOT, KeyTypeSR25519},
		{"Kusama", NetworkKSM, KeyTypeSR25519},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := KeyTypeForNetwork(tc.network)
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// TestKeyTypeForNetworkRefusesUnknown is the guard against the failure this
// table exists to prevent: an unrecognised network silently resolving to
// secp256k1, which would sign a Solana transaction with the wrong key.
func TestKeyTypeForNetworkRefusesUnknown(t *testing.T) {
	for _, network := range []NetworkCode{"", "UNKNOWN", "SOLANA", "eth ", "APTOS", "SUI"} {
		t.Run(string(network), func(t *testing.T) {
			kt, err := KeyTypeForNetwork(network)
			assert.ErrorIs(t, err, ErrUnknownNetwork)
			assert.Empty(t, string(kt), "a refusal must not also return a curve")
		})
	}
}

func TestParseNetwork(t *testing.T) {
	for input, expected := range map[string]NetworkCode{
		"SOL":         NetworkSOL,
		"sol":         NetworkSOL,
		"solana":      NetworkSOL,
		"Solana":      NetworkSOL,
		"SOL-devnet":  NetworkSOLDevnet,
		"sol-devnet":  NetworkSOLDevnet,
		"ETH":         NetworkETH,
		"ethereum":    NetworkETH,
		"evm":         NetworkEVM,
		"EVM":         NetworkEVM,
		"base":        NetworkEVM,
		"arbitrum":    NetworkEVM,
		"lux":         NetworkLUX,
		"LUX-testnet": NetworkLUXTestnet,
		"bitcoin":     NetworkBTC,
		"TON":         NetworkTON,
		"  ETH  ":     NetworkETH,
	} {
		t.Run(input, func(t *testing.T) {
			got, err := ParseNetwork(input)
			assert.NoError(t, err)
			assert.Equal(t, expected, got)
		})
	}
}

// TestParseNetworkRefusesUnknown pins the closed-set property: a chain name
// nobody recorded does not get pattern-matched into a family.
func TestParseNetworkRefusesUnknown(t *testing.T) {
	for _, input := range []string{"", "   ", "unichain", "aptos", "sui", "eth-mainnet", "ethereum-classic"} {
		t.Run(input, func(t *testing.T) {
			got, err := ParseNetwork(input)
			assert.ErrorIs(t, err, ErrUnknownNetwork)
			assert.Empty(t, string(got))
		})
	}
}

// TestEveryNetworkConstantResolves keeps the constant list and the curve table
// from drifting apart: a network code that exists but is absent from the table
// would be a name callers can pass and the signer must then refuse.
func TestEveryNetworkConstantResolves(t *testing.T) {
	for _, code := range []NetworkCode{
		NetworkBTC, NetworkBTCTestnet,
		NetworkETH, NetworkETHSepolia, NetworkETHGoerli, NetworkEVM,
		NetworkSOL, NetworkSOLDevnet, NetworkSOLTestnet,
		NetworkXRPL, NetworkXRPLTestnet, NetworkXRPLDevnet,
		NetworkLUX, NetworkLUXTestnet,
		NetworkDOT, NetworkDOTTestnet, NetworkKSM,
		NetworkTON, NetworkTONTestnet,
	} {
		t.Run(string(code), func(t *testing.T) {
			_, err := KeyTypeForNetwork(code)
			assert.NoError(t, err, "network constant %q has no curve recorded", code)
		})
	}
}
