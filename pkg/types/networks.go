package types

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

// SupportedNetworks contains all supported network codes
var SupportedNetworks = map[NetworkCode]bool{
	NetworkBTC:         true,
	NetworkBTCTestnet:  true,
	NetworkETH:         true,
	NetworkETHSepolia:  true,
	NetworkETHGoerli:   true,
	NetworkSOL:         true,
	NetworkSOLDevnet:   true,
	NetworkSOLTestnet:  true,
	NetworkXRPL:        true,
	NetworkXRPLTestnet: true,
	NetworkXRPLDevnet:  true,
	NetworkLUX:         true,
	NetworkLUXTestnet:  true,
	NetworkDOT:         true,
	NetworkDOTTestnet:  true,
	NetworkKSM:         true,
	NetworkTON:         true,
	NetworkTONTestnet:  true,
}

// IsNetworkSupported checks if a network code is supported
func IsNetworkSupported(network string) bool {
	return SupportedNetworks[NetworkCode(network)]
}

// GetNetworkKeyType returns the appropriate key type for a network
func GetNetworkKeyType(network NetworkCode) KeyType {
	switch network {
	case NetworkXRPL, NetworkXRPLTestnet, NetworkXRPLDevnet:
		// XRPL uses secp256k1 for signing
		return KeyTypeSecp256k1
	case NetworkSOL, NetworkSOLDevnet, NetworkSOLTestnet:
		// Solana uses Ed25519
		return KeyTypeEd25519
	case NetworkDOT, NetworkDOTTestnet, NetworkKSM:
		// Polkadot/Kusama uses sr25519 (Ristretto255/Schnorrkel)
		return KeyTypeSR25519
	case NetworkTON, NetworkTONTestnet:
		// TON uses Ed25519
		return KeyTypeEd25519
	default:
		// Most other networks (BTC, ETH, LUX) use secp256k1
		return KeyTypeSecp256k1
	}
}
