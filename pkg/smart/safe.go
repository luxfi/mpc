// Package smart provides Gnosis Safe and ERC-4337 smart contract wallet integration.
// The MPC EOA serves as one of the Safe owners, signing Safe transaction hashes
// rather than raw Ethereum transactions.
package smart

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

// Well-known Safe contract addresses (same across all EVM chains for v1.3.0).
const (
	SafeSingletonV130    = "0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552"
	SafeProxyFactoryV130 = "0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2"
	SafeFallbackHandler  = "0xf48f2B2d2a534e402487b3ee7C18c33Aec0Fe5e4"
)

// SafeConfig holds deployment parameters for a new Safe.
type SafeConfig struct {
	FactoryAddress  string   // Safe ProxyFactory address
	SingletonAddr   string   // Safe singleton (master copy) address
	Owners          []string // Owner addresses (includes the MPC EOA)
	Threshold       int      // Number of required confirmations
	Salt            string   // CREATE2 salt (hex, 0x-prefixed or plain 32-byte hex)
	FallbackHandler string   // Fallback handler address
}

// SafeTransaction represents a queued Safe transaction (EIP-712 typed).
type SafeTransaction struct {
	To             string `json:"to"`
	Value          string `json:"value"`     // decimal wei
	Data           string `json:"data"`      // 0x-prefixed hex calldata
	Operation      int    `json:"operation"` // 0=Call, 1=DelegateCall
	SafeTxGas      string `json:"safe_tx_gas"`
	BaseGas        string `json:"base_gas"`
	GasPrice       string `json:"gas_price"`
	GasToken       string `json:"gas_token"`
	RefundReceiver string `json:"refund_receiver"`
	Nonce          int    `json:"nonce"`
}

// Safe EIP-712 type hashes — computed once at init.
var (
	safeDomainTypehash = keccak256([]byte(
		"EIP712Domain(uint256 chainId,address verifyingContract)",
	))
	safeTxTypehash = keccak256([]byte(
		"SafeTx(address to,uint256 value,bytes data,uint8 operation," +
			"uint256 safeTxGas,uint256 baseGas,uint256 gasPrice," +
			"address gasToken,address refundReceiver,uint256 nonce)",
	))
)

func applyDefaults(cfg *SafeConfig) {
	if cfg.FactoryAddress == "" {
		cfg.FactoryAddress = SafeProxyFactoryV130
	}
	if cfg.SingletonAddr == "" {
		cfg.SingletonAddr = SafeSingletonV130
	}
	if cfg.FallbackHandler == "" {
		cfg.FallbackHandler = SafeFallbackHandler
	}
}

func parseSaltNonce(salt string) *big.Int {
	salt = strings.TrimPrefix(salt, "0x")
	salt = strings.TrimPrefix(salt, "0X")
	if salt == "" {
		return big.NewInt(0)
	}
	n := new(big.Int)
	n.SetString(salt, 16)
	return n
}

// encodeSetup builds Safe.setup() calldata (the initializer for the proxy).
func encodeSetup(cfg SafeConfig) []byte {
	sel := abiSelector("setup(address[],uint256,address,bytes,address,address,uint256,address)")

	// 8 params: owners(addr[]), threshold(uint256), to(addr), data(bytes),
	//           fallbackHandler(addr), paymentToken(addr), payment(uint256), paymentReceiver(addr)
	// Dynamic: owners (idx 0), data (idx 3).
	// Head = 8 × 32 = 256 bytes.
	// owners offset = 256
	ownersData := abiEncodeAddressArray(cfg.Owners)
	ownersOffset := big.NewInt(256)
	// empty bytes for `data` starts after owners
	emptyBytesOffset := new(big.Int).Add(ownersOffset, big.NewInt(int64(len(ownersData))))

	heads := make([]byte, 0, 256)
	heads = append(heads, abiUint256(ownersOffset)...)
	heads = append(heads, abiUint256Int(int64(cfg.Threshold))...)
	heads = append(heads, abiAddress("0x0000000000000000000000000000000000000000")...)
	heads = append(heads, abiUint256(emptyBytesOffset)...)
	heads = append(heads, abiAddress(cfg.FallbackHandler)...)
	heads = append(heads, abiAddress("0x0000000000000000000000000000000000000000")...)
	heads = append(heads, abiUint256Int(0)...)
	heads = append(heads, abiAddress("0x0000000000000000000000000000000000000000")...)

	calldata := make([]byte, 0)
	calldata = append(calldata, sel...)
	calldata = append(calldata, heads...)
	calldata = append(calldata, ownersData...)
	calldata = append(calldata, abiDynBytes(nil)...) // empty bytes for `data`
	return calldata
}

// EncodeDeploy returns the calldata for Safe ProxyFactory.createProxyWithNonce().
func EncodeDeploy(cfg SafeConfig) ([]byte, error) {
	applyDefaults(&cfg)
	if len(cfg.Owners) == 0 {
		return nil, fmt.Errorf("safe: at least one owner required")
	}
	if cfg.Threshold < 1 || cfg.Threshold > len(cfg.Owners) {
		return nil, fmt.Errorf("safe: threshold must be 1..%d", len(cfg.Owners))
	}

	sel := abiSelector("createProxyWithNonce(address,bytes,uint256)")
	initializer := encodeSetup(cfg)

	// 3 params: singleton(addr), initializer(bytes), saltNonce(uint256)
	// Dynamic: initializer (idx 1). Head = 3×32 = 96 bytes. initializer offset = 96.
	initOffset := big.NewInt(96)
	initData := abiDynBytes(initializer)

	calldata := make([]byte, 0)
	calldata = append(calldata, sel...)
	calldata = append(calldata, abiAddress(cfg.SingletonAddr)...)
	calldata = append(calldata, abiUint256(initOffset)...)
	calldata = append(calldata, abiUint256(parseSaltNonce(cfg.Salt))...)
	calldata = append(calldata, initData...)
	return calldata, nil
}

// PredictAddress computes the CREATE2 address for a Safe deployment.
// Returns a 0x-prefixed lowercase hex address.
func PredictAddress(cfg SafeConfig) string {
	applyDefaults(&cfg)
	initializer := encodeSetup(cfg)

	// Safe ProxyFactory CREATE2 salt: keccak256(keccak256(initializer) ++ saltNonce[32])
	initHash := keccak256(initializer)
	sn := parseSaltNonce(cfg.Salt)
	snSlot := abiUint256(sn)
	factorySalt := keccak256(initHash, snSlot)

	// Safe proxy creation code for v1.3.0 + ABI-encoded singleton appended.
	proxyCreationCode, _ := hex.DecodeString(
		"608060405234801561001057600080fd5b506040516101e63803806101e6833981810160405260" +
			"208110156100335760008060fd5b810190808051906020019092919050505060" +
			"0073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffff" +
			"ffffffffffffffffffffffffff1614156100ca57604051600080fd5b806000806" +
			"101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373" +
			"ffffffffffffffffffffffffffffffffffffffff1602179055505060ab806101" +
			"196000396000f3fe608060405273ffffffffffffffffffffffffffffff" +
			"ffffffffff600054167fa619486e0000000000000000000000000000000000000" +
			"00000000000000060003514156050578060005260206000f35b3660008037600" +
			"080366000845af43d6000803e60008015156068573d6000fd5b3d6000f3fea264" +
			"6970667358221220d1429297349653a4918076d650332de1a1068c5f3e07c5c82" +
			"360c277770b95264736f6c63430007060033",
	)
	initCode := append(proxyCreationCode, abiAddress(cfg.SingletonAddr)...)
	initCodeHash := keccak256(initCode)

	// Decode factory address
	factoryHex := strings.TrimPrefix(cfg.FactoryAddress, "0x")
	factoryBytes, _ := hex.DecodeString(factoryHex)
	if len(factoryBytes) < 20 {
		pad := make([]byte, 20-len(factoryBytes))
		factoryBytes = append(pad, factoryBytes...)
	}
	factoryBytes = factoryBytes[len(factoryBytes)-20:]

	preimage := make([]byte, 0, 85)
	preimage = append(preimage, 0xff)
	preimage = append(preimage, factoryBytes...)
	preimage = append(preimage, factorySalt...)
	preimage = append(preimage, initCodeHash...)

	addrBytes := keccak256(preimage)
	return "0x" + hex.EncodeToString(addrBytes[12:])
}

// HashSafeTransaction computes the EIP-712 hash that all owners must sign.
// Returns the 32-byte hash — pass this to MPC TriggerSign as the payload.
func HashSafeTransaction(safeAddress string, chainID int64, tx SafeTransaction) ([]byte, error) {
	// Domain separator
	domainSep := keccak256(
		safeDomainTypehash,
		abiUint256Int(chainID),
		abiAddress(safeAddress),
	)

	// Parse tx fields
	value := new(big.Int)
	if tx.Value != "" {
		value.SetString(tx.Value, 10)
	}
	var dataBytes []byte
	if tx.Data != "" && tx.Data != "0x" {
		raw := strings.TrimPrefix(tx.Data, "0x")
		var err error
		dataBytes, err = hex.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("safe: invalid data hex: %w", err)
		}
	}
	dataHash := keccak256(dataBytes)

	safeTxGas := parseBigInt(tx.SafeTxGas)
	baseGas := parseBigInt(tx.BaseGas)
	gasPrice := parseBigInt(tx.GasPrice)

	gasToken := tx.GasToken
	if gasToken == "" {
		gasToken = "0x0000000000000000000000000000000000000000"
	}
	refundReceiver := tx.RefundReceiver
	if refundReceiver == "" {
		refundReceiver = "0x0000000000000000000000000000000000000000"
	}

	// safeTxHash = keccak256(SAFE_TX_TYPEHASH || to || value || keccak256(data) ||
	//                        operation || safeTxGas || baseGas || gasPrice ||
	//                        gasToken || refundReceiver || nonce)
	encoded := make([]byte, 0, 32*11)
	encoded = append(encoded, safeTxTypehash...)
	encoded = append(encoded, abiAddress(tx.To)...)
	encoded = append(encoded, abiUint256(value)...)
	encoded = append(encoded, dataHash...)
	encoded = append(encoded, abiUint256Int(int64(tx.Operation))...)
	encoded = append(encoded, abiUint256(safeTxGas)...)
	encoded = append(encoded, abiUint256(baseGas)...)
	encoded = append(encoded, abiUint256(gasPrice)...)
	encoded = append(encoded, abiAddress(gasToken)...)
	encoded = append(encoded, abiAddress(refundReceiver)...)
	encoded = append(encoded, abiUint256Int(int64(tx.Nonce))...)
	safeTxHash := keccak256(encoded)

	// Final EIP-712: keccak256(\x19\x01 || domainSep || safeTxHash)
	msg := append([]byte{0x19, 0x01}, domainSep...)
	msg = append(msg, safeTxHash...)
	return keccak256(msg), nil
}

// EncodeExecTransaction returns calldata for Safe.execTransaction() with packed sigs.
func EncodeExecTransaction(tx SafeTransaction, signatures []byte) ([]byte, error) {
	sel := abiSelector("execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)")

	value := parseBigInt(tx.Value)
	var dataBytes []byte
	if tx.Data != "" && tx.Data != "0x" {
		raw := strings.TrimPrefix(tx.Data, "0x")
		var err error
		dataBytes, err = hex.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("safe: invalid data hex: %w", err)
		}
	}
	safeTxGas := parseBigInt(tx.SafeTxGas)
	baseGas := parseBigInt(tx.BaseGas)
	gasPrice := parseBigInt(tx.GasPrice)

	gasToken := tx.GasToken
	if gasToken == "" {
		gasToken = "0x0000000000000000000000000000000000000000"
	}
	refundReceiver := tx.RefundReceiver
	if refundReceiver == "" {
		refundReceiver = "0x0000000000000000000000000000000000000000"
	}

	// 10 params; dynamic: data (idx 2), signatures (idx 9). Head = 10×32 = 320 bytes.
	dataEncoded := abiDynBytes(dataBytes)
	dataOffset := big.NewInt(320)
	sigsOffset := new(big.Int).Add(dataOffset, big.NewInt(int64(len(dataEncoded))))
	sigsEncoded := abiDynBytes(signatures)

	heads := make([]byte, 0, 320)
	heads = append(heads, abiAddress(tx.To)...)
	heads = append(heads, abiUint256(value)...)
	heads = append(heads, abiUint256(dataOffset)...)
	heads = append(heads, abiUint256Int(int64(tx.Operation))...)
	heads = append(heads, abiUint256(safeTxGas)...)
	heads = append(heads, abiUint256(baseGas)...)
	heads = append(heads, abiUint256(gasPrice)...)
	heads = append(heads, abiAddress(gasToken)...)
	heads = append(heads, abiAddress(refundReceiver)...)
	heads = append(heads, abiUint256(sigsOffset)...)

	calldata := make([]byte, 0)
	calldata = append(calldata, sel...)
	calldata = append(calldata, heads...)
	calldata = append(calldata, dataEncoded...)
	calldata = append(calldata, sigsEncoded...)
	return calldata, nil
}

// PackSignature packs MPC r+s+v into the 65-byte format Safe expects per owner.
func PackSignature(r, s []byte, v byte) []byte {
	sig := make([]byte, 65)
	copy(sig[32-len(r):32], r)
	copy(sig[64-len(s):64], s)
	sig[64] = v
	return sig
}

func parseBigInt(s string) *big.Int {
	n := new(big.Int)
	if s != "" {
		n.SetString(s, 10)
	}
	return n
}
