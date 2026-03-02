package smart

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

// ERC-4337 EntryPoint v0.6 address (deployed on all major EVM chains).
const EntrypointV06 = "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789"

// UserOperation represents an ERC-4337 user operation (v0.6).
type UserOperation struct {
	Sender               string `json:"sender"`
	Nonce                string `json:"nonce"`                // hex uint256
	InitCode             string `json:"initCode"`             // 0x-prefixed bytes (factory+calldata)
	CallData             string `json:"callData"`             // 0x-prefixed bytes
	CallGasLimit         string `json:"callGasLimit"`         // hex uint256
	VerificationGasLimit string `json:"verificationGasLimit"` // hex uint256
	PreVerificationGas   string `json:"preVerificationGas"`   // hex uint256
	MaxFeePerGas         string `json:"maxFeePerGas"`         // hex uint256
	MaxPriorityFeePerGas string `json:"maxPriorityFeePerGas"` // hex uint256
	PaymasterAndData     string `json:"paymasterAndData"`     // 0x-prefixed bytes
	Signature            string `json:"signature"`            // 0x-prefixed bytes
}

// AccountConfig holds parameters for deploying an ERC-4337 SimpleAccount.
type AccountConfig struct {
	FactoryAddress    string // SimpleAccountFactory address
	EntrypointAddress string // EntryPoint address (defaults to EntrypointV06)
	OwnerAddress      string // MPC EOA address that will control the account
	Salt              string // uint256 salt for deterministic deployment
}

// EncodeInitCode builds the initCode for first-time ERC-4337 account deployment.
// initCode = factory address (20 bytes) + createAccount(owner, salt) calldata.
func EncodeInitCode(cfg AccountConfig) ([]byte, error) {
	if cfg.FactoryAddress == "" {
		return nil, fmt.Errorf("erc4337: factory address required")
	}
	if cfg.OwnerAddress == "" {
		return nil, fmt.Errorf("erc4337: owner address required")
	}

	// createAccount(address owner, uint256 salt)
	sel := abiSelector("createAccount(address,uint256)")
	salt := new(big.Int)
	if cfg.Salt != "" {
		s := strings.TrimPrefix(cfg.Salt, "0x")
		salt.SetString(s, 16)
	}

	calldata := make([]byte, 0, 4+64)
	calldata = append(calldata, sel...)
	calldata = append(calldata, abiAddress(cfg.OwnerAddress)...)
	calldata = append(calldata, abiUint256(salt)...)

	// initCode = factory bytes (20) + calldata
	factoryHex := strings.TrimPrefix(cfg.FactoryAddress, "0x")
	factoryBytes, err := hex.DecodeString(factoryHex)
	if err != nil {
		return nil, fmt.Errorf("erc4337: invalid factory address: %w", err)
	}
	if len(factoryBytes) < 20 {
		pad := make([]byte, 20-len(factoryBytes))
		factoryBytes = append(pad, factoryBytes...)
	}
	factoryBytes = factoryBytes[len(factoryBytes)-20:]

	initCode := append(factoryBytes, calldata...)
	return initCode, nil
}

// PredictAccountAddress computes the counterfactual CREATE2 address of the SimpleAccount.
// Uses getAddress(owner, salt) logic from SimpleAccountFactory.
func PredictAccountAddress(cfg AccountConfig) string {
	if cfg.FactoryAddress == "" || cfg.OwnerAddress == "" {
		return ""
	}

	// SimpleAccount creation code is factory-specific.
	// We use the standard keccak256(createAccount selector || abi.encode(owner, salt))
	// pattern that ERC-4337 factories use for deterministic deployment.
	salt := new(big.Int)
	if cfg.Salt != "" {
		s := strings.TrimPrefix(cfg.Salt, "0x")
		salt.SetString(s, 16)
	}

	// salt used in CREATE2 = keccak256(abi.encode(owner, salt)) per SimpleAccountFactory
	innerSalt := keccak256(
		abiAddress(cfg.OwnerAddress),
		abiUint256(salt),
	)

	// Decode factory address to raw bytes
	factoryHex := strings.TrimPrefix(cfg.FactoryAddress, "0x")
	factoryHex = strings.TrimPrefix(factoryHex, "0X")
	factoryBytes, _ := hex.DecodeString(factoryHex)
	if len(factoryBytes) < 20 {
		pad := make([]byte, 20-len(factoryBytes))
		factoryBytes = append(pad, factoryBytes...)
	}
	factoryBytes = factoryBytes[len(factoryBytes)-20:]

	// Build the initCode for CREATE2 hash. For SimpleAccountFactory, the
	// creation code corresponds to the ABI-encoded createAccount call
	// (selector + owner + salt).
	createCalldata := make([]byte, 0, 4+64)
	createCalldata = append(createCalldata, abiSelector("createAccount(address,uint256)")...)
	createCalldata = append(createCalldata, abiAddress(cfg.OwnerAddress)...)
	createCalldata = append(createCalldata, abiUint256(salt)...)
	initCodeHash := keccak256(createCalldata)

	// CREATE2 address = keccak256(0xff ++ factory ++ salt32 ++ keccak256(initCode))[12:]
	raw := make([]byte, 0, 85)
	raw = append(raw, 0xff)
	raw = append(raw, factoryBytes...)
	raw = append(raw, innerSalt...)
	raw = append(raw, initCodeHash...)

	hash := keccak256(raw)
	addr := hash[12:]
	return "0x" + hex.EncodeToString(addr)
}

// PredictCreate2Address computes a raw CREATE2 address given explicit parameters.
// This is the general-purpose CREATE2 formula:
//
//	address = keccak256(0xff ++ deployer ++ salt32 ++ keccak256(initCode))[12:]
func PredictCreate2Address(deployer [20]byte, salt [32]byte, initCode []byte) [20]byte {
	initCodeHash := keccak256(initCode)

	raw := make([]byte, 0, 85)
	raw = append(raw, 0xff)
	raw = append(raw, deployer[:]...)
	raw = append(raw, salt[:]...)
	raw = append(raw, initCodeHash...)

	hash := keccak256(raw)
	var addr [20]byte
	copy(addr[:], hash[12:])
	return addr
}

// hexToBig converts a 0x-prefixed or plain hex string to *big.Int.
func hexToBig(s string) *big.Int {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	n := new(big.Int)
	if s != "" {
		n.SetString(s, 16)
	}
	return n
}

// decBytes converts 0x-prefixed hex to []byte. Returns nil on empty/0x.
func decBytes(s string) []byte {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	if s == "" {
		return nil
	}
	b, _ := hex.DecodeString(s)
	return b
}

// PackUserOp ABI-encodes the UserOperation fields for hashing (ERC-4337 v0.6 spec).
// Returns the packed bytes that get keccak256'd to form the userOpHash inner hash.
func PackUserOp(op *UserOperation) []byte {
	// Per EIP-4337 v0.6: pack = abi.encode(
	//   sender, nonce, keccak256(initCode), keccak256(callData),
	//   callGasLimit, verificationGasLimit, preVerificationGas,
	//   maxFeePerGas, maxPriorityFeePerGas, keccak256(paymasterAndData)
	// )
	initCodeHash := keccak256(decBytes(op.InitCode))
	callDataHash := keccak256(decBytes(op.CallData))
	paymasterHash := keccak256(decBytes(op.PaymasterAndData))

	packed := make([]byte, 0, 32*10)
	packed = append(packed, abiAddress(op.Sender)...)
	packed = append(packed, abiUint256(hexToBig(op.Nonce))...)
	packed = append(packed, initCodeHash...)
	packed = append(packed, callDataHash...)
	packed = append(packed, abiUint256(hexToBig(op.CallGasLimit))...)
	packed = append(packed, abiUint256(hexToBig(op.VerificationGasLimit))...)
	packed = append(packed, abiUint256(hexToBig(op.PreVerificationGas))...)
	packed = append(packed, abiUint256(hexToBig(op.MaxFeePerGas))...)
	packed = append(packed, abiUint256(hexToBig(op.MaxPriorityFeePerGas))...)
	packed = append(packed, paymasterHash...)
	return packed
}

// HashUserOp computes the userOpHash that the MPC key must sign.
// This is what gets submitted as the signature field in the UserOperation.
// Returns 32 bytes — pass to MPC TriggerSign as payload.
func HashUserOp(op *UserOperation, entrypoint string, chainID int64) ([]byte, error) {
	if op == nil {
		return nil, fmt.Errorf("erc4337: nil UserOperation")
	}
	if entrypoint == "" {
		entrypoint = EntrypointV06
	}

	// userOpHash = keccak256(abi.encode(keccak256(pack(userOp)), entrypoint, chainId))
	innerHash := keccak256(PackUserOp(op))

	encoded := make([]byte, 0, 96)
	encoded = append(encoded, innerHash...)
	encoded = append(encoded, abiAddress(entrypoint)...)
	encoded = append(encoded, abiUint256Int(chainID)...)
	return keccak256(encoded), nil
}

// BuildUserOp creates a UserOperation for a simple ETH transfer or contract call.
// The Nonce, gas fields, and PaymasterAndData must be set by the caller after
// fetching them from the bundler/EntryPoint.
func BuildUserOp(sender, to, value, callData string, nonce uint64) *UserOperation {
	// Encode execute(address dest, uint256 value, bytes calldata func) calldata
	// Standard for SimpleAccount.
	sel := abiSelector("execute(address,uint256,bytes)")

	val := new(big.Int)
	if value != "" {
		val.SetString(value, 10)
	}

	var funcData []byte
	if callData != "" && callData != "0x" {
		funcData, _ = hex.DecodeString(strings.TrimPrefix(callData, "0x"))
	}

	// 3 params: to(addr), value(uint256), data(bytes). Dynamic: data (idx 2). Head = 96.
	dataEncoded := abiDynBytes(funcData)
	dataOffset := big.NewInt(96)

	execCalldata := make([]byte, 0)
	execCalldata = append(execCalldata, sel...)
	execCalldata = append(execCalldata, abiAddress(to)...)
	execCalldata = append(execCalldata, abiUint256(val)...)
	execCalldata = append(execCalldata, abiUint256(dataOffset)...)
	execCalldata = append(execCalldata, dataEncoded...)

	nonceHex := fmt.Sprintf("0x%x", nonce)

	return &UserOperation{
		Sender:               sender,
		Nonce:                nonceHex,
		InitCode:             "0x",
		CallData:             "0x" + hex.EncodeToString(execCalldata),
		CallGasLimit:         "0x15f90",    // 90000 — caller should override with estimate
		VerificationGasLimit: "0x186a0",    // 100000
		PreVerificationGas:   "0xbb8",      // 3000
		MaxFeePerGas:         "0x3b9aca00", // 1 gwei
		MaxPriorityFeePerGas: "0x3b9aca00",
		PaymasterAndData:     "0x",
	}
}
