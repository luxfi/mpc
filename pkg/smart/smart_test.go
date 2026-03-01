package smart

import (
	"encoding/hex"
	"strings"
	"testing"
)

// TestSafeEncodeDeploy verifies EncodeDeploy produces valid 4-byte selector + ABI data.
func TestSafeEncodeDeploy(t *testing.T) {
	cfg := SafeConfig{
		Owners:    []string{"0xEAbCC110fAcBfebabC66Ad6f9E7B67288e720B59"},
		Threshold: 1,
		Salt:      "0x1",
	}
	calldata, err := EncodeDeploy(cfg)
	if err != nil {
		t.Fatalf("EncodeDeploy: %v", err)
	}
	if len(calldata) < 4 {
		t.Fatalf("calldata too short: %d bytes", len(calldata))
	}
	// Selector for createProxyWithNonce(address,bytes,uint256)
	wantSel := abiSelector("createProxyWithNonce(address,bytes,uint256)")
	gotSel := calldata[:4]
	if hex.EncodeToString(gotSel) != hex.EncodeToString(wantSel) {
		t.Errorf("wrong selector: got %x want %x", gotSel, wantSel)
	}
}

// TestSafeHashSafeTransaction verifies EIP-712 hash is 32 bytes and deterministic.
func TestSafeHashSafeTransaction(t *testing.T) {
	tx := SafeTransaction{
		To:    "0xEAbCC110fAcBfebabC66Ad6f9E7B67288e720B59",
		Value: "1000000000000000000",
		Nonce: 0,
	}
	hash1, err := HashSafeTransaction("0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552", 1, tx)
	if err != nil {
		t.Fatalf("HashSafeTransaction: %v", err)
	}
	if len(hash1) != 32 {
		t.Errorf("expected 32-byte hash, got %d bytes", len(hash1))
	}
	// Deterministic
	hash2, _ := HashSafeTransaction("0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552", 1, tx)
	if hex.EncodeToString(hash1) != hex.EncodeToString(hash2) {
		t.Error("hash not deterministic")
	}
	// Different chain ID → different hash
	hash3, _ := HashSafeTransaction("0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552", 137, tx)
	if hex.EncodeToString(hash1) == hex.EncodeToString(hash3) {
		t.Error("expected different hash for different chainID")
	}
}

// TestSafePredictAddress verifies PredictAddress returns a valid hex address.
func TestSafePredictAddress(t *testing.T) {
	cfg := SafeConfig{
		Owners:    []string{"0xEAbCC110fAcBfebabC66Ad6f9E7B67288e720B59"},
		Threshold: 1,
		Salt:      "0x0",
	}
	addr := PredictAddress(cfg)
	if !strings.HasPrefix(addr, "0x") {
		t.Errorf("expected 0x-prefixed address, got %q", addr)
	}
	if len(addr) != 42 {
		t.Errorf("expected 42-char address, got %d chars: %s", len(addr), addr)
	}
}

// TestEncodeExecTransaction verifies execTransaction calldata has correct selector.
func TestEncodeExecTransaction(t *testing.T) {
	tx := SafeTransaction{
		To:    "0xEAbCC110fAcBfebabC66Ad6f9E7B67288e720B59",
		Value: "0",
	}
	sigs := PackSignature(make([]byte, 32), make([]byte, 32), 27)
	calldata, err := EncodeExecTransaction(tx, sigs)
	if err != nil {
		t.Fatalf("EncodeExecTransaction: %v", err)
	}
	wantSel := abiSelector("execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)")
	if hex.EncodeToString(calldata[:4]) != hex.EncodeToString(wantSel) {
		t.Errorf("wrong selector: got %x want %x", calldata[:4], wantSel)
	}
}

// TestBuildUserOp verifies BuildUserOp returns a valid UserOperation.
func TestBuildUserOp(t *testing.T) {
	op := BuildUserOp(
		"0xEAbCC110fAcBfebabC66Ad6f9E7B67288e720B59",
		"0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552",
		"1000000000000000000",
		"",
		0,
	)
	if op.Sender == "" {
		t.Error("expected sender")
	}
	if !strings.HasPrefix(op.CallData, "0x") {
		t.Error("expected 0x-prefixed calldata")
	}
}

// TestHashUserOp verifies ERC-4337 userOpHash is 32 bytes and deterministic.
func TestHashUserOp(t *testing.T) {
	op := BuildUserOp(
		"0xEAbCC110fAcBfebabC66Ad6f9E7B67288e720B59",
		"0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552",
		"0",
		"",
		42,
	)
	hash1, err := HashUserOp(op, EntrypointV06, 1)
	if err != nil {
		t.Fatalf("HashUserOp: %v", err)
	}
	if len(hash1) != 32 {
		t.Errorf("expected 32-byte hash, got %d", len(hash1))
	}
	hash2, _ := HashUserOp(op, EntrypointV06, 1)
	if hex.EncodeToString(hash1) != hex.EncodeToString(hash2) {
		t.Error("hash not deterministic")
	}
}

// TestEncodeInitCode verifies the ERC-4337 initCode format.
func TestEncodeInitCode(t *testing.T) {
	cfg := AccountConfig{
		FactoryAddress: "0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2",
		OwnerAddress:   "0xEAbCC110fAcBfebabC66Ad6f9E7B67288e720B59",
		Salt:           "0x0",
	}
	initCode, err := EncodeInitCode(cfg)
	if err != nil {
		t.Fatalf("EncodeInitCode: %v", err)
	}
	// First 20 bytes = factory address
	if len(initCode) < 20 {
		t.Fatalf("initCode too short: %d bytes", len(initCode))
	}
	gotFactory := "0x" + hex.EncodeToString(initCode[:20])
	wantFactory := strings.ToLower(cfg.FactoryAddress)
	if strings.ToLower(gotFactory) != wantFactory {
		t.Errorf("factory mismatch: got %s want %s", gotFactory, wantFactory)
	}
	// Bytes 20+ = createAccount selector + params
	remaining := initCode[20:]
	wantSel := abiSelector("createAccount(address,uint256)")
	if len(remaining) < 4 || hex.EncodeToString(remaining[:4]) != hex.EncodeToString(wantSel) {
		t.Errorf("wrong createAccount selector: got %x want %x", remaining[:4], wantSel)
	}
}
