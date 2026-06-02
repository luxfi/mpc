package approval

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	dcrec "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// LedgerDeviceProvider integrates a USB-connected Ledger Nano (S Plus / X
// / Stax) for executive approvals. The provider does not link any USB or
// HID library directly — it shells out to the Ledger Live `ledgerctl`
// tool, which Ledger ships and which already owns the USB and per-app
// APDU surface for every Ledger app (ethereum, lux, bitcoin, solana,
// …). Operators install ledgerctl on the host, plug in the device,
// unlock it, and open the relevant app before approval ceremonies.
//
// One Ledger app, many chains. The Lux Ledger app firmware exposes two
// CLA bytes — 0x80 for native Lux operations, 0xE0 for EIP-155 EVM
// transactions — and the same hardware key signs Hanzo / Zoo / Pars
// transactions through the Ethereum-compat path (chain_id replay
// protection lives in the EIP-155 RLP body, not in the derivation
// path). See github.com/luxfi/ledger/docs/CHAIN_PATHS.md.
//
// Configuration:
//
//	ledgerctl_path  — path to ledgerctl (default "ledgerctl" on PATH)
//	app             — Ledger app name. Default "ethereum". Set to
//	                  "lux" for Lux native paths, "bitcoin" for BTC, etc.
//	bip32_path      — derivation path. Default m/44'/9000'/0'/0/0 (Lux
//	                  native). For EVM-compat use m/44'/60'/0'/0/0;
//	                  ledger.BIP44PathForName(...) builds this.
//	chain_id        — EIP-155 chain id forwarded to ledgerctl when app
//	                  is "ethereum". Optional.
//	sign_action     — override the verb passed to ledgerctl; defaults
//	                  to "{app}-sign-hash".
//	pubkey_action   — override the verb for fetching the device pubkey;
//	                  defaults to "{app}-get-pubkey".
//
// Verification: pubkeys returned by the device are parsed as compressed
// SEC1 secp256k1 (33 bytes). Approvals sign SHA-256(intent.Bytes())
// (the same value intent.Digest() returns) using ECDSA-secp256k1 and
// produce ASN.1-DER-encoded signatures, which ecdsa.VerifyASN1 accepts.
// If the device returns a 64-byte raw or 65-byte recoverable signature,
// ParseSignature normalizes it to ASN.1 DER before storing.
//
// Test discipline: the integration test in ledger_device_test.go
// substitutes a fake `ledgerctl` script that signs deterministically
// using a software key, exercising every code path end-to-end without
// hardware in CI.
type LedgerDeviceProvider struct {
	tool         string
	app          string
	configPath   string // BIP-32 derivation path (default for unenrolled approvers)
	chainID      uint64
	signAction   string
	pubkeyAction string

	mu       sync.RWMutex
	identity map[string]ledgerDeviceEntry
}

type ledgerDeviceEntry struct {
	BIP32Path string
	PubKey    *ecdsa.PublicKey
	PubKeyRaw []byte // compressed SEC1 (33 bytes), useful for audit logs
}

// NewLedgerDevice returns a LedgerDeviceProvider configured to shell out
// to ledgerctl. The provider does not validate that the tool exists at
// construction time — that check is performed lazily on first use, so
// dev / test workflows that don't exercise the device do not need
// ledgerctl installed.
func NewLedgerDevice(config map[string]string) (ApprovalProvider, error) {
	tool := "ledgerctl"
	app := "ethereum"
	path := "m/44'/9000'/0'/0/0"
	var chainID uint64
	var signAction, pubkeyAction string

	if config != nil {
		if v := strings.TrimSpace(config["ledgerctl_path"]); v != "" {
			tool = v
		}
		if v := strings.TrimSpace(config["app"]); v != "" {
			app = strings.ToLower(v)
		}
		if v := strings.TrimSpace(config["bip32_path"]); v != "" {
			path = v
		}
		if v := strings.TrimSpace(config["chain_id"]); v != "" {
			id, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("approval/ledger-device: parse chain_id: %w", err)
			}
			chainID = id
		}
		if v := strings.TrimSpace(config["sign_action"]); v != "" {
			signAction = v
		}
		if v := strings.TrimSpace(config["pubkey_action"]); v != "" {
			pubkeyAction = v
		}
	}
	if signAction == "" {
		signAction = app + "-sign-hash"
	}
	if pubkeyAction == "" {
		pubkeyAction = app + "-get-pubkey"
	}

	return &LedgerDeviceProvider{
		tool:         tool,
		app:          app,
		configPath:   path,
		chainID:      chainID,
		signAction:   signAction,
		pubkeyAction: pubkeyAction,
		identity:     make(map[string]ledgerDeviceEntry),
	}, nil
}

func (p *LedgerDeviceProvider) Provider() string { return "ledger-device" }

// Enroll pins (approverID -> bip32_path -> pubkey) before any approval.
// Production ceremonies enroll once via a controlled GetPublicIdentity
// call (operator confirms address on device); subsequent verifications
// match against the pinned key. A pubKey of nil triggers a live fetch
// from ledgerctl.
func (p *LedgerDeviceProvider) Enroll(ctx context.Context, approverID, bip32Path string, pubKeyCompressed []byte) error {
	if bip32Path == "" {
		bip32Path = p.configPath
	}
	if pubKeyCompressed == nil {
		raw, err := p.fetchPubKey(ctx, bip32Path)
		if err != nil {
			return err
		}
		pubKeyCompressed = raw
	}
	parsed, err := dcrec.ParsePubKey(pubKeyCompressed)
	if err != nil {
		return fmt.Errorf("approval/ledger-device: parse pubkey: %w", err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.identity[approverID] = ledgerDeviceEntry{
		BIP32Path: bip32Path,
		PubKey:    parsed.ToECDSA(),
		PubKeyRaw: append([]byte(nil), pubKeyCompressed...),
	}
	return nil
}

// GetPublicIdentity returns the pinned identity for approverID. If the
// approver is not yet enrolled, the provider fetches the pubkey live
// from the device (with operator confirmation) and pins it.
func (p *LedgerDeviceProvider) GetPublicIdentity(ctx context.Context, approverID string) (PublicIdentity, error) {
	p.mu.RLock()
	entry, ok := p.identity[approverID]
	p.mu.RUnlock()
	if !ok {
		// First-touch enrollment uses the provider-default path. This
		// is the standard ceremony: operator approves the address on
		// device, pubkey is pinned, future approvals verify against
		// the pin.
		if err := p.Enroll(ctx, approverID, p.configPath, nil); err != nil {
			return PublicIdentity{}, err
		}
		p.mu.RLock()
		entry = p.identity[approverID]
		p.mu.RUnlock()
	}
	return PublicIdentity{
		ApproverID: approverID,
		Provider:   p.Provider(),
		PublicKey:  entry.PubKeyRaw,
		Algorithm:  AlgorithmECDSAsecp256k1,
	}, nil
}

// ApproveIntent signs the canonical-intent digest via ledgerctl. The
// call blocks until the operator taps the device. The returned
// signature is ASN.1 DER (the form ecdsa.VerifyASN1 expects). If
// ledgerctl produces a 64-byte raw or 65-byte Ethereum recoverable
// signature, it is normalized to DER before returning.
func (p *LedgerDeviceProvider) ApproveIntent(ctx context.Context, approverID string, intent CanonicalIntent) (ApprovalSignature, error) {
	p.mu.RLock()
	entry, ok := p.identity[approverID]
	p.mu.RUnlock()
	if !ok {
		// Auto-enroll on first approval for symmetry with
		// GetPublicIdentity. Operator confirms address on device.
		if err := p.Enroll(ctx, approverID, p.configPath, nil); err != nil {
			return ApprovalSignature{}, err
		}
		p.mu.RLock()
		entry = p.identity[approverID]
		p.mu.RUnlock()
	}

	digest := intent.Digest()
	sigBytes, err := p.signDigest(ctx, entry.BIP32Path, digest[:])
	if err != nil {
		return ApprovalSignature{}, err
	}
	derSig, err := normalizeSecp256k1Sig(sigBytes)
	if err != nil {
		return ApprovalSignature{}, fmt.Errorf("approval/ledger-device: normalize signature: %w", err)
	}
	// Defense in depth: verify the signature locally against the pinned
	// pubkey before returning. A tampering ledgerctl wrapper that
	// returned a wrong signature would be caught here.
	if !ecdsa.VerifyASN1(entry.PubKey, digest[:], derSig) {
		return ApprovalSignature{}, errors.New("approval/ledger-device: device returned signature that does not verify against pinned pubkey")
	}
	return ApprovalSignature{
		ApproverID:   approverID,
		Provider:     p.Provider(),
		IntentDigest: digest,
		Signature:    derSig,
		Timestamp:    time.Now().UTC(),
		Algorithm:    AlgorithmECDSAsecp256k1,
	}, nil
}

// VerifyApproval checks (provider, algorithm, digest, pinned-pubkey,
// signature) — every gate must pass. Errors only on unrecoverable
// failures; signature mismatches are (false, nil).
func (p *LedgerDeviceProvider) VerifyApproval(_ context.Context, intent CanonicalIntent, sig ApprovalSignature) (bool, error) {
	if sig.Provider != p.Provider() {
		return false, nil
	}
	if sig.Algorithm != AlgorithmECDSAsecp256k1 {
		return false, nil
	}
	digest := intent.Digest()
	if digest != sig.IntentDigest {
		return false, nil
	}
	p.mu.RLock()
	entry, ok := p.identity[sig.ApproverID]
	p.mu.RUnlock()
	if !ok {
		// Refusing rather than silently failing: an approver we never
		// enrolled cannot have signed for us.
		return false, nil
	}
	if entry.PubKey == nil {
		return false, errors.New("approval/ledger-device: enrolled entry missing public key")
	}
	der, err := normalizeSecp256k1Sig(sig.Signature)
	if err != nil {
		return false, nil
	}
	return ecdsa.VerifyASN1(entry.PubKey, digest[:], der), nil
}

// fetchPubKey shells out to ledgerctl to get the compressed SEC1 pubkey
// for the given path. ledgerctl returns hex; we decode and validate
// the length (33 bytes compressed, 65 bytes uncompressed converted to
// compressed via dcrec.ParsePubKey).
func (p *LedgerDeviceProvider) fetchPubKey(ctx context.Context, path string) ([]byte, error) {
	if _, err := exec.LookPath(p.tool); err != nil {
		return nil, fmt.Errorf("approval/ledger-device: %s not found on PATH (install Ledger Live / ledgerctl)", p.tool)
	}
	args := []string{p.pubkeyAction, "--path", path, "--output-format", "hex"}
	cmd := exec.CommandContext(ctx, p.tool, args...)
	cmd.Stderr = os.Stderr
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("approval/ledger-device: %s failed: %w", p.pubkeyAction, err)
	}
	pkHex := strings.TrimSpace(out.String())
	if pkHex == "" {
		return nil, errors.New("approval/ledger-device: empty pubkey returned")
	}
	pk, err := hex.DecodeString(pkHex)
	if err != nil {
		return nil, fmt.Errorf("approval/ledger-device: decode pubkey hex: %w", err)
	}
	// Normalize uncompressed (65 bytes) to compressed (33 bytes) by
	// reparsing through dcrec — both pass through the same code path.
	parsed, err := dcrec.ParsePubKey(pk)
	if err != nil {
		return nil, fmt.Errorf("approval/ledger-device: invalid secp256k1 pubkey from device: %w", err)
	}
	return parsed.SerializeCompressed(), nil
}

// signDigest shells out to ledgerctl to sign a 32-byte digest. The
// device firmware shows the digest hex on screen and waits for the
// operator's tap.
func (p *LedgerDeviceProvider) signDigest(ctx context.Context, path string, digest []byte) ([]byte, error) {
	if len(digest) != sha256.Size {
		return nil, fmt.Errorf("approval/ledger-device: digest must be %d bytes, got %d", sha256.Size, len(digest))
	}
	if _, err := exec.LookPath(p.tool); err != nil {
		return nil, fmt.Errorf("approval/ledger-device: %s not found on PATH (install Ledger Live / ledgerctl)", p.tool)
	}
	args := []string{p.signAction,
		"--path", path,
		"--input-format", "hex",
		"--output-format", "hex",
	}
	if strings.EqualFold(p.app, "ethereum") && p.chainID != 0 {
		args = append(args, "--chain-id", fmt.Sprintf("%d", p.chainID))
	}
	cmd := exec.CommandContext(ctx, p.tool, args...)
	cmd.Stdin = strings.NewReader(hex.EncodeToString(digest))
	cmd.Stderr = os.Stderr
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("approval/ledger-device: %s failed: %w", p.signAction, err)
	}
	sigHex := strings.TrimSpace(out.String())
	if sigHex == "" {
		return nil, errors.New("approval/ledger-device: empty signature returned")
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return nil, fmt.Errorf("approval/ledger-device: decode signature hex: %w", err)
	}
	return sig, nil
}

// normalizeSecp256k1Sig accepts ASN.1 DER (typical cosmos / generic
// secp256k1 output), 64-byte raw r||s, or 65-byte Ethereum-style
// [r||s||v] recoverable signatures and returns ASN.1 DER for use with
// ecdsa.VerifyASN1.
func normalizeSecp256k1Sig(sig []byte) ([]byte, error) {
	switch len(sig) {
	case 0:
		return nil, errors.New("empty signature")
	case 64:
		return ecdsaRawToASN1secp256k1(sig)
	case 65:
		// Drop the recovery byte (last). Ethereum prepends or appends
		// v depending on tool; ledgerctl appends.
		return ecdsaRawToASN1secp256k1(sig[:64])
	default:
		// Assume DER; ecdsa.VerifyASN1 will reject malformed.
		return sig, nil
	}
}

// ecdsaRawToASN1secp256k1 mirrors ecdsaRawToASN1 (which assumes 32-byte
// scalars) but is named distinctly to make grep-ability obvious — the
// two curves happen to share the same scalar length but the helper is
// explicitly secp256k1 here.
func ecdsaRawToASN1secp256k1(raw []byte) ([]byte, error) {
	if len(raw) != 64 {
		return nil, fmt.Errorf("expected 64-byte r||s, got %d", len(raw))
	}
	r := new(big.Int).SetBytes(raw[:32])
	s := new(big.Int).SetBytes(raw[32:])
	return asn1MarshalRS(r, s)
}

// asn1MarshalRS encodes (r, s) as an ASN.1 SEQUENCE { INTEGER r, INTEGER s }
// matching the format ecdsa.VerifyASN1 expects.
func asn1MarshalRS(r, s *big.Int) ([]byte, error) {
	// Reuse the helper from ecdsa_helpers.go via the local ecdsaSig type.
	return marshalECDSASig(ecdsaSig{R: r, S: s})
}
