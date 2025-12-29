package approval

import (
	"context"
	"errors"
	"fmt"
)

// LedgerDeviceProvider would integrate a USB-connected Ledger Nano S/X via
// APDU (ISO 7816-4) over HID. The protocol shape is well-known:
//
//   CLA INS P1 P2 LC | data ... | LE
//
// For approval attestations, the Lux companion app exposes:
//
//   GET PUBLIC KEY       — CLA=0x80 INS=0x02 P1=0x00 P2=0x00 LC=0x14 data=BIP32 path
//   SIGN APPROVAL DIGEST — CLA=0x80 INS=0x04 P1=0x00 P2=0x00 LC=0x34 data=path||digest
//
// **Honest residual**: this build ships as NOTIMPL — we don't import a USB
// HID library here and we don't have a Lux companion app shipped to the
// Ledger registry yet. The right next step is:
//
//   1. ship the companion app (Rust, Ledger-NanoS BOLOS SDK)
//   2. import github.com/karalabe/hid (BSD-3) for cross-platform HID access
//   3. wrap APDU exchange + signing flow here
//
// Until then, NewLedgerDevice constructs a stub that always returns
// errNotImplemented from GetPublicIdentity / ApproveIntent. This keeps the
// factory consistent (you can configure "ledger-device" in the keyset) but
// every approval attempt explicitly fails.
//
// VerifyApproval is also NOTIMPL — there are no Ledger-device approvals to
// verify yet. When the companion app ships, signature format matches
// ECDSA-secp256k1 over SHA-256(digest) — same verifier path as the
// AWS-KMS / GCP-KMS providers with secp256k1 enrolled.
type LedgerDeviceProvider struct {
	configuredPath string // BIP32 path, currently unused (stub)
}

// NewLedgerDevice returns a stub provider. Configuration:
//
//   bip32_path — e.g. "m/44'/9000'/0'/0/0" for Lux approval keys
//
// Production deployment requires shipping the Lux Ledger companion app
// (Rust BOLOS SDK) and wiring github.com/karalabe/hid here. See provider doc.
func NewLedgerDevice(config map[string]string) (ApprovalProvider, error) {
	path := ""
	if config != nil {
		path = config["bip32_path"]
	}
	if path == "" {
		path = "m/44'/9000'/0'/0/0"
	}
	return &LedgerDeviceProvider{configuredPath: path}, nil
}

func (p *LedgerDeviceProvider) Provider() string { return "ledger-device" }

func (p *LedgerDeviceProvider) GetPublicIdentity(_ context.Context, _ string) (PublicIdentity, error) {
	return PublicIdentity{}, fmt.Errorf("approval/ledger-device: %w (companion app not yet shipped; see provider doc)", errNotImplemented)
}

func (p *LedgerDeviceProvider) ApproveIntent(_ context.Context, _ string, _ CanonicalIntent) (ApprovalSignature, error) {
	return ApprovalSignature{}, fmt.Errorf("approval/ledger-device: %w (companion app not yet shipped; see provider doc)", errNotImplemented)
}

func (p *LedgerDeviceProvider) VerifyApproval(_ context.Context, _ CanonicalIntent, _ ApprovalSignature) (bool, error) {
	// Refuse to verify rather than silently return false — a future build
	// must positively verify, never accept-by-omission.
	return false, errors.New("approval/ledger-device: VerifyApproval not implemented (companion app not shipped)")
}
