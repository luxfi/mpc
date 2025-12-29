package approval

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	dcrec "github.com/decred/dcrd/dcrec/secp256k1/v4"
	dcrecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// The fake ledgerctl binary is the test binary itself, re-invoked with
// MPC_FAKE_LEDGERCTL=1. This is the standard Go pattern (os.Args[0]
// trick) — keeps the test self-contained, no external interpreter or
// build step required.
//
// TestMain hands off to fakeLedgerctlMain when the env var is set;
// otherwise it falls through to the regular test runner.

func TestMain(m *testing.M) {
	if os.Getenv("MPC_FAKE_LEDGERCTL") == "1" {
		fakeLedgerctlMain()
		return
	}
	os.Exit(m.Run())
}

func fakeLedgerctlMain() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "fakeledgerctl: missing verb")
		os.Exit(2)
	}
	verb := os.Args[1]
	privHex := os.Getenv("MPC_FAKE_LEDGERCTL_PRIV")
	pubHex := os.Getenv("MPC_FAKE_LEDGERCTL_PUB")

	switch {
	case strings.HasSuffix(verb, "-get-pubkey"):
		fmt.Print(pubHex)
	case strings.HasSuffix(verb, "-sign-hash"):
		raw, _ := io.ReadAll(os.Stdin)
		digestHex := strings.TrimSpace(string(raw))
		digest, err := hex.DecodeString(digestHex)
		if err != nil {
			fmt.Fprintln(os.Stderr, "fakeledgerctl: hex decode:", err)
			os.Exit(2)
		}
		privBytes, err := hex.DecodeString(privHex)
		if err != nil {
			fmt.Fprintln(os.Stderr, "fakeledgerctl: priv hex:", err)
			os.Exit(2)
		}
		priv := dcrec.PrivKeyFromBytes(privBytes)
		sig := dcrecdsa.Sign(priv, digest)
		fmt.Print(hex.EncodeToString(sig.Serialize()))
	default:
		fmt.Fprintln(os.Stderr, "fakeledgerctl: unknown verb", verb)
		os.Exit(2)
	}
	os.Exit(0)
}

// installFakeLedgerctl writes a wrapper script that invokes the test
// binary with MPC_FAKE_LEDGERCTL=1, propagating the configured
// secp256k1 keypair via env. Returns the wrapper path.
func installFakeLedgerctl(t *testing.T, priv *dcrec.PrivateKey) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake ledgerctl wrapper script is POSIX-shell only")
	}

	dir := t.TempDir()
	tool := filepath.Join(dir, "ledgerctl")

	pubHex := hex.EncodeToString(priv.PubKey().SerializeCompressed())
	privHex := hex.EncodeToString(priv.Serialize())

	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	script := fmt.Sprintf(`#!/usr/bin/env sh
exec env \
  MPC_FAKE_LEDGERCTL=1 \
  MPC_FAKE_LEDGERCTL_PRIV=%s \
  MPC_FAKE_LEDGERCTL_PUB=%s \
  %q "$@"
`, privHex, pubHex, self)

	if err := os.WriteFile(tool, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return tool
}

func TestLedgerDevice_ProviderName(t *testing.T) {
	p, err := NewLedgerDevice(map[string]string{
		"ledgerctl_path": "/nonexistent/ledgerctl",
		"app":            "ethereum",
		"bip32_path":     "m/44'/60'/0'/0/0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := p.Provider(), "ledger-device"; got != want {
		t.Fatalf("Provider() = %q, want %q", got, want)
	}
}

func TestLedgerDevice_DefaultPath(t *testing.T) {
	p, err := NewLedgerDevice(nil)
	if err != nil {
		t.Fatal(err)
	}
	dev := p.(*LedgerDeviceProvider)
	if want := "m/44'/9000'/0'/0/0"; dev.configPath != want {
		t.Fatalf("default path = %q, want %q", dev.configPath, want)
	}
	if dev.app != "ethereum" {
		t.Fatalf("default app = %q, want ethereum", dev.app)
	}
	if dev.signAction != "ethereum-sign-hash" {
		t.Fatalf("default signAction = %q", dev.signAction)
	}
}

func TestLedgerDevice_NormalizeSig(t *testing.T) {
	// 64-byte raw r||s → DER round-trips.
	priv, err := dcrec.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("hello"))
	sig := dcrecdsa.Sign(priv, digest[:])
	der := sig.Serialize()
	raw, err := ecdsaASN1ToRaw(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 64 {
		t.Fatalf("raw length %d, want 64", len(raw))
	}
	der2, err := normalizeSecp256k1Sig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(der2) < 8 || der2[0] != 0x30 {
		t.Fatalf("expected ASN.1 SEQUENCE, got %x", der2)
	}
	// 65-byte recoverable (raw + v): DER from same raw matches.
	recov := append(append([]byte{}, raw...), 0x1c)
	der3, err := normalizeSecp256k1Sig(recov)
	if err != nil {
		t.Fatal(err)
	}
	if string(der2) != string(der3) {
		t.Fatal("64-byte and 65-byte normalization should match (v dropped)")
	}
}

func TestLedgerDevice_NormalizeSig_RejectsEmpty(t *testing.T) {
	if _, err := normalizeSecp256k1Sig(nil); err == nil {
		t.Fatal("normalizeSecp256k1Sig(nil) returned nil err")
	}
}

func TestLedgerDevice_VerifyApproval_RejectsWrongProvider(t *testing.T) {
	p, _ := NewLedgerDevice(nil)
	intent := newTestIntent("hello")
	ok, err := p.VerifyApproval(context.Background(), intent, ApprovalSignature{
		Provider:     "not-ledger-device",
		Algorithm:    AlgorithmECDSAsecp256k1,
		IntentDigest: intent.Digest(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("verified signature with wrong provider claim")
	}
}

func TestLedgerDevice_VerifyApproval_RejectsWrongAlgo(t *testing.T) {
	p, _ := NewLedgerDevice(nil)
	intent := newTestIntent("hello")
	ok, err := p.VerifyApproval(context.Background(), intent, ApprovalSignature{
		Provider:     "ledger-device",
		Algorithm:    AlgorithmEd25519,
		IntentDigest: intent.Digest(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("verified signature with wrong algorithm")
	}
}

func TestLedgerDevice_VerifyApproval_VerifiesEnrolledKey(t *testing.T) {
	p, _ := NewLedgerDevice(nil)
	dev := p.(*LedgerDeviceProvider)

	priv, _ := dcrec.GeneratePrivateKey()
	if err := dev.Enroll(context.Background(), "alice", "m/44'/60'/0'/0/0", priv.PubKey().SerializeCompressed()); err != nil {
		t.Fatal(err)
	}

	intent := newTestIntent("real intent")
	digest := intent.Digest()
	sig := dcrecdsa.Sign(priv, digest[:])

	// Verify legit signature passes.
	ok, err := p.VerifyApproval(context.Background(), intent, ApprovalSignature{
		ApproverID:   "alice",
		Provider:     "ledger-device",
		Algorithm:    AlgorithmECDSAsecp256k1,
		IntentDigest: digest,
		Signature:    sig.Serialize(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("legitimate signature did not verify")
	}
}

func TestLedgerDevice_VerifyApproval_RejectsTamperedDigest(t *testing.T) {
	p, _ := NewLedgerDevice(nil)
	dev := p.(*LedgerDeviceProvider)

	priv, _ := dcrec.GeneratePrivateKey()
	if err := dev.Enroll(context.Background(), "alice", "m/44'/60'/0'/0/0", priv.PubKey().SerializeCompressed()); err != nil {
		t.Fatal(err)
	}

	intent := newTestIntent("real intent")
	digest := intent.Digest()
	sig := dcrecdsa.Sign(priv, digest[:])

	// Tamper with the digest claim — verify must fail.
	tamperedDigest := sha256.Sum256([]byte("tampered"))
	ok, err := p.VerifyApproval(context.Background(), intent, ApprovalSignature{
		ApproverID:   "alice",
		Provider:     "ledger-device",
		Algorithm:    AlgorithmECDSAsecp256k1,
		IntentDigest: tamperedDigest,
		Signature:    sig.Serialize(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("verified signature whose digest claim does not match the intent digest")
	}
}

func TestLedgerDevice_VerifyApproval_RejectsUnknownApprover(t *testing.T) {
	p, _ := NewLedgerDevice(nil)
	intent := newTestIntent("hello")
	priv, _ := dcrec.GeneratePrivateKey()
	digest := intent.Digest()
	sig := dcrecdsa.Sign(priv, digest[:])

	// Approver was never enrolled — verify must fail.
	ok, err := p.VerifyApproval(context.Background(), intent, ApprovalSignature{
		ApproverID:   "ghost",
		Provider:     "ledger-device",
		Algorithm:    AlgorithmECDSAsecp256k1,
		IntentDigest: digest,
		Signature:    sig.Serialize(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("verified signature for unenrolled approver")
	}
}

func TestLedgerDevice_FullCeremony_FakeLedger(t *testing.T) {
	// Skip if /bin/sh is unavailable (Windows); installFakeLedgerctl
	// already skips Windows itself.
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no /bin/sh available")
	}

	priv, err := dcrec.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	tool := installFakeLedgerctl(t, priv)

	p, err := NewLedgerDevice(map[string]string{
		"ledgerctl_path": tool,
		"app":            "ethereum",
		"bip32_path":     "m/44'/60'/0'/0/0",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Auto-enroll on first GetPublicIdentity.
	id, err := p.GetPublicIdentity(context.Background(), "alice")
	if err != nil {
		t.Fatalf("GetPublicIdentity: %v", err)
	}
	if id.Algorithm != AlgorithmECDSAsecp256k1 {
		t.Fatalf("Algorithm = %q", id.Algorithm)
	}
	want := priv.PubKey().SerializeCompressed()
	if string(id.PublicKey) != string(want) {
		t.Fatalf("pubkey mismatch:\n  got  %x\n  want %x", id.PublicKey, want)
	}

	intent := newTestIntent("transfer 50 hanzo to alice")
	sig, err := p.ApproveIntent(context.Background(), "alice", intent)
	if err != nil {
		t.Fatalf("ApproveIntent: %v", err)
	}
	if sig.ApproverID != "alice" {
		t.Fatalf("ApproverID = %q", sig.ApproverID)
	}
	if sig.IntentDigest != intent.Digest() {
		t.Fatal("IntentDigest mismatch")
	}
	if sig.Provider != "ledger-device" {
		t.Fatalf("Provider = %q", sig.Provider)
	}
	if sig.Algorithm != AlgorithmECDSAsecp256k1 {
		t.Fatalf("Algorithm = %q", sig.Algorithm)
	}

	ok, err := p.VerifyApproval(context.Background(), intent, sig)
	if err != nil {
		t.Fatalf("VerifyApproval: %v", err)
	}
	if !ok {
		t.Fatal("VerifyApproval = false on freshly-issued signature")
	}

	// Tamper with the intent — verification must fail.
	tampered := newTestIntent("transfer 5000 hanzo to attacker")
	ok, err = p.VerifyApproval(context.Background(), tampered, sig)
	if err != nil {
		t.Fatalf("VerifyApproval tampered: %v", err)
	}
	if ok {
		t.Fatal("VerifyApproval(tampered) = true")
	}
}
