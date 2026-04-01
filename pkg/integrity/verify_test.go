package integrity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyFile_ValidSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	binPath := filepath.Join(dir, "mpcd")
	content := []byte("binary-content-here")
	if err := os.WriteFile(binPath, content, 0644); err != nil {
		t.Fatal(err)
	}
	if err := SignFile(binPath, priv); err != nil {
		t.Fatal(err)
	}

	if err := SetTrustedKeys([]string{hex.EncodeToString(pub)}); err != nil {
		t.Fatal(err)
	}

	if err := VerifyFile(binPath); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
}

func TestVerifyFile_TamperedBinary(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	binPath := filepath.Join(dir, "mpcd")

	os.WriteFile(binPath, []byte("original"), 0644)
	SignFile(binPath, priv)

	// Tamper with the binary after signing
	os.WriteFile(binPath, []byte("tampered"), 0644)

	SetTrustedKeys([]string{hex.EncodeToString(pub)})
	if err := VerifyFile(binPath); err == nil {
		t.Fatal("tampered binary was accepted — O-1 regression")
	}
}

func TestVerifyFile_WrongKey(t *testing.T) {
	_, priv1, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	binPath := filepath.Join(dir, "mpcd")

	os.WriteFile(binPath, []byte("content"), 0644)
	SignFile(binPath, priv1)

	// Trust only key2, but signed with key1
	SetTrustedKeys([]string{hex.EncodeToString(pub2)})
	if err := VerifyFile(binPath); err == nil {
		t.Fatal("signature from untrusted key was accepted")
	}
}

func TestVerifyFile_NoSignatureFile(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	binPath := filepath.Join(dir, "mpcd")
	os.WriteFile(binPath, []byte("content"), 0644)

	SetTrustedKeys([]string{hex.EncodeToString(pub)})
	if err := VerifyFile(binPath); err == nil {
		t.Fatal("missing .sig file was not detected")
	}
}

func TestVerifyFile_NoTrustedKeys(t *testing.T) {
	TrustedSigningKeys = nil
	if err := VerifyFile("/nonexistent"); err == nil {
		t.Fatal("no trusted keys should fail")
	}
}

func TestHashFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test")
	content := []byte("test-content")
	os.WriteFile(path, content, 0644)

	got, err := HashFile(path)
	if err != nil {
		t.Fatal(err)
	}
	expected := sha256.Sum256(content)
	if got != hex.EncodeToString(expected[:]) {
		t.Fatalf("hash mismatch: got %s", got)
	}
}
