// Package integrity provides Ed25519 signature verification for MPC binaries
// and configuration files. This prevents code injection via compromised S3
// buckets or supply-chain attacks on binary distribution.
package integrity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
)

// TrustedSigningKeys contains the Ed25519 public keys authorized to sign MPC
// binaries. The binary signature file (<binary>.sig) must be verifiable by at
// least one of these keys. Keys are hex-encoded 32-byte Ed25519 public keys.
//
// These are baked into the binary at compile time. To rotate, update this list
// and rebuild. The old key should be kept for one release cycle to allow
// rollback.
var TrustedSigningKeys []ed25519.PublicKey

// SetTrustedKeys sets the signing keys. Called from main() with keys loaded
// from config or hardcoded.
func SetTrustedKeys(hexKeys []string) error {
	TrustedSigningKeys = nil
	for _, h := range hexKeys {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != ed25519.PublicKeySize {
			return fmt.Errorf("invalid signing key: %s", h)
		}
		TrustedSigningKeys = append(TrustedSigningKeys, ed25519.PublicKey(b))
	}
	return nil
}

// VerifyFile checks that a file's Ed25519 signature is valid against at least
// one trusted signing key. The signature file must exist at <path>.sig and
// contain a hex-encoded 64-byte Ed25519 signature of SHA-256(file contents).
func VerifyFile(path string) error {
	if len(TrustedSigningKeys) == 0 {
		return fmt.Errorf("no trusted signing keys configured")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	sigHex, err := os.ReadFile(path + ".sig")
	if err != nil {
		return fmt.Errorf("read signature file %s.sig: %w", path, err)
	}

	sig, err := hex.DecodeString(string(sigHex))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature format in %s.sig", path)
	}

	hash := sha256.Sum256(data)

	for _, key := range TrustedSigningKeys {
		if ed25519.Verify(key, hash[:], sig) {
			return nil
		}
	}

	return fmt.Errorf("signature verification failed: no trusted key signed %s", path)
}

// HashFile returns the hex-encoded SHA-256 hash of a file.
func HashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

// SignFile creates a signature file for the given path using the provided
// Ed25519 private key. The signature covers SHA-256(file contents).
func SignFile(path string, privKey ed25519.PrivateKey) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}
	hash := sha256.Sum256(data)
	sig := ed25519.Sign(privKey, hash[:])
	return os.WriteFile(path+".sig", []byte(hex.EncodeToString(sig)), 0644)
}
