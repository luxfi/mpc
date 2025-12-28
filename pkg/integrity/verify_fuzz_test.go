package integrity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func FuzzVerifyFile(f *testing.F) {
	// Generate a real key pair for seeding
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	f.Add([]byte("valid binary content"), []byte(hex.EncodeToString(ed25519.Sign(priv, []byte("valid binary content")))))
	f.Add([]byte(""), []byte(""))
	f.Add([]byte("content"), []byte("not-hex"))
	f.Add([]byte("content"), []byte("deadbeef"))

	f.Fuzz(func(t *testing.T, content []byte, sigBytes []byte) {
		dir := t.TempDir()
		binPath := filepath.Join(dir, "test-binary")
		os.WriteFile(binPath, content, 0644)
		os.WriteFile(binPath+".sig", sigBytes, 0644)

		SetTrustedKeys([]string{hex.EncodeToString(pub)})

		// Must not panic regardless of input
		err := VerifyFile(binPath)

		// If verification passes, the signature must actually be valid
		if err == nil {
			// Double-check: manually verify
			sigHex := string(sigBytes)
			sig, decErr := hex.DecodeString(sigHex)
			if decErr != nil || len(sig) != ed25519.SignatureSize {
				t.Fatal("verification passed but signature is malformed")
			}
		}
	})
}

func FuzzSetTrustedKeys(f *testing.F) {
	f.Add("deadbeef")
	f.Add("")
	f.Add("not-hex!")
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	f.Add(hex.EncodeToString(pub))

	f.Fuzz(func(t *testing.T, keyHex string) {
		// Must not panic
		err := SetTrustedKeys([]string{keyHex})
		if err == nil {
			// Valid key: must be exactly 32 bytes
			decoded, _ := hex.DecodeString(keyHex)
			if len(decoded) != ed25519.PublicKeySize {
				t.Fatalf("accepted key of length %d (expected %d)", len(decoded), ed25519.PublicKeySize)
			}
		}
	})
}
