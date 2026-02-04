package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

// EncryptAESGCM encrypts plaintext using AES-GCM.
// Key must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256.
func EncryptAESGCM(plain, key []byte) (ciphertext, nonce []byte, err error) {
	// Validate key length for AES
	switch len(key) {
	case 16, 24, 32:
		// Valid AES key sizes
	default:
		return nil, nil, fmt.Errorf("invalid AES key length: %d (must be 16, 24, or 32 bytes)", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = aead.Seal(nil, nonce, plain, nil)
	return ciphertext, nonce, nil
}

// DecryptAESGCM decrypts ciphertext using AES-GCM.
// Key must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256.
func DecryptAESGCM(ciphertext, key, nonce []byte) ([]byte, error) {
	// Validate key length for AES
	switch len(key) {
	case 16, 24, 32:
		// Valid AES key sizes
	default:
		return nil, fmt.Errorf("invalid AES key length: %d (must be 16, 24, or 32 bytes)", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, nil)
}
