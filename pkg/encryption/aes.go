package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

// EncryptAESGCM encrypts plaintext using AES-GCM with optional context-binding AAD.
// Key must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256.
// The aad parameter binds the ciphertext to a context (e.g. wallet_id or key path),
// preventing cross-context ciphertext transplant attacks. Pass nil for no AAD
// (backward compatible, but not recommended for new callers).
func EncryptAESGCM(plain, key []byte, aad ...[]byte) (ciphertext, nonce []byte, err error) {
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
	var additionalData []byte
	if len(aad) > 0 {
		additionalData = aad[0]
	}
	ciphertext = aead.Seal(nil, nonce, plain, additionalData)
	return ciphertext, nonce, nil
}

// DecryptAESGCM decrypts ciphertext using AES-GCM with optional context-binding AAD.
// Key must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256.
// The aad parameter must match the AAD used during encryption; mismatched AAD
// causes authentication failure, preventing cross-context transplant attacks.
func DecryptAESGCM(ciphertext, key, nonce []byte, aad ...[]byte) ([]byte, error) {
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
	var additionalData []byte
	if len(aad) > 0 {
		additionalData = aad[0]
	}
	return aead.Open(nil, nonce, ciphertext, additionalData)
}
