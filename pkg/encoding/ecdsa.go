package encoding

import (
	"crypto/ecdsa"
)

// EncodeS256PubKey encodes an ECDSA public key to 64 bytes (32 bytes X + 32 bytes Y).
// This uses fixed-size encoding to avoid ambiguity when X or Y have leading zeros.
func EncodeS256PubKey(pubKey *ecdsa.PublicKey) ([]byte, error) {
	// Secp256k1 coordinates are 32 bytes each
	const coordSize = 32

	publicKeyBytes := make([]byte, coordSize*2)

	// Pad X to 32 bytes (right-aligned)
	xBytes := pubKey.X.Bytes()
	copy(publicKeyBytes[coordSize-len(xBytes):coordSize], xBytes)

	// Pad Y to 32 bytes (right-aligned)
	yBytes := pubKey.Y.Bytes()
	copy(publicKeyBytes[coordSize*2-len(yBytes):], yBytes)

	return publicKeyBytes, nil
}
