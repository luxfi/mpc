package smart

import (
	"hash"

	"golang.org/x/crypto/sha3"
)

// newKeccak256 returns a new legacy Keccak-256 hasher (Ethereum-compatible).
func newKeccak256() hash.Hash {
	return sha3.NewLegacyKeccak256()
}
