// Package smart provides Ethereum ABI encoding utilities for Safe and ERC-4337.
// Uses only luxfi/crypto — no go-ethereum or third-party ABI libraries.
package smart

import (
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"strings"
)

// abi32 left-pads b to 32 bytes (Ethereum ABI fixed slot).
func abi32(b []byte) []byte {
	slot := make([]byte, 32)
	if len(b) > 32 {
		copy(slot, b[len(b)-32:])
	} else {
		copy(slot[32-len(b):], b)
	}
	return slot
}

// abiAddress ABI-encodes a hex address (with or without 0x) as a 32-byte slot.
func abiAddress(addr string) []byte {
	addr = strings.TrimPrefix(addr, "0x")
	addr = strings.TrimPrefix(addr, "0X")
	if len(addr) < 40 {
		addr = strings.Repeat("0", 40-len(addr)) + addr
	}
	b, _ := hex.DecodeString(addr[len(addr)-40:])
	return abi32(b)
}

// abiUint256 ABI-encodes a *big.Int as a 32-byte slot.
func abiUint256(n *big.Int) []byte {
	if n == nil {
		return make([]byte, 32)
	}
	return abi32(n.Bytes())
}

// abiUint256Int ABI-encodes an int64 as a 32-byte slot.
func abiUint256Int(n int64) []byte {
	return abiUint256(big.NewInt(n))
}

// abiBytes32 ABI-encodes a 32-byte value as a 32-byte slot (right-pad with zeros).
func abiBytes32(b []byte) []byte {
	slot := make([]byte, 32)
	copy(slot, b)
	return slot
}

// abiDynBytes ABI-encodes a dynamic bytes value (length + data, right-padded to 32-byte boundary).
func abiDynBytes(data []byte) []byte {
	// length slot
	lenSlot := abiUint256(big.NewInt(int64(len(data))))
	// data padded to 32-byte multiple
	padLen := (len(data) + 31) &^ 31
	padded := make([]byte, padLen)
	copy(padded, data)
	return append(lenSlot, padded...)
}

// abiSelector returns the first 4 bytes of keccak256(signature).
func abiSelector(sig string) []byte {
	h := keccak256([]byte(sig))
	return h[:4]
}

// keccak256 computes keccak256 of data using golang.org/x/crypto/sha3.
func keccak256(data ...[]byte) []byte {
	// Import is handled via bridge in bridge.go (same package).
	// Implement directly using sha3.NewLegacyKeccak256 from x/crypto.
	h := newKeccak256()
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}

// abiEncodeAddressArray encodes a dynamic address[] value.
// Returns the head offset and tail data for embedding in a larger tuple.
func abiEncodeAddressArray(addrs []string) []byte {
	// length + each address
	out := abiUint256(big.NewInt(int64(len(addrs))))
	for _, a := range addrs {
		out = append(out, abiAddress(a)...)
	}
	return out
}

// encodeUint32BE encodes a uint32 as big-endian 4 bytes.
func encodeUint32BE(n uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, n)
	return b
}
