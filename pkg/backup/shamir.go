package backup

// Shamir Secret Sharing over GF(2^8) for wallet backup key splitting.
//
// Default: 2-of-2 (iCloud Shard A + Platform HSM Shard B).
// Supports arbitrary T-of-N configurations for institutional custody.
//
// Uses the AES irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11b).

import (
	"crypto/rand"
	"errors"
	"fmt"
)

// Share is a single Shamir share: an evaluation of the secret polynomial at point Index.
type Share struct {
	Index byte   `json:"index"` // x-coordinate (1-based, never 0)
	Data  []byte `json:"data"`  // y-coordinates (one per secret byte)
}

// ShamirSplit splits secret into n shares, requiring threshold to reconstruct.
// threshold must be >= 2 and <= n. n must be <= 255.
func ShamirSplit(secret []byte, n, threshold int) ([]Share, error) {
	if len(secret) == 0 {
		return nil, errors.New("shamir: secret must not be empty")
	}
	if threshold < 2 {
		return nil, errors.New("shamir: threshold must be >= 2")
	}
	if n < threshold {
		return nil, errors.New("shamir: n must be >= threshold")
	}
	if n > 255 {
		return nil, errors.New("shamir: n must be <= 255")
	}

	shares := make([]Share, n)
	for i := range shares {
		shares[i] = Share{
			Index: byte(i + 1),
			Data:  make([]byte, len(secret)),
		}
	}

	// For each byte of the secret, create a random polynomial of degree (threshold-1)
	// with the secret byte as the constant term, then evaluate at points 1..n.
	coeffs := make([]byte, threshold)
	for byteIdx := 0; byteIdx < len(secret); byteIdx++ {
		// coeffs[0] = secret byte, rest are random
		coeffs[0] = secret[byteIdx]
		if _, err := rand.Read(coeffs[1:]); err != nil {
			return nil, fmt.Errorf("shamir: random generation failed: %w", err)
		}

		for i := 0; i < n; i++ {
			x := byte(i + 1)
			shares[i].Data[byteIdx] = gf256Eval(coeffs, x)
		}
	}

	return shares, nil
}

// ShamirCombine reconstructs the secret from threshold-or-more shares.
// Shares must have consistent Data lengths.
func ShamirCombine(shares []Share) ([]byte, error) {
	if len(shares) < 2 {
		return nil, errors.New("shamir: need at least 2 shares")
	}

	secretLen := len(shares[0].Data)
	for _, s := range shares {
		if len(s.Data) != secretLen {
			return nil, errors.New("shamir: all shares must have the same data length")
		}
	}

	// Check for duplicate indices
	seen := make(map[byte]bool, len(shares))
	for _, s := range shares {
		if s.Index == 0 {
			return nil, errors.New("shamir: share index must not be 0")
		}
		if seen[s.Index] {
			return nil, fmt.Errorf("shamir: duplicate share index %d", s.Index)
		}
		seen[s.Index] = true
	}

	// Lagrange interpolation at x=0 for each byte position
	secret := make([]byte, secretLen)
	for byteIdx := 0; byteIdx < secretLen; byteIdx++ {
		secret[byteIdx] = gf256Interpolate(shares, byteIdx)
	}

	return secret, nil
}

// gf256Eval evaluates polynomial coeffs[0] + coeffs[1]*x + coeffs[2]*x^2 + ...
// at the given point in GF(2^8).
func gf256Eval(coeffs []byte, x byte) byte {
	// Horner's method
	result := byte(0)
	for i := len(coeffs) - 1; i >= 0; i-- {
		result = gf256Add(gf256Mul(result, x), coeffs[i])
	}
	return result
}

// gf256Interpolate performs Lagrange interpolation at x=0 for a single byte position.
func gf256Interpolate(shares []Share, byteIdx int) byte {
	result := byte(0)
	n := len(shares)

	for i := 0; i < n; i++ {
		xi := shares[i].Index
		yi := shares[i].Data[byteIdx]

		// Compute Lagrange basis polynomial L_i(0)
		// L_i(0) = product over j!=i of (0 - x_j) / (x_i - x_j)
		//         = product over j!=i of x_j / (x_i - x_j)
		//         (in GF(2^8), subtraction == addition == XOR)
		num := byte(1)
		den := byte(1)
		for j := 0; j < n; j++ {
			if i == j {
				continue
			}
			xj := shares[j].Index
			num = gf256Mul(num, xj)
			den = gf256Mul(den, gf256Add(xi, xj))
		}

		// L_i(0) = num / den = num * den^(-1)
		lagrange := gf256Mul(num, gf256Inv(den))
		result = gf256Add(result, gf256Mul(yi, lagrange))
	}

	return result
}

// --- GF(2^8) arithmetic using AES polynomial (0x11b) ---

// gf256Add is addition in GF(2^8), which is XOR.
func gf256Add(a, b byte) byte {
	return a ^ b
}

// gf256Mul is multiplication in GF(2^8) using the AES polynomial.
func gf256Mul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gf256ExpTable[(int(gf256LogTable[a])+int(gf256LogTable[b]))%255]
}

// gf256Inv returns the multiplicative inverse in GF(2^8).
func gf256Inv(a byte) byte {
	if a == 0 {
		// Should never happen in well-formed shares.
		panic("shamir: division by zero in GF(2^8)")
	}
	return gf256ExpTable[255-int(gf256LogTable[a])]
}

// Log and exp tables for GF(2^8) with generator 3 and AES polynomial 0x11b.
var gf256LogTable [256]byte
var gf256ExpTable [256]byte

func init() {
	// Build log/exp tables using generator g=3 under polynomial 0x11b.
	x := 1
	for i := 0; i < 255; i++ {
		gf256ExpTable[i] = byte(x)
		gf256LogTable[x] = byte(i)
		x = gf256MulNoTable(x, 3)
	}
	// gf256LogTable[0] is unused (log(0) is undefined); leave as 0.
	// gf256ExpTable[255] wraps to gf256ExpTable[0] so that
	// gf256Inv(1) = gf256ExpTable[255 - log(1)] = gf256ExpTable[255] = 1.
	gf256ExpTable[255] = gf256ExpTable[0]
}

// gf256MulNoTable performs carry-less multiplication mod 0x11b without tables.
// Used only during init to build the tables.
func gf256MulNoTable(a, b int) int {
	p := 0
	for b > 0 {
		if b&1 != 0 {
			p ^= a
		}
		a <<= 1
		if a&0x100 != 0 {
			a ^= 0x11b
		}
		b >>= 1
	}
	return p
}
