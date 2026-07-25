package protocol

import (
	"crypto/ecdsa"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/luxfi/threshold/pkg/math/curve"
)

// CurvePoint converts the *ecdsa.PublicKey that this package's interfaces
// carry into the curve.Point the threshold protocols verify against. It
// returns nil if the key is not a usable secp256k1 point.
//
// The conversion goes through the 33-byte compressed SEC1 encoding, which is
// what curve.Point unmarshals. Building it needs only X and the parity of Y —
// no modular square root — so there is no branch that can silently pick the
// wrong one of the two candidate points, which is the classic way a
// decompression helper ends up verifying against the sibling point and
// rejecting every valid signature.
//
// X is left-padded with FillBytes rather than Bytes: big.Int drops leading
// zero bytes, so an X below 2^248 (about one key in 256) would otherwise
// produce a short, unparseable encoding.
func CurvePoint(pub *ecdsa.PublicKey) curve.Point {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil
	}
	if pub.X.Sign() == 0 && pub.Y.Sign() == 0 {
		return nil // point at infinity has no signer
	}
	if pub.X.BitLen() > 256 || pub.Y.BitLen() > 256 {
		return nil
	}

	// The caller's Y must be the real Y for this X, not merely have the right
	// parity. Compression keeps only the parity, so without this check an
	// inconsistent (X, Y) would be silently "corrected" to a valid point —
	// and the signature would then be verified against a key the caller never
	// asked about. Rejecting is the only safe response to a malformed key.
	if !onCurve(pub.X, pub.Y) {
		return nil
	}

	compressed := make([]byte, 33)
	compressed[0] = 0x02 | byte(pub.Y.Bit(0)) // 0x02 even-Y, 0x03 odd-Y
	pub.X.FillBytes(compressed[1:])

	point := curve.Secp256k1{}.NewPoint()
	if err := point.UnmarshalBinary(compressed); err != nil {
		return nil
	}
	return point
}

// secp256k1P is the field prime; secp256k1 is y^2 = x^3 + 7 over it.
var secp256k1P, _ = new(big.Int).SetString(
	"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)

// onCurve reports whether (x, y) satisfies the secp256k1 curve equation.
func onCurve(x, y *big.Int) bool {
	if x.Sign() < 0 || y.Sign() < 0 || x.Cmp(secp256k1P) >= 0 || y.Cmp(secp256k1P) >= 0 {
		return false
	}
	lhs := new(big.Int).Mul(y, y)
	lhs.Mod(lhs, secp256k1P)

	rhs := new(big.Int).Mul(x, x)
	rhs.Mod(rhs, secp256k1P)
	rhs.Mul(rhs, x)
	rhs.Add(rhs, big.NewInt(7))
	rhs.Mod(rhs, secp256k1P)

	return lhs.Cmp(rhs) == 0
}

// PublicKey is the inverse of [CurvePoint]: it renders a secp256k1
// curve.Point as the *ecdsa.PublicKey this package's interfaces return.
// It returns nil for the identity point or a point it cannot decode.
func PublicKey(point curve.Point) *ecdsa.PublicKey {
	if point == nil || point.IsIdentity() {
		return nil
	}
	compressed, err := point.MarshalBinary()
	if err != nil || len(compressed) != 33 {
		return nil
	}

	// Recover Y by decompressing through the same secp256k1 implementation
	// the rest of the stack uses, rather than a hand-rolled Tonelli-Shanks.
	pub, err := secp256k1.ParsePubKey(compressed)
	if err != nil {
		return nil
	}
	uncompressed := pub.SerializeUncompressed() // 0x04 ‖ X(32) ‖ Y(32)
	if len(uncompressed) != 65 {
		return nil
	}
	return &ecdsa.PublicKey{
		Curve: secp256k1.S256(),
		X:     new(big.Int).SetBytes(uncompressed[1:33]),
		Y:     new(big.Int).SetBytes(uncompressed[33:]),
	}
}
