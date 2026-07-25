package protocol

import (
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/sample"
)

// CurvePoint and PublicKey must be exact inverses. Every signature
// verification in the adapters goes through CurvePoint, so a conversion that
// lands on the sibling point (wrong Y) makes every valid signature look
// invalid, and a conversion that silently truncates X makes some keys
// unverifiable at random.
func TestCurvePointPublicKeyRoundTrip(t *testing.T) {
	group := curve.Secp256k1{}

	sawEven, sawOdd := false, false
	for i := 0; i < 512; i++ {
		want := sample.Scalar(rand.Reader, group).ActOnBase()

		pub := PublicKey(want)
		if pub == nil {
			t.Fatalf("iteration %d: PublicKey returned nil for a valid point", i)
		}
		if pub.X == nil || pub.Y == nil {
			t.Fatalf("iteration %d: PublicKey returned an incomplete key", i)
		}

		got := CurvePoint(pub)
		if got == nil {
			t.Fatalf("iteration %d: CurvePoint returned nil for a valid key", i)
		}
		if !got.Equal(want) {
			t.Fatalf("iteration %d: round-trip landed on a different point", i)
		}

		// The recovered Y must actually satisfy the curve equation, not just
		// round-trip through our own encoder.
		if !onSecp256k1(pub.X, pub.Y) {
			t.Fatalf("iteration %d: recovered (X,Y) is not on secp256k1", i)
		}

		if pub.Y.Bit(0) == 0 {
			sawEven = true
		} else {
			sawOdd = true
		}
	}
	if !sawEven || !sawOdd {
		t.Fatalf("did not exercise both Y parities (even=%v odd=%v)", sawEven, sawOdd)
	}
}

// A key whose X has leading zero bytes must still convert. big.Int.Bytes()
// drops them, which would produce a 32-byte-short compressed encoding and a
// nil point for roughly one key in 256 — a failure that only shows up in
// production, on one wallet, with no obvious cause.
func TestCurvePointHandlesShortX(t *testing.T) {
	group := curve.Secp256k1{}

	for i := 0; i < 4096; i++ {
		point := sample.Scalar(rand.Reader, group).ActOnBase()
		pub := PublicKey(point)
		if pub == nil {
			t.Fatalf("iteration %d: PublicKey returned nil", i)
		}
		if pub.X.BitLen() > 248 {
			continue // not a short-X key; keep looking
		}
		// Found one: X fits in fewer than 31 bytes.
		got := CurvePoint(pub)
		if got == nil || !got.Equal(point) {
			t.Fatalf("short-X key (X bitlen %d) failed to convert", pub.X.BitLen())
		}
		return
	}
	t.Skip("no short-X key drawn in 4096 samples; the padding path is covered by the round-trip test")
}

func TestCurvePointRejectsInvalidKeys(t *testing.T) {
	for _, tc := range []struct {
		name string
		pub  *ecdsa.PublicKey
	}{
		{"nil key", nil},
		{"nil X", &ecdsa.PublicKey{Y: big.NewInt(1)}},
		{"nil Y", &ecdsa.PublicKey{X: big.NewInt(1)}},
		{"point at infinity", &ecdsa.PublicKey{X: big.NewInt(0), Y: big.NewInt(0)}},
		{"X not on curve", &ecdsa.PublicKey{X: big.NewInt(1), Y: big.NewInt(1)}},
		{"X oversized", &ecdsa.PublicKey{X: new(big.Int).Lsh(big.NewInt(1), 300), Y: big.NewInt(1)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := CurvePoint(tc.pub); got != nil {
				t.Fatalf("CurvePoint accepted an invalid key, returned %v", got)
			}
		})
	}
}

func TestPublicKeyRejectsIdentity(t *testing.T) {
	if got := PublicKey(curve.Secp256k1{}.NewPoint()); got != nil {
		t.Fatal("PublicKey accepted the identity point")
	}
	if got := PublicKey(nil); got != nil {
		t.Fatal("PublicKey accepted a nil point")
	}
}

// onSecp256k1 checks y^2 == x^3 + 7 (mod p) independently of the conversion
// code under test.
func onSecp256k1(x, y *big.Int) bool {
	p, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	lhs := new(big.Int).Mul(y, y)
	lhs.Mod(lhs, p)
	rhs := new(big.Int).Mul(x, x)
	rhs.Mod(rhs, p)
	rhs.Mul(rhs, x)
	rhs.Mod(rhs, p)
	rhs.Add(rhs, big.NewInt(7))
	rhs.Mod(rhs, p)
	return lhs.Cmp(rhs) == 0
}

// An (X, Y) pair that is not on the curve must be rejected outright. X=1 is a
// valid X coordinate on secp256k1 (y^2 = 8 is a quadratic residue), so a
// conversion that keeps only X and the parity of Y would happily "correct"
// (1, 1) into the real point at X=1 and verify signatures against a key the
// caller never named. This pins the rejection.
func TestCurvePointRejectsInconsistentY(t *testing.T) {
	group := curve.Secp256k1{}
	point := sample.Scalar(rand.Reader, group).ActOnBase()
	good := PublicKey(point)
	if good == nil {
		t.Fatal("PublicKey returned nil for a valid point")
	}

	// Same X, a Y that is not the curve's Y (nor its negation): same parity,
	// wrong value.
	badY := new(big.Int).Add(good.Y, big.NewInt(2))
	badY.Mod(badY, secp256k1P)
	bad := &ecdsa.PublicKey{Curve: good.Curve, X: new(big.Int).Set(good.X), Y: badY}
	if onCurve(bad.X, bad.Y) {
		t.Skip("perturbed Y landed back on the curve; rerun")
	}
	if got := CurvePoint(bad); got != nil {
		t.Fatal("CurvePoint accepted an (X,Y) that is not on the curve — it substituted a valid point")
	}

	// The real key still converts.
	if got := CurvePoint(good); got == nil || !got.Equal(point) {
		t.Fatal("CurvePoint rejected a valid key")
	}
}
