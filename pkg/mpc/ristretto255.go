package mpc

// Ristretto255 curve types implementing the threshold library's curve.Curve,
// curve.Scalar, and curve.Point interfaces. These enable the FROST protocol to
// operate over the ristretto255 prime-order group for sr25519 threshold signing.
//
// Once the threshold library publishes a version with native Ristretto255 support,
// this file can be removed and imports switched to the threshold library's types.

import (
	"fmt"
	"math/big"

	"github.com/cronokirby/saferith"
	r255 "github.com/gtank/ristretto255"
	"github.com/luxfi/threshold/pkg/math/curve"
)

// ristretto255Order is l = 2^252 + 27742317777372353535851937790883648493.
var ristretto255OrderBig = func() *big.Int {
	l := new(big.Int).SetInt64(1)
	l.Lsh(l, 252)
	delta, _ := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
	l.Add(l, delta)
	return l
}()

var ristretto255OrderNat = func() *saferith.Nat {
	b := ristretto255OrderBig.Bytes() // big-endian
	return new(saferith.Nat).SetBytes(b)
}()

var ristretto255Order = saferith.ModulusFromNat(ristretto255OrderNat)

// halfOrder for IsOverHalfOrder check.
var ristretto255HalfOrder = new(big.Int).Rsh(ristretto255OrderBig, 1)

// Ristretto255 implements curve.Curve for the ristretto255 prime-order group.
type Ristretto255 struct{}

func (Ristretto255) NewPoint() curve.Point {
	return &Ristretto255Point{value: r255.NewElement().Zero()}
}

func (Ristretto255) NewBasePoint() curve.Point {
	return &Ristretto255Point{value: r255.NewElement().Base()}
}

func (Ristretto255) NewScalar() curve.Scalar {
	return &Ristretto255Scalar{value: r255.NewScalar().Zero()}
}

func (Ristretto255) Name() string {
	return "ristretto255"
}

func (Ristretto255) ScalarBits() int {
	return 253
}

func (Ristretto255) SafeScalarBytes() int {
	return 32
}

func (Ristretto255) Order() *saferith.Modulus {
	return ristretto255Order
}

// --- Ristretto255Scalar ---

// Ristretto255Scalar implements curve.Scalar using ristretto255.Scalar.
type Ristretto255Scalar struct {
	value *r255.Scalar
}

func ristretto255CastScalar(generic curve.Scalar) *Ristretto255Scalar {
	out, ok := generic.(*Ristretto255Scalar)
	if !ok {
		panic(fmt.Sprintf("failed to convert to Ristretto255Scalar: %v", generic))
	}
	return out
}

func (*Ristretto255Scalar) Curve() curve.Curve {
	return Ristretto255{}
}

// MarshalBinary encodes the scalar as 32 big-endian bytes.
// The ristretto255 library uses little-endian internally, so we reverse.
func (s *Ristretto255Scalar) MarshalBinary() ([]byte, error) {
	le := s.value.Encode(nil) // 32 bytes, little-endian
	be := make([]byte, 32)
	for i := 0; i < 32; i++ {
		be[i] = le[31-i]
	}
	return be, nil
}

// UnmarshalBinary decodes 32 big-endian bytes into the scalar.
func (s *Ristretto255Scalar) UnmarshalBinary(data []byte) error {
	if len(data) != 32 {
		return fmt.Errorf("invalid length for ristretto255 scalar: %d", len(data))
	}
	le := make([]byte, 32)
	for i := 0; i < 32; i++ {
		le[i] = data[31-i]
	}
	if err := s.value.Decode(le); err != nil {
		return fmt.Errorf("invalid bytes for ristretto255 scalar: %w", err)
	}
	return nil
}

func (s *Ristretto255Scalar) Add(that curve.Scalar) curve.Scalar {
	other := ristretto255CastScalar(that)
	s.value.Add(s.value, other.value)
	return s
}

func (s *Ristretto255Scalar) Sub(that curve.Scalar) curve.Scalar {
	other := ristretto255CastScalar(that)
	s.value.Subtract(s.value, other.value)
	return s
}

func (s *Ristretto255Scalar) Negate() curve.Scalar {
	s.value.Negate(s.value)
	return s
}

func (s *Ristretto255Scalar) Mul(that curve.Scalar) curve.Scalar {
	other := ristretto255CastScalar(that)
	s.value.Multiply(s.value, other.value)
	return s
}

func (s *Ristretto255Scalar) Invert() curve.Scalar {
	s.value.Invert(s.value)
	return s
}

func (s *Ristretto255Scalar) Equal(that curve.Scalar) bool {
	other := ristretto255CastScalar(that)
	return s.value.Equal(other.value) == 1
}

func (s *Ristretto255Scalar) IsZero() bool {
	return s.value.Equal(r255.NewScalar().Zero()) == 1
}

func (s *Ristretto255Scalar) Set(that curve.Scalar) curve.Scalar {
	other := ristretto255CastScalar(that)
	// Encode + Decode is the only way to copy since Scalar fields are unexported.
	le := other.value.Encode(nil)
	_ = s.value.Decode(le)
	return s
}

func (s *Ristretto255Scalar) SetNat(x *saferith.Nat) curve.Scalar {
	reduced := new(saferith.Nat).Mod(x, ristretto255Order)
	be := reduced.Bytes()
	// Pad to 32 bytes big-endian, then convert to little-endian for Decode.
	padded := make([]byte, 32)
	if len(be) <= 32 {
		copy(padded[32-len(be):], be)
	} else {
		copy(padded, be[len(be)-32:])
	}
	le := make([]byte, 32)
	for i := 0; i < 32; i++ {
		le[i] = padded[31-i]
	}
	_ = s.value.Decode(le)
	return s
}

func (s *Ristretto255Scalar) Act(that curve.Point) curve.Point {
	other := ristretto255CastPoint(that)
	result := r255.NewElement().ScalarMult(s.value, other.value)
	return &Ristretto255Point{value: result}
}

func (s *Ristretto255Scalar) ActOnBase() curve.Point {
	result := r255.NewElement().ScalarBaseMult(s.value)
	return &Ristretto255Point{value: result}
}

func (s *Ristretto255Scalar) IsOverHalfOrder() bool {
	be, _ := s.MarshalBinary()
	val := new(big.Int).SetBytes(be)
	return val.Cmp(ristretto255HalfOrder) > 0
}

// --- Ristretto255Point ---

// Ristretto255Point implements curve.Point using ristretto255.Element.
type Ristretto255Point struct {
	value *r255.Element
}

func ristretto255CastPoint(generic curve.Point) *Ristretto255Point {
	out, ok := generic.(*Ristretto255Point)
	if !ok {
		panic(fmt.Sprintf("failed to convert to Ristretto255Point: %v", generic))
	}
	return out
}

func (*Ristretto255Point) Curve() curve.Curve {
	return Ristretto255{}
}

// MarshalBinary encodes the point as 32 bytes in ristretto canonical encoding.
func (p *Ristretto255Point) MarshalBinary() ([]byte, error) {
	return p.value.Encode(nil), nil
}

// UnmarshalBinary decodes 32 bytes in ristretto canonical encoding.
func (p *Ristretto255Point) UnmarshalBinary(data []byte) error {
	if len(data) != 32 {
		return fmt.Errorf("invalid length for ristretto255 point: %d", len(data))
	}
	if err := p.value.Decode(data); err != nil {
		return fmt.Errorf("invalid bytes for ristretto255 point: %w", err)
	}
	return nil
}

func (p *Ristretto255Point) Add(that curve.Point) curve.Point {
	other := ristretto255CastPoint(that)
	result := r255.NewElement().Add(p.value, other.value)
	return &Ristretto255Point{value: result}
}

func (p *Ristretto255Point) Sub(that curve.Point) curve.Point {
	other := ristretto255CastPoint(that)
	neg := r255.NewElement().Negate(other.value)
	result := r255.NewElement().Add(p.value, neg)
	return &Ristretto255Point{value: result}
}

func (p *Ristretto255Point) Negate() curve.Point {
	result := r255.NewElement().Negate(p.value)
	return &Ristretto255Point{value: result}
}

func (p *Ristretto255Point) Equal(that curve.Point) bool {
	other := ristretto255CastPoint(that)
	return p.value.Equal(other.value) == 1
}

func (p *Ristretto255Point) IsIdentity() bool {
	identity := r255.NewElement().Zero()
	return p.value.Equal(identity) == 1
}

// XScalar returns nil since ristretto255 is not an ECDSA curve.
func (p *Ristretto255Point) XScalar() curve.Scalar {
	return nil
}

// Compile-time interface satisfaction checks.
var (
	_ curve.Curve  = Ristretto255{}
	_ curve.Scalar = (*Ristretto255Scalar)(nil)
	_ curve.Point  = (*Ristretto255Point)(nil)
)
