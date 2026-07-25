package cggmp21

import (
	"crypto/rand"
	"testing"

	tecdsa "github.com/luxfi/threshold/pkg/ecdsa"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/sample"

	"github.com/luxfi/mpc/pkg/protocol"
)

// newTestSignature produces a genuine ECDSA signature over hash under secret
// x, using the same curve arithmetic the threshold protocol outputs.
func newTestSignature(t *testing.T, x curve.Scalar, hash []byte) *tecdsa.Signature {
	t.Helper()
	group := x.Curve()

	k := sample.Scalar(rand.Reader, group)
	m := curve.FromHash(group, hash)
	kInv := group.NewScalar().Set(k).Invert()
	R := kInv.ActOnBase()
	r := R.XScalar()
	s := r.Mul(x).Add(m).Mul(k)
	return &tecdsa.Signature{R: R, S: s}
}

// signatureAdapter.Verify used to `return false` unconditionally with the
// comment "For now". Any caller using it as a signing-path health check saw a
// permanent, inexplicable failure; any caller treating an unverifiable
// signature as acceptable got no verification at all. This pins that it now
// actually verifies.
func TestSignatureAdapterVerifiesRealSignature(t *testing.T) {
	group := curve.Secp256k1{}

	for i := 0; i < 64; i++ {
		x := sample.Scalar(rand.Reader, group)
		pub := protocol.PublicKey(x.ActOnBase())
		if pub == nil {
			t.Fatalf("iteration %d: could not render public key", i)
		}

		hash := make([]byte, 32)
		if _, err := rand.Read(hash); err != nil {
			t.Fatalf("rand: %v", err)
		}

		adapter := &signatureAdapter{sig: newTestSignature(t, x, hash)}
		if !adapter.Verify(pub, hash) {
			t.Fatalf("iteration %d: Verify rejected a valid signature", i)
		}
	}
}

func TestSignatureAdapterRejectsBadInput(t *testing.T) {
	group := curve.Secp256k1{}
	x := sample.Scalar(rand.Reader, group)
	pub := protocol.PublicKey(x.ActOnBase())

	hash := make([]byte, 32)
	copy(hash, "the message that was signed-----")
	adapter := &signatureAdapter{sig: newTestSignature(t, x, hash)}

	otherHash := make([]byte, 32)
	copy(otherHash, "a different message entirely----")

	otherPub := protocol.PublicKey(sample.Scalar(rand.Reader, group).ActOnBase())

	for _, tc := range []struct {
		name string
		run  func() bool
	}{
		{"wrong message", func() bool { return adapter.Verify(pub, otherHash) }},
		{"wrong public key", func() bool { return adapter.Verify(otherPub, hash) }},
		{"nil public key", func() bool { return adapter.Verify(nil, hash) }},
		{"nil signature", func() bool { return (&signatureAdapter{}).Verify(pub, hash) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.run() {
				t.Fatal("Verify accepted something it must reject")
			}
		})
	}
}
