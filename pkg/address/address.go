// Package address turns a wallet's public keys into the deposit addresses a
// chain will accept.
//
// The rule this package exists to enforce is that an address is derived from a
// curve, never from a byte length. An Ed25519 public key and a BIP-340 x-only
// secp256k1 public key are both exactly 32 bytes, so a length test cannot tell
// them apart. Rendering a secp256k1 key as a Solana address produces a string
// that is syntactically perfect, accepts deposits, and can never be spent from,
// because no Ed25519 signature will ever satisfy it. Every function here
// therefore checks the key against its curve and returns an error instead of a
// string when it cannot. Callers must omit the address when they get an error:
// no address is a recoverable state, a wrong address is not.
//
// The chains are one file each: Solana here, TON in ton.go, XRP in xrp.go.
// Each file states which curve it gates on and, where the address is not a
// direct encoding of the key, exactly which parameters were pinned to produce
// it — because those parameters are as address-determining as the key. TON in
// particular is not an encoding of a public key at all but the hash of a
// specific wallet contract's StateInit, so its file names the contract version
// it committed to and why; see ton.go.
package address

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/mr-tron/base58"
)

// ErrNotEd25519 reports that bytes offered as an Ed25519 public key are not one.
// Callers should treat it as "this wallet has no address on this chain" and emit
// nothing, never as a reason to fall back to encoding the bytes anyway.
var ErrNotEd25519 = errors.New("not an Ed25519 public key")

// Solana derives a Solana address from an Ed25519 public key.
//
// The address is the base58 encoding of the 32-byte key. base58 will encode any
// bytes at all, so the check happens first: the key must decode as a canonical
// edwards25519 point in the prime-order subgroup, using the same decoder the DKG
// uses to accept a key from the wire. A key that fails is refused.
//
// This check is defence in depth, not the primary defence. Against a wrong-curve
// key it is only probabilistic: roughly half of all 32-byte strings decode to
// some edwards25519 point, and one in eight of those lies in the prime-order
// subgroup, so a BIP-340 secp256k1 key slips through about one time in sixteen.
// The primary defence is provenance — the EdDSA public key is written only by
// the Ed25519 DKG, and nothing else is allowed to populate it.
func Solana(pub []byte) (string, error) {
	if err := RequireEd25519(pub); err != nil {
		return "", err
	}
	return base58.Encode(pub), nil
}

// RequireEd25519 reports whether pub is a usable Ed25519 public key: 32 bytes
// that decode to a canonical edwards25519 point of prime order, and that are not
// the identity.
//
// The prime-order requirement is not pedantry. Edwards25519 has cofactor 8, so a
// point can decode successfully and still carry a torsion component. The Schnorr
// verification equation S·B = R + k·A has a torsion-free left-hand side, so a
// torsion-tainted group key makes the equation unsatisfiable: the address would
// look ordinary, accept deposits, and never spend.
//
// The identity is excluded separately, because it passes the prime-order test —
// [L]O = O — while being far more dangerous than a torsion point. If the group
// key is the identity then verification reduces to S·B = R + k·O = R, which the
// pair (R = O, S = 0) satisfies for every message. Such an address is not merely
// unspendable by us; it is spendable by anyone who notices. The DKG does not
// itself reject an identity group key, so it is rejected here.
func RequireEd25519(pub []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: want %d bytes, got %d", ErrNotEd25519, ed25519.PublicKeySize, len(pub))
	}
	point := (curve.Ed25519{}).NewPoint()
	if err := point.UnmarshalBinary(pub); err != nil {
		return fmt.Errorf("%w: %v", ErrNotEd25519, err)
	}
	if point.IsIdentity() {
		return fmt.Errorf("%w: key is the identity element, for which any signature verifies", ErrNotEd25519)
	}
	return nil
}
