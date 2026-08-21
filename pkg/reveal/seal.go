// Copyright © 2026 Lux Industries Inc. All rights reserved.

package reveal

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/luxfi/threshold/pkg/math/curve"
	tr "github.com/luxfi/threshold/protocols/reveal"
)

// PublicKeySize is the length of the group key a ring publishes for a wallet:
// one compressed Ed25519 point.
const PublicKeySize = 32

// ErrBadPublicKey reports a group key that is not a point on the curve.
var ErrBadPublicKey = errors.New("reveal: not a group key")

// Seal writes a secret only a quorum can read.
//
// It is the half of this protocol that needs no ring. Enrolling a secret takes
// the group key and nothing else — no share, no node, no round — so whoever
// holds a secret can seal it where it already lives and hand over ciphertext.
// Reading it back is the part that needs the committee, and that asymmetry is
// the whole point: a secret can be given to the ring without ever being shown
// to it.
//
// publicKey is the 32 bytes the keygen published for the wallet (eddsa_pub_key,
// and what PublicKey returns on a node). The result is opened by Combine from
// enough Answers, and by nothing else.
func Seal(publicKey, secret []byte) ([]byte, error) {
	if len(publicKey) != PublicKeySize {
		return nil, fmt.Errorf("%w: %d bytes, want %d", ErrBadPublicKey, len(publicKey), PublicKeySize)
	}
	if len(secret) == 0 {
		return nil, errors.New("reveal: sealing nothing")
	}

	point := curve.Ed25519{}.NewPoint()
	if err := point.UnmarshalBinary(publicKey); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadPublicKey, err)
	}
	// The identity is a VALID encoding, so the decoder lets it through. It is
	// the one point that must not be sealed to: every answer verifies against
	// it, so anyone could open the result. Refused here, under the same error
	// as any other key that cannot be sealed to, because a caller deciding what
	// to do about a bad key should not have to tell the two apart.
	if point.IsIdentity() {
		return nil, fmt.Errorf("%w: the identity", ErrBadPublicKey)
	}

	ct, err := tr.Encrypt(rand.Reader, point, secret)
	if err != nil {
		return nil, fmt.Errorf("reveal: seal: %w", err)
	}
	return ct.MarshalBinary()
}
