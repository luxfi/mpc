// Copyright © 2026 Lux Industries Inc. All rights reserved.

package reveal

import (
	"bytes"
	"errors"
	"testing"

	"github.com/luxfi/threshold/pkg/math/curve"
)

// The point of Seal is that it needs nothing but the published key. This holds
// it to that: the sealer is given 32 bytes and no share, no store and no node,
// and the committee opens what it wrote.
func TestASealerWithOnlyThePublishedKeyWritesWhatTheCommitteeOpens(t *testing.T) {
	stores, cfg := committee(t, 2)

	published, err := cfg.PublicKey.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(published) != PublicKeySize {
		t.Fatalf("a published group key is %d bytes, want %d", len(published), PublicKeySize)
	}

	secret := []byte("the root key, which no one node may hold")
	sealed, err := Seal(published, secret)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if bytes.Contains(sealed, secret) {
		t.Fatal("the ciphertext carries the secret in the clear")
	}

	var answers [][]byte
	var combiner *shelf
	for _, s := range stores {
		a, err := Answer(s, testOrg, testWallet, sealed)
		if err != nil {
			t.Fatalf("answer: %v", err)
		}
		answers = append(answers, a)
		combiner = s
	}

	got, err := Combine(combiner, testOrg, testWallet, sealed, answers)
	if err != nil {
		t.Fatalf("combine: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("opened %q, want %q", got, secret)
	}
}

// Two seals of one secret share no bytes. Encrypt draws a fresh scalar each
// time, so a repeated enrolment does not announce that it repeated.
func TestSealingTwiceWritesTwoDifferentThings(t *testing.T) {
	_, cfg := committee(t, 2)
	published, err := cfg.PublicKey.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	secret := []byte("same secret, twice")
	a, err := Seal(published, secret)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Seal(published, secret)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two seals of one secret are identical")
	}
}

// A key that is not a point never becomes one. The identity matters most: every
// answer verifies against it, so a secret sealed there is readable by anyone,
// and the decoder is where that has to stop.
func TestSealRefusesAnythingThatIsNotAGroupKey(t *testing.T) {
	identity, err := curve.Ed25519{}.NewPoint().MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name string
		key  []byte
	}{
		{"identity", identity},
		{"off the curve", bytes.Repeat([]byte{0xff}, PublicKeySize)},
		{"too short", make([]byte, PublicKeySize-1)},
		{"too long", make([]byte, PublicKeySize+1)},
		{"nothing", nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Seal(c.key, []byte("secret")); !errors.Is(err, ErrBadPublicKey) {
				t.Fatalf("err = %v, want ErrBadPublicKey", err)
			}
		})
	}
}

func TestSealRefusesAnEmptySecret(t *testing.T) {
	_, cfg := committee(t, 2)
	published, err := cfg.PublicKey.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Seal(published, nil); err == nil {
		t.Fatal("sealed nothing without complaint")
	}
}
