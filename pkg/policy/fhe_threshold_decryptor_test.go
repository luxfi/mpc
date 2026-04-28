// Tests for RealThresholdDecryptor. The PartyClient interface is
// stubbed out with a thin in-memory adapter that wraps the
// fhethr.PartialDecrypter directly — exercising the dispatcher fan-out
// + aggregator wiring without an actual RPC layer.
//
// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause
package policy

import (
	"context"
	"errors"
	"os"
	"testing"

	fhethr "github.com/luxfi/threshold/protocols/tfhe"
)

// TestMain opts into the fake-threshold tfhe implementation for the
// duration of these unit tests. The threshold library's
// PartialDecrypter/ShareAggregator panic without this opt-in to make the
// real-threshold cutover unmissable in production. The stub party path
// here is by definition a unit-test simulation, so opting in is correct
// — the real RPC-backed PartyClient does not transit this guard.
func TestMain(m *testing.M) {
	os.Setenv("LUX_ALLOW_FAKE_TFHE_FOR_TESTING_ONLY", "1")
	os.Exit(m.Run())
}

// stubParty implements PartyClient over a local PartialDecrypter +
// fixed KeyShare. Used by tests only.
type stubParty struct {
	id      uint32
	key     fhethr.KeyShare
	decrypt *fhethr.PartialDecrypter
	err     error // injected error, when set is returned instead of decrypting
}

func newStubParty(id uint32, key fhethr.KeyShare) *stubParty {
	return &stubParty{
		id:      id,
		key:     key,
		decrypt: fhethr.NewPartialDecrypter(),
	}
}

func (s *stubParty) PartyID() uint32 { return s.id }

func (s *stubParty) PartialDecrypt(
	ctx context.Context,
	ct fhethr.FHECiphertext,
	sess [32]byte,
) (fhethr.FHEThresholdShare, error) {
	if s.err != nil {
		return fhethr.FHEThresholdShare{}, s.err
	}
	return s.decrypt.PartialDecrypt(ctx, s.key, ct, sess)
}

func makeTestCommittee(n uint32) ([]PartyClient, map[uint32]fhethr.KeyShare) {
	parties := make([]PartyClient, 0, n)
	keys := make(map[uint32]fhethr.KeyShare, n)
	for i := uint32(1); i <= n; i++ {
		b := make([]byte, 32)
		for j := range b {
			b[j] = byte(i)*0x33 ^ byte(j)
		}
		k := fhethr.KeyShare{PartyID: i, Bytes: b}
		keys[i] = k
		parties = append(parties, newStubParty(i, k))
	}
	return parties, keys
}

func TestRealThresholdDecryptor_2of3(t *testing.T) {
	parties, keys := makeTestCommittee(3)
	d := NewRealThresholdDecryptor(parties, 2)
	d.PartyKeys = keys

	// Plaintext "anything non-zero" → true. The toy threshold scheme
	// recovers a non-empty plaintext for any non-empty ciphertext.
	ct := []byte("encrypted-policy-verdict-allow")
	ok, err := d.Decrypt(context.Background(), ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !ok {
		t.Fatalf("Decrypt = false, want true (non-zero plaintext)")
	}
}

func TestRealThresholdDecryptor_3of5(t *testing.T) {
	parties, keys := makeTestCommittee(5)
	d := NewRealThresholdDecryptor(parties, 3)
	d.PartyKeys = keys

	ct := []byte("encrypted-policy-3of5")
	ok, err := d.Decrypt(context.Background(), ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !ok {
		t.Fatalf("Decrypt = false")
	}
}

func TestRealThresholdDecryptor_InsufficientPeers(t *testing.T) {
	parties, _ := makeTestCommittee(2)
	d := NewRealThresholdDecryptor(parties, 3) // threshold > peers
	_, err := d.Decrypt(context.Background(), []byte("ciphertext"))
	if !errors.Is(err, ErrCommitteeQuorum) {
		t.Fatalf("err = %v, want ErrCommitteeQuorum", err)
	}
}

func TestRealThresholdDecryptor_PartyErrors(t *testing.T) {
	parties, keys := makeTestCommittee(3)
	// Two parties err; threshold=2 cannot be met.
	parties[0].(*stubParty).err = errors.New("network down")
	parties[1].(*stubParty).err = errors.New("network down")

	d := NewRealThresholdDecryptor(parties, 2)
	d.PartyKeys = keys
	_, err := d.Decrypt(context.Background(), []byte("ciphertext"))
	if !errors.Is(err, ErrCommitteeQuorum) {
		t.Fatalf("err = %v, want ErrCommitteeQuorum", err)
	}
}

func TestRealThresholdDecryptor_OnePartyError_SufficientQuorum(t *testing.T) {
	parties, keys := makeTestCommittee(3)
	// One party errs; threshold=2, two healthy peers can satisfy.
	parties[2].(*stubParty).err = errors.New("network down")

	d := NewRealThresholdDecryptor(parties, 2)
	d.PartyKeys = keys
	ok, err := d.Decrypt(context.Background(), []byte("ciphertext"))
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !ok {
		t.Fatalf("Decrypt = false")
	}
}

func TestRealThresholdDecryptor_ZeroThreshold(t *testing.T) {
	parties, _ := makeTestCommittee(3)
	d := NewRealThresholdDecryptor(parties, 0)
	_, err := d.Decrypt(context.Background(), []byte("ciphertext"))
	if err == nil {
		t.Fatalf("expected error on zero threshold")
	}
}

func TestRoundToBool(t *testing.T) {
	cases := []struct {
		in   []byte
		want bool
	}{
		{nil, false},
		{[]byte{}, false},
		{[]byte{0x00}, false},
		{[]byte{0x00, 0x00, 0x00}, false},
		{[]byte{0x01}, true},
		{[]byte{0x00, 0x01, 0x00}, true},
	}
	for _, c := range cases {
		if got := roundToBool(c.in); got != c.want {
			t.Errorf("roundToBool(%x) = %v, want %v", c.in, got, c.want)
		}
	}
}
