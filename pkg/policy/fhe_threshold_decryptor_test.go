// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

// Tests for the threshold-FHE policy decryptor, over a real dealerless
// committee served in-process. The smudging noise is seeded, so a run is
// reproducible; the committee key is freshly generated.

package policy

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/luxfi/fhe"
	"github.com/luxfi/lattice/v7/utils/sampling"
	"github.com/luxfi/threshold/protocols/tfhe"
)

var (
	committeeCRSSeed = []byte("lux-mpc-policy-committee-test-crs-seed-v1")
	committeeNoise   = []byte("lux-mpc-policy-committee-test-noise-seed-v1")
)

// member serves one committee member over the PartyClient interface.
type member struct {
	m *tfhe.Member

	// err, when set, is returned instead of a partial decryption.
	err error

	// answerAbout, when set, is the ciphertext this member decrypts whatever it
	// was asked about.
	answerAbout []byte

	// claimPosition, when non-zero, is the position this member claims to be.
	claimPosition int
}

func (p *member) Party() int { return p.m.Share.Index }

func (p *member) PartialDecrypt(_ context.Context, ciphertext []byte) (tfhe.Decryption, error) {
	if p.err != nil {
		return tfhe.Decryption{}, p.err
	}
	subject := ciphertext
	if p.answerAbout != nil {
		subject = p.answerAbout
	}
	prng, err := sampling.NewKeyedPRNG(append(append([]byte(nil), committeeNoise...), byte(p.m.Share.Index)))
	if err != nil {
		return tfhe.Decryption{}, err
	}
	share, err := p.m.Decrypt(subject, prng)
	if err != nil {
		return tfhe.Decryption{}, err
	}
	if p.claimPosition != 0 {
		share.From = p.claimPosition
	}
	return share, nil
}

// newCommittee runs a dealerless key generation and returns the member
// clients, the parameters and the collective public key.
func newCommittee(t *testing.T, threshold, total int) ([]*member, fhe.Parameters, *fhe.PublicKey) {
	t.Helper()
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		t.Fatalf("parameters: %v", err)
	}
	pub, shares, err := tfhe.Keygen(params, threshold, total, committeeCRSSeed)
	if err != nil {
		t.Fatalf("dealerless key generation: %v", err)
	}
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		t.Fatalf("encode collective public key: %v", err)
	}
	members := make([]*member, total)
	for i := range shares {
		members[i] = &member{m: &tfhe.Member{
			Params:    fhe.PN10QP27,
			Threshold: threshold,
			Total:     total,
			Key:       pubBytes,
			Share:     shares[i],
		}}
	}
	return members, params, pub
}

func clients(members []*member) []PartyClient {
	out := make([]PartyClient, len(members))
	for i, m := range members {
		out[i] = m
	}
	return out
}

// verdict encrypts a one-bit policy verdict under the collective public key.
func verdict(t *testing.T, params fhe.Parameters, pub *fhe.PublicKey, allow bool) []byte {
	t.Helper()
	var bit uint64
	if allow {
		bit = 1
	}
	ciphertext, err := tfhe.Encrypt(params, pub, bit, fhe.FheBool)
	if err != nil {
		t.Fatalf("encrypt verdict: %v", err)
	}
	return ciphertext
}

// TestCommittee_RecoversBothVerdicts asserts both verdict bits through a
// 2-of-3 committee.
func TestCommittee_RecoversBothVerdicts(t *testing.T) {
	members, params, pub := newCommittee(t, 2, 3)
	d := NewThresholdDecryptor(clients(members), 2, params)

	for _, allow := range []bool{true, false} {
		got, err := d.Decrypt(context.Background(), verdict(t, params, pub, allow))
		if err != nil {
			t.Fatalf("Decrypt(allow=%v): %v", allow, err)
		}
		if got != allow {
			t.Fatalf("Decrypt(allow=%v) = %v", allow, got)
		}
	}
}

// TestCommittee_3of5 covers a larger committee at its threshold.
func TestCommittee_3of5(t *testing.T) {
	members, params, pub := newCommittee(t, 3, 5)
	d := NewThresholdDecryptor(clients(members), 3, params)

	got, err := d.Decrypt(context.Background(), verdict(t, params, pub, true))
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !got {
		t.Fatal("Decrypt = false, want true")
	}
}

// TestCommittee_ShortCommitteeRefuses checks a committee smaller than its
// threshold is refused before any member is contacted.
func TestCommittee_ShortCommitteeRefuses(t *testing.T) {
	members, params, pub := newCommittee(t, 2, 2)
	d := NewThresholdDecryptor(clients(members), 3, params)

	_, err := d.Decrypt(context.Background(), verdict(t, params, pub, true))
	if !errors.Is(err, tfhe.ErrQuorum) {
		t.Fatalf("err = %v, want a quorum failure", err)
	}
}

// TestCommittee_ZeroThresholdRefuses checks a threshold of zero is refused.
func TestCommittee_ZeroThresholdRefuses(t *testing.T) {
	members, params, pub := newCommittee(t, 2, 3)
	d := NewThresholdDecryptor(clients(members), 0, params)

	_, err := d.Decrypt(context.Background(), verdict(t, params, pub, true))
	if err == nil {
		t.Fatal("Decrypt accepted a threshold of zero")
	}
	if !strings.Contains(err.Error(), "threshold must be at least 1") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// TestCommittee_TooManyUnreachableRefuses checks member failures below the
// threshold refuse rather than guess the verdict.
func TestCommittee_TooManyUnreachableRefuses(t *testing.T) {
	members, params, pub := newCommittee(t, 2, 3)
	members[0].err = errors.New("network down")
	members[1].err = errors.New("network down")
	d := NewThresholdDecryptor(clients(members), 2, params)

	_, err := d.Decrypt(context.Background(), verdict(t, params, pub, true))
	if !errors.Is(err, tfhe.ErrQuorum) {
		t.Fatalf("err = %v, want a quorum failure", err)
	}
}

// TestCommittee_OneUnreachableStillDecrypts checks the threshold is a floor,
// not unanimity.
func TestCommittee_OneUnreachableStillDecrypts(t *testing.T) {
	members, params, pub := newCommittee(t, 2, 3)
	members[2].err = errors.New("network down")
	d := NewThresholdDecryptor(clients(members), 2, params)

	got, err := d.Decrypt(context.Background(), verdict(t, params, pub, true))
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !got {
		t.Fatal("Decrypt = false, want true")
	}
}

// TestCommittee_ReplayedPartialDoesNotFillQuorum checks a member answering
// about a different ciphertext is neither combined nor counted, and the honest
// members still carry the round.
func TestCommittee_ReplayedPartialDoesNotFillQuorum(t *testing.T) {
	members, params, pub := newCommittee(t, 2, 3)
	stale := verdict(t, params, pub, true)
	members[0].answerAbout = stale

	d := NewThresholdDecryptor(clients(members), 2, params)
	got, err := d.Decrypt(context.Background(), verdict(t, params, pub, false))
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got {
		t.Fatal("a replayed partial decryption turned a deny into an allow")
	}
}

// TestCommittee_ReplayedPartialRefusesWhenItIsTheQuorum checks the same with
// no honest member to fall back on: the round fails.
func TestCommittee_ReplayedPartialRefusesWhenItIsTheQuorum(t *testing.T) {
	members, params, pub := newCommittee(t, 2, 2)
	stale := verdict(t, params, pub, true)
	members[0].answerAbout = stale

	d := NewThresholdDecryptor(clients(members), 2, params)
	_, err := d.Decrypt(context.Background(), verdict(t, params, pub, false))
	if !errors.Is(err, tfhe.ErrQuorum) {
		t.Fatalf("err = %v, want a quorum failure", err)
	}
}

// TestCommittee_ImpostorPositionRejected checks a member answering under
// another member's position is rejected.
func TestCommittee_ImpostorPositionRejected(t *testing.T) {
	members, params, pub := newCommittee(t, 2, 2)
	members[0].claimPosition = 2
	d := NewThresholdDecryptor(clients(members), 2, params)

	_, err := d.Decrypt(context.Background(), verdict(t, params, pub, true))
	if !errors.Is(err, tfhe.ErrQuorum) {
		t.Fatalf("err = %v, want a quorum failure", err)
	}
}

// TestCommittee_WideCiphertextRefused checks the one-bit verdict contract.
func TestCommittee_WideCiphertextRefused(t *testing.T) {
	members, params, pub := newCommittee(t, 2, 3)
	wide, err := tfhe.Encrypt(params, pub, 1, fhe.FheUint8)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	d := NewThresholdDecryptor(clients(members), 2, params)

	if _, err := d.Decrypt(context.Background(), wide); err == nil {
		t.Fatal("Decrypt accepted an 8-bit verdict")
	} else if !strings.Contains(err.Error(), "carries 8 bits") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// TestCommittee_GarbageCiphertextRefused covers input that is not a
// ciphertext.
func TestCommittee_GarbageCiphertextRefused(t *testing.T) {
	members, params, _ := newCommittee(t, 2, 3)
	d := NewThresholdDecryptor(clients(members), 2, params)

	for _, in := range [][]byte{nil, {}, []byte("not a ciphertext")} {
		if _, err := d.Decrypt(context.Background(), in); err == nil {
			t.Fatalf("Decrypt accepted %q as a verdict", in)
		}
	}
}

// TestCommittee_CancelledContextRefuses checks a cancelled round denies.
func TestCommittee_CancelledContextRefuses(t *testing.T) {
	members, params, pub := newCommittee(t, 2, 3)
	ciphertext := verdict(t, params, pub, true)
	for _, m := range members {
		m.err = context.Canceled
	}
	d := NewThresholdDecryptor(clients(members), 2, params)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.Decrypt(ctx, ciphertext); err == nil {
		t.Fatal("Decrypt returned a verdict for a cancelled round")
	}
}

// TestCommittee_SatisfiesThresholdDecryptor keeps the decryptor wired to the
// interface the policy gate consumes.
func TestCommittee_SatisfiesThresholdDecryptor(t *testing.T) {
	var _ ThresholdDecryptor = (*Committee)(nil)
}
