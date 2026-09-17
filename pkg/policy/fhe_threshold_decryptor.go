// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

// Committee is the FHE policy gate's threshold decryptor, backed by the
// M-Chain committee of github.com/luxfi/threshold/protocols/tfhe.
//
// One encrypted verdict bit goes to every member; each returns a partial
// decryption under its own share, bound by digest to the ciphertext. Any
// failure returns an error, which FHEVerifier reads as a denial.

package policy

import (
	"context"
	"fmt"
	"sync"

	"github.com/luxfi/fhe"
	"github.com/luxfi/threshold/protocols/tfhe"
)

// PartyClient is the per-member RPC client, one per node holding one share.
// Implementations own the transport.
type PartyClient interface {
	// Party returns the member's 1-based committee position.
	Party() int

	// PartialDecrypt asks the member to partially decrypt ciphertext.
	// Implementations must be safe for concurrent use.
	PartialDecrypt(ctx context.Context, ciphertext []byte) (tfhe.Decryption, error)
}

// Committee is the threshold-FHE decryptor for the policy gate.
type Committee struct {
	// Parties is the member client set. Requests fan out to all of them.
	Parties []PartyClient

	// Threshold is how many partial decryptions recover a verdict.
	Threshold int

	// Params is the committee's FHE parameter set.
	Params fhe.Parameters
}

// NewThresholdDecryptor returns the policy gate's threshold decryptor.
func NewThresholdDecryptor(parties []PartyClient, threshold int, params fhe.Parameters) *Committee {
	return &Committee{Parties: parties, Threshold: threshold, Params: params}
}

// Decrypt implements ThresholdDecryptor: the encrypted verdict is a one-bit
// ciphertext and Decrypt returns that bit. A wider ciphertext is refused.
func (c *Committee) Decrypt(ctx context.Context, ciphertext []byte) (bool, error) {
	if c.Threshold < 1 {
		return false, fmt.Errorf("policy/tfhe: threshold must be at least 1, got %d", c.Threshold)
	}
	if len(c.Parties) < c.Threshold {
		return false, fmt.Errorf("%w: committee has %d members, threshold is %d",
			tfhe.ErrQuorum, len(c.Parties), c.Threshold)
	}
	verdict, err := tfhe.Parse(ciphertext)
	if err != nil {
		return false, err
	}
	if verdict.NumBits() != 1 {
		return false, fmt.Errorf("policy/tfhe: encrypted verdict carries %d bits, want 1", verdict.NumBits())
	}

	shares, err := c.collect(ctx, ciphertext)
	if err != nil {
		return false, err
	}
	bits, err := tfhe.Decrypt(ciphertext, shares, c.Params, c.Threshold)
	if err != nil {
		return false, err
	}
	return bits[0], nil
}

// collect fans out to every member and returns as soon as the contributions in
// hand contain a quorum that recombines exactly; reaching the threshold count
// alone is not sufficient (tfhe.Quorum).
//
// A member that errors, repeats a position, or answers about a different
// ciphertext does not occupy a quorum slot.
func (c *Committee) collect(ctx context.Context, ciphertext []byte) ([]tfhe.Decryption, error) {
	want := tfhe.Digest(ciphertext)

	type answer struct {
		share tfhe.Decryption
		err   error
	}
	out := make(chan answer, len(c.Parties))
	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	for _, p := range c.Parties {
		wg.Add(1)
		go func(p PartyClient) {
			defer wg.Done()
			share, err := p.PartialDecrypt(subCtx, ciphertext)
			if err == nil && share.From != p.Party() {
				err = fmt.Errorf("member %d answered as %d", p.Party(), share.From)
			}
			select {
			case out <- answer{share: share, err: err}:
			case <-subCtx.Done():
			}
		}(p)
	}
	go func() { wg.Wait(); close(out) }()

	collected := make([]tfhe.Decryption, 0, len(c.Parties))
	positions := make([]int, 0, len(c.Parties))
	seen := make(map[int]struct{}, len(c.Parties))
	rejected := 0
	for a := range out {
		if a.err != nil {
			rejected++
			continue
		}
		if a.share.Digest != want {
			rejected++
			continue
		}
		if _, dup := seen[a.share.From]; dup {
			rejected++
			continue
		}
		seen[a.share.From] = struct{}{}
		collected = append(collected, a.share)
		positions = append(positions, a.share.From)
		if tfhe.Quorum(positions, c.Threshold) {
			return collected, nil
		}
	}
	return nil, fmt.Errorf("%w: %d of %d members answered, %d unusable, and no %d of them recombine exactly",
		tfhe.ErrQuorum, len(collected), len(c.Parties), rejected, c.Threshold)
}
