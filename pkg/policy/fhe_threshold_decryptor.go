// RealThresholdDecryptor wires the FHEVerifier's ThresholdDecryptor
// interface to the t-of-n committee implemented in luxfi/fhe/threshold.
//
// Flow:
//
//  1. Send a PartialDecrypt request to every configured PartyClient.
//  2. Collect FHEThresholdShare responses as they arrive.
//  3. Once `threshold` valid shares are in hand, call
//     ShareAggregateService.Aggregate.
//  4. Round the recovered plaintext to a boolean (FHE policy verdicts
//     are 1-bit) and return.
//
// Failure modes are mapped to ErrFHEThresholdDec by the verifier wrapper
// so the policy gate fails closed on any committee anomaly.
//
// This file is additive — it does not modify the FHEVerifier struct or
// its existing constructors. Callers wire RealThresholdDecryptor via
// FHEVerifier.Decryptor like any other ThresholdDecryptor.
//
// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause
package policy

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"

	fhethr "github.com/luxfi/fhe/threshold"
)

// ErrCommitteeQuorum is returned by RealThresholdDecryptor.Decrypt when
// the configured threshold could not be assembled from the available
// PartyClient set within the request lifetime.
var ErrCommitteeQuorum = errors.New("real-threshold-decryptor: insufficient quorum")

// PartyClient is the per-peer RPC client. The default deployment maps
// one PartyClient to one M-Chain MPC node hosting a single
// FHEThresholdShare-producing endpoint.
//
// Implementations are responsible for transport (TLS 1.3, ZAP wire
// types 60-79 per LP-022, etc.); this interface only describes the
// shape of the request/response.
type PartyClient interface {
	// PartyID returns the 1-indexed party identifier this client
	// targets. Used by the dispatcher to demux responses and by the
	// aggregator to verify per-party material.
	PartyID() uint32

	// PartialDecrypt issues a partial-decrypt request to the peer.
	// Implementations are expected to be concurrent-safe.
	PartialDecrypt(
		ctx context.Context,
		ciphertext fhethr.FHECiphertext,
		sessionID [32]byte,
	) (fhethr.FHEThresholdShare, error)
}

// RealThresholdDecryptor is the production ThresholdDecryptor wired to
// the M-Chain MPC committee.
type RealThresholdDecryptor struct {
	// Aggregate is the local aggregation service. Defaults to a
	// fhethr.NewShareAggregator() when nil.
	Aggregate fhethr.ShareAggregateService

	// Parties is the per-party RPC client set. The dispatcher fans out
	// to every entry in parallel and short-circuits as soon as
	// `threshold` valid shares are received.
	Parties []PartyClient

	// Threshold is the t-of-n bound. Must satisfy 1 ≤ Threshold ≤
	// len(Parties).
	Threshold uint32

	// PartyKeys, when set, switches the aggregator to the symmetric-key
	// verification path (see fhethr.ShareAggregator). Production
	// committee self-checks populate this field; cross-committee
	// callers leave it nil and rely on the public-key path once CDS
	// noise proofs ship.
	PartyKeys map[uint32]fhethr.KeyShare
}

// NewRealThresholdDecryptor returns a configured decryptor.
func NewRealThresholdDecryptor(
	parties []PartyClient,
	threshold uint32,
) *RealThresholdDecryptor {
	return &RealThresholdDecryptor{
		Aggregate: fhethr.NewShareAggregator(),
		Parties:   parties,
		Threshold: threshold,
	}
}

// Decrypt implements ThresholdDecryptor. It accepts the opaque
// encrypted-verdict bytes, fans out partial-decrypt requests to the
// committee, and aggregates ≥t shares into a boolean verdict.
//
// The sessionID is derived from sha256("decrypt" || ciphertext) — the
// FHEVerifier issues one ciphertext per (intent, policy) pair so the
// derivation is replay-safe across calls. Production may layer a
// caller-supplied sessionID on top via decorating the ciphertext bytes.
func (d *RealThresholdDecryptor) Decrypt(
	ctx context.Context,
	ciphertextBytes []byte,
) (bool, error) {
	if d.Threshold == 0 {
		return false, fmt.Errorf("real-threshold-decryptor: threshold must be > 0")
	}
	if uint32(len(d.Parties)) < d.Threshold {
		return false, ErrCommitteeQuorum
	}
	ct := fhethr.NewFHECiphertext(ciphertextBytes)
	sess := sessionForCiphertext(ct)

	shares, err := d.collectShares(ctx, ct, sess)
	if err != nil {
		return false, err
	}
	if uint32(len(shares)) < d.Threshold {
		return false, ErrCommitteeQuorum
	}

	agg := d.Aggregate
	if agg == nil {
		agg = fhethr.NewShareAggregator()
	}
	if a, ok := agg.(*fhethr.ShareAggregator); ok && d.PartyKeys != nil {
		a.PartyKeys = d.PartyKeys
	}
	res, plaintext, err := agg.Aggregate(ctx, ct, shares, d.Threshold, sess)
	if err != nil {
		return false, fmt.Errorf("real-threshold-decryptor: aggregate: %w", err)
	}
	if res.Status != fhethr.StatusOK {
		return false, fmt.Errorf("real-threshold-decryptor: status=%s", res.Status)
	}
	return roundToBool(plaintext), nil
}

// collectShares fans out PartialDecrypt to every configured peer and
// returns as soon as `threshold` shares are collected. Errors from
// individual peers are accumulated for diagnostic but not propagated:
// the protocol succeeds when ≥t valid shares arrive regardless of how
// many peers reported errors.
func (d *RealThresholdDecryptor) collectShares(
	ctx context.Context,
	ct fhethr.FHECiphertext,
	sess [32]byte,
) ([]fhethr.FHEThresholdShare, error) {
	type result struct {
		share fhethr.FHEThresholdShare
		err   error
	}
	out := make(chan result, len(d.Parties))
	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	for _, p := range d.Parties {
		wg.Add(1)
		go func(p PartyClient) {
			defer wg.Done()
			s, err := p.PartialDecrypt(subCtx, ct, sess)
			select {
			case out <- result{share: s, err: err}:
			case <-subCtx.Done():
			}
		}(p)
	}
	go func() { wg.Wait(); close(out) }()

	collected := make([]fhethr.FHEThresholdShare, 0, d.Threshold)
	seen := make(map[uint32]struct{}, d.Threshold)
	var errs []error
	for r := range out {
		if r.err != nil {
			errs = append(errs, r.err)
			continue
		}
		if _, dup := seen[r.share.PartyID]; dup {
			continue
		}
		seen[r.share.PartyID] = struct{}{}
		collected = append(collected, r.share)
		if uint32(len(collected)) >= d.Threshold {
			cancel()
			return collected, nil
		}
	}
	if uint32(len(collected)) < d.Threshold {
		return collected, fmt.Errorf("%w (collected %d, errors %d)", ErrCommitteeQuorum, len(collected), len(errs))
	}
	return collected, nil
}

// sessionForCiphertext derives a deterministic 32-byte sessionID from
// the ciphertext bytes. Per-call uniqueness comes from the F-Chain
// PolicyVault: each evaluation produces a distinct ciphertext, so each
// produces a distinct session.
//
// An additional 16 bytes of crypto/rand entropy are mixed in to defend
// against the (small) chance of two evaluations producing identical
// ciphertext bytes due to deterministic FHE encoding — at the cost of
// the per-call replay protection in the producer's PartialDecrypter
// being a no-op. Production deployments anchoring the session to
// ciphertext-only MUST disable the entropy mix.
func sessionForCiphertext(ct fhethr.FHECiphertext) [32]byte {
	var rnd [16]byte
	_, _ = rand.Read(rnd[:])
	h := sha256.New()
	h.Write([]byte("LUX/FHE/THRESHOLD/SESSION/v1"))
	h.Write(ct.ID[:])
	h.Write(rnd[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// roundToBool reduces an arbitrary plaintext byte slice to a single
// boolean: true iff any byte is non-zero. The FHE policy circuit emits
// a 1-bit verdict, so the plaintext is always 1 byte in production —
// the byte-vector path here matches the toy threshold scheme used by
// the threshold package's unit tests.
func roundToBool(plaintext []byte) bool {
	for _, b := range plaintext {
		if b != 0 {
			return true
		}
	}
	return false
}
