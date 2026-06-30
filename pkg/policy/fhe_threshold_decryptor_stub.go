//go:build !experimental_tfhe

// Default (production) build of the threshold-FHE policy decryptor.
//
// The encrypted-verdict committee decryptor is NOT wired to a real
// threshold scheme yet. The only existing committee implementation,
// luxfi/threshold/protocols/tfhe, is a fail-loud placeholder where every
// party holds the full master key (PartialDecrypt returns an HMAC tag and
// CombineShares runs single-party decryption) — it provides NO threshold
// security and was removed from luxfi/threshold upstream. That placeholder
// is reachable only under the `experimental_tfhe` build tag
// (fhe_threshold_decryptor.go); it is intentionally excluded from
// production builds.
//
// Real threshold-FHE decryption is to be wired onto luxfi/fhe pkg/threshold
// (ShareLWESecretKey / PartialDecryptLWE / CombineLWE — genuine Shamir/LWE
// partial decryption with smudging noise and Lagrange combine) plus the
// committee transport/session layer. That is an open task per LP-137 §2.6.
//
// Until it lands, production fails CLOSED: NewThresholdDecryptor returns a
// decryptor whose Decrypt always reports ErrThresholdFHENotWired, which
// FHEVerifier maps to ErrFHEThresholdDec — i.e. a policy deny. This is the
// only safe posture when the committee cannot actually decrypt a verdict.
//
// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause
package policy

import (
	"context"
	"errors"
)

// ErrThresholdFHENotWired is returned by the production ThresholdDecryptor
// because real threshold-FHE committee decryption is not yet wired. Build
// with `-tags experimental_tfhe` to compile the UNSAFE placeholder instead
// (see fhe_threshold_decryptor.go).
var ErrThresholdFHENotWired = errors.New(
	"policy: threshold FHE decryption not yet wired — real Shamir/LWE committee " +
		"(luxfi/fhe pkg/threshold) pending LP-137 §2.6; production fails closed",
)

// UnwiredThresholdDecryptor is the default-build ThresholdDecryptor. It
// satisfies the ThresholdDecryptor interface and fails closed on every
// call, so an FHEVerifier configured with it denies any FHE-gated intent
// rather than trusting an un-decryptable verdict.
type UnwiredThresholdDecryptor struct{}

// NewThresholdDecryptor returns the production ThresholdDecryptor. In the
// default build this is the fail-closed UnwiredThresholdDecryptor; the real
// committee implementation is wired here once LP-137 §2.6 lands.
func NewThresholdDecryptor() ThresholdDecryptor { return UnwiredThresholdDecryptor{} }

// Decrypt always returns ErrThresholdFHENotWired (fail-closed). It never
// returns true: there is no real committee to decrypt the verdict.
func (UnwiredThresholdDecryptor) Decrypt(_ context.Context, _ []byte) (bool, error) {
	return false, ErrThresholdFHENotWired
}
