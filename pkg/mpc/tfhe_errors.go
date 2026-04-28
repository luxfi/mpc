// Copyright (c) 2026, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

package mpc

import "errors"

// ErrTFHENotImplemented is returned by every TFHE wallet keygen / compute
// entry point in default builds.
//
// The threshold-FHE wallet ceremony in this codebase is wired to
// luxfi/threshold/protocols/tfhe, which is a fail-loud placeholder: every
// party stores the full master key, PartialDecrypt returns an HMAC tag, and
// CombineShares ignores partials and runs single-party decryption. The
// upstream package panics at every entry point unless
// LUX_ALLOW_FAKE_TFHE_FOR_TESTING_ONLY=1 is set, by design.
//
// Real-threshold wiring (luxfi/lattice Shamir/LWE) is tracked as a separate
// multi-week task per lps/LP-137-TFHE-REAL-THRESHOLD-SPEC.md §2.6. Until that
// lands, the wallet keygen / compute path is gated behind the
// `experimental_tfhe` build tag and default production builds reject every
// caller with this error.
var ErrTFHENotImplemented = errors.New("mpc/tfhe: threshold-FHE wallet keygen requires real Shamir/LWE threshold (LP-137 §2.6); placeholder UNSAFE primitive is gated behind the `experimental_tfhe` build tag")
