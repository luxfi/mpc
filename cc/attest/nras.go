// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

package attest

import (
	"context"
	"fmt"
)

// NRAS is the NVIDIA Remote Attestation Service verifier.
//
// Status: STUB — tracked at issue #222 stage 3.
//
// Production plan (intentionally not yet implemented):
//
//   - Parse the NRAS-signed JWT (RFC 7519) carrying the GPU device-state
//     report.
//   - Validate the JWS signature against the NRAS signing key fetched
//     from the NRAS JWKS endpoint, with a TTL'd cache and a force-rotate
//     hook for emergency key rotation.
//   - Verify the EAT/JWT claims: nbf, exp, nonce binding, audience.
//   - Cross-check the embedded device-state report against the RIM
//     (Reference Integrity Manifest) for the asserted driver+VBIOS pair
//     (see pkg/attestation/nvidia/rim.go for the existing RIM type).
//   - Extract the per-GPU UUID, driver version, VBIOS version, and the
//     per-GPU measurement digest.
//   - Compose CompositeHash via the same domain-separated SHA-256 as
//     the SEV path.
//
// pkg/attestation/nvidia already implements NRAS request/response shaping
// and JWT signature verification against a caller-supplied trust root.
// Stage 3 lifts that into the cc/attest contract: a single Verify(ctx,
// evidence, opts...) entry point with an internal JWKS cache and the
// canonical VerifiedReport output shape.
//
// Verify returns ErrNotImplemented so the call site refuses the release
// without crashing the process. See TDX.Verify for the rationale.
type NRAS struct{}

// Verify implements Verifier. NOT YET IMPLEMENTED — do not enable NRAS
// dispatch in production until #222 stage 3 lands.
func (NRAS) Verify(ctx context.Context, evidence []byte, opts ...Option) (*VerifiedReport, error) {
	return nil, fmt.Errorf("%w: NRAS attestation envelope verification not configured for this build (tracked at #222 stage 3: NRAS JWT + JWKS cache)",
		ErrNotImplemented)
}

var _ Verifier = NRAS{}
