// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

// Package attest is the canonical TEE attestation verifier for the Lux
// confidential-compute control plane.
//
// Status:
//   - SEV-SNP: PRODUCTION (live VCEK fetch from AMD KDS, full chain verify)
//   - TDX:     STUB (tracked at #222 stage 2; use go-tdx-guest + Intel PCS)
//   - NRAS:    STUB (tracked at #222 stage 3; use NRAS JWT + JWKS cache)
//
// luxcpp/crypto/attestation provides parser-only primitives. THIS package
// is where chain verification + trust anchor management lives. The two
// are connected via Go cgo binding into the C-ABI parser, then verifying
// the bytes here BEFORE accepting the parser's measurement output.
//
// Layering:
//
//	caller (kms release gate, scheduler, indexer)
//	  └── cc/attest.Verifier.Verify(ctx, evidence, opts...)        ◄── this package
//	        ├── SEV-SNP    → google/go-sev-guest + AMD KDS         (PROD)
//	        ├── Intel TDX  → google/go-tdx-guest + Intel PCS       (STUB)
//	        └── NVIDIA GPU → NRAS JWT + JWKS rotation              (STUB)
//
// Wire format dispatch is by the leading magic / kind byte stamped by the
// C-ABI parser. The parser's output is NOT trusted until Verify returns
// without error: the parser only normalises framing; this package
// validates the chain to the vendor root and extracts measurements.
//
// Security invariants:
//
//   - Trust anchors are pinned per-vendor in code (AMD ARK/ASK ship
//     embedded with go-sev-guest; Intel/NVIDIA roots are fetched
//     once and cached, never trusted from the evidence itself).
//   - Tests do not hit the network. KDS responses are pre-fetched
//     into testdata/ and replayed via a SimpleGetter map.
//   - A failed verify never falls back to "best effort"; callers must
//     treat (nil, err) as "refuse the request".
package attest
