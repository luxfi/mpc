// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

// Package attest is a TRANSITION ADAPTER. The canonical attestation
// verifier was extracted into the orthogonal leaf module
// github.com/luxfi/cc (one verifier, depended on by mpc/tee/ai, coupled to
// none). New code — including all mpc-internal consumers (pkg/kms,
// pkg/attestation) — imports github.com/luxfi/cc/attest directly.
//
// This package exists ONLY so the single external consumer that is still
// pinned to a pre-extraction luxfi/mpc — github.com/luxfi/threshold v1.9.9,
// whose pkg/thresholdd/tee_options.go imports github.com/luxfi/mpc/cc/attest
// and references attest.KindNRAS — keeps building. threshold's main branch
// has already dropped this import (the TEE custody code moved to luxfi/tee);
// mpc cannot bump to it yet because mpc/pkg/mpc still imports
// threshold/protocols/tfhe, which that same threshold branch removed.
//
// Every symbol here is a zero-logic re-export (type aliases preserve type
// identity with the leaf — a value produced by github.com/luxfi/cc/attest is
// the SAME type as the one named here). REMOVE this package once threshold
// republishes against the leaf and mpc's tfhe dependency is resolved.
package attest

import cc "github.com/luxfi/cc/attest"

// Re-exported types. Type aliases ⇒ identical types to the leaf, so the
// kms.CompositeAttestation release-gate interface is satisfied by values
// from either import path.
type (
	Kind           = cc.Kind
	Option         = cc.Option
	Verifier       = cc.Verifier
	VerifiedReport = cc.VerifiedReport
	SEVSNP         = cc.SEVSNP
	TDX            = cc.TDX
	NVTrust        = cc.NVTrust
)

// Re-exported kinds. KindNRAS is the deprecated name for the NVIDIA GPU
// kind; it is retained ONLY for threshold v1.9.9 (which references it) and
// resolves to the canonical KindNVTrust value. New code uses KindNVTrust.
const (
	KindSEVSNP  = cc.KindSEVSNP
	KindTDX     = cc.KindTDX
	KindNVTrust = cc.KindNVTrust

	// Deprecated: transitional alias for github.com/luxfi/threshold v1.9.9.
	KindNRAS = cc.KindNVTrust
)

// Re-exported sentinel errors. Same values ⇒ errors.Is works across both
// import paths.
var (
	ErrUnsupportedKind  = cc.ErrUnsupportedKind
	ErrInvalidEvidence  = cc.ErrInvalidEvidence
	ErrChainInvalid     = cc.ErrChainInvalid
	ErrSignatureInvalid = cc.ErrSignatureInvalid
	ErrPolicy           = cc.ErrPolicy
	ErrNotImplemented   = cc.ErrNotImplemented
)

// Re-exported constructors / entry points.
var (
	Dispatch                = cc.Dispatch
	WithExpectedReportData  = cc.WithExpectedReportData
	WithExpectedMeasurement = cc.WithExpectedMeasurement
	WithNow                 = cc.WithNow
	WithKDSGetter           = cc.WithKDSGetter
	WithNVTrustRIM          = cc.WithNVTrustRIM
	WithNVTrustTrustRoots   = cc.WithNVTrustTrustRoots
)
