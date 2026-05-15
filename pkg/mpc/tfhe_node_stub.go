// Copyright (c) 2026, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

//go:build !experimental_tfhe

// Default-build stub for the threshold-FHE wallet ceremony. The real
// implementation lives in tfhe_node.go behind the `experimental_tfhe` build
// tag. Production builds reject every caller with ErrTFHENotImplemented
// because the upstream luxfi/threshold/protocols/tfhe primitive is a
// fail-loud placeholder (every party stores the full master key — see
// lps/LP-137-TFHE-REAL-THRESHOLD-SPEC.md §2.6).

package mpc

import "github.com/luxfi/mpc/pkg/messaging"

// CreateTFHEKeyGenSession returns ErrTFHENotImplemented in default builds.
// Compile with `-tags experimental_tfhe` to opt into the placeholder UNSAFE
// primitive (which itself requires ALLOW_FAKE_TFHE_FOR_TESTING_ONLY=1 at
// runtime to avoid panicking — by design).
func (p *Node) CreateTFHEKeyGenSession(
	walletID string,
	threshold int,
	resultQueue messaging.MessageQueue,
	orgID string,
) (Session, error) {
	_ = walletID
	_ = threshold
	_ = resultQueue
	_ = orgID
	return nil, ErrTFHENotImplemented
}

// CreateTFHEComputeSession returns ErrTFHENotImplemented in default builds.
// See CreateTFHEKeyGenSession for the rationale.
func (p *Node) CreateTFHEComputeSession(
	sessionID string,
	walletID string,
	participantPeerIDs []string,
	resultQueue messaging.MessageQueue,
	orgID string,
) (Session, error) {
	_ = sessionID
	_ = walletID
	_ = participantPeerIDs
	_ = resultQueue
	_ = orgID
	return nil, ErrTFHENotImplemented
}
