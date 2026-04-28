// Copyright (c) 2024-2026, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

//go:build experimental_tfhe

// Experimental TFHE wallet ceremony wiring on Node. Default builds use
// tfhe_node_stub.go which returns ErrTFHENotImplemented.

package mpc

import (
	"fmt"

	"github.com/luxfi/fhe"

	"github.com/luxfi/mpc/pkg/messaging"
)

// CreateTFHEKeyGenSession creates a threshold FHE key generation session.
// EXPERIMENTAL: backed by the placeholder UNSAFE primitive in
// luxfi/threshold/protocols/tfhe (every party stores the full master key).
// Compile with `-tags experimental_tfhe` to enable; production must wait for
// real Shamir/LWE wiring per LP-137 §2.6.
func (p *Node) CreateTFHEKeyGenSession(
	walletID string,
	threshold int,
	resultQueue messaging.MessageQueue,
	orgID string,
) (Session, error) {
	if !p.peerRegistry.ArePeersReady() {
		return nil, fmt.Errorf(
			"peers are not ready yet. ready: %d, expected: %d",
			p.peerRegistry.GetReadyPeersCount(),
			len(p.peerIDs)+1,
		)
	}

	readyPeerIDs := p.peerRegistry.GetReadyPeersIncludeSelf()
	// TFHE uses version 0 for raw party IDs
	selfPartyID, allPartyIDs := p.generatePartyIDs(PurposeKeygen, readyPeerIDs, 0)

	// Use default FHE parameters (128-bit security)
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		return nil, fmt.Errorf("failed to create FHE parameters: %w", err)
	}

	session := newTFHEKeygenSession(
		walletID,
		p.pubSub,
		selfPartyID,
		allPartyIDs,
		threshold,
		params,
		p.kvstore,
		p.keyinfoStore,
		resultQueue,
		p.identityStore,
		orgID,
	)

	return session, nil
}

// CreateTFHEComputeSession creates a session for threshold FHE computation.
// EXPERIMENTAL: backed by the placeholder UNSAFE primitive in
// luxfi/threshold/protocols/tfhe.
func (p *Node) CreateTFHEComputeSession(
	sessionID string,
	walletID string,
	participantPeerIDs []string,
	resultQueue messaging.MessageQueue,
	orgID string,
) (Session, error) {
	// Check if this node is in the participant list
	if !contains(participantPeerIDs, p.nodeID) {
		return nil, ErrNotInParticipantList
	}

	// Generate party IDs for participants
	selfPartyID, participantPartyIDs := p.generatePartyIDs(PurposeKeygen, participantPeerIDs, 0)

	session, err := newTFHEComputeSession(
		sessionID,
		walletID,
		p.pubSub,
		selfPartyID,
		participantPartyIDs,
		p.kvstore,
		p.keyinfoStore,
		resultQueue,
		p.identityStore,
		orgID,
	)
	if err != nil {
		return nil, err
	}

	return session, nil
}
