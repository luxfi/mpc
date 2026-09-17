// Copyright (c) 2024-2026, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

// Node entry points for the threshold-FHE wallet ceremony.

package mpc

import (
	"fmt"

	"github.com/luxfi/mpc/pkg/messaging"
)

// CreateTFHEKeyGenSession starts a dealerless threshold-FHE key generation
// across the ready committee, yielding the collective public key and one
// Shamir share per node.
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
	selfPartyID, allPartyIDs := p.generatePartyIDs(PurposeKeygen, readyPeerIDs, 0)

	params, paramsLit, err := tfheParams()
	if err != nil {
		return nil, fmt.Errorf("mpc/tfhe: parameters: %w", err)
	}

	session, err := newTFHEKeygenSession(
		walletID,
		p.pubSub,
		selfPartyID,
		allPartyIDs,
		threshold,
		params,
		paramsLit,
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

// CreateTFHEComputeSession starts a session that encrypts under a wallet's
// collective public key and threshold-decrypts. It loads this node's single
// share.
func (p *Node) CreateTFHEComputeSession(
	sessionID string,
	walletID string,
	participantPeerIDs []string,
	resultQueue messaging.MessageQueue,
	orgID string,
) (Session, error) {
	if !contains(participantPeerIDs, p.nodeID) {
		return nil, ErrNotInParticipantList
	}

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
