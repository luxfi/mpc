package mpc

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/luxfi/cggmp21/pkg/party"
	"github.com/luxfi/mpc/pkg/common/errors"
	"github.com/luxfi/mpc/pkg/identity"
	"github.com/luxfi/mpc/pkg/keyinfo"
	"github.com/luxfi/mpc/pkg/kvstore"
	"github.com/luxfi/mpc/pkg/logger"
	"github.com/luxfi/mpc/pkg/messaging"
)

const (
	PurposeKeygen  string = "keygen"
	PurposeSign    string = "sign"
	PurposeReshare string = "reshare"

	DefaultVersion int = 1
)

type ID string

type Node struct {
	nodeID        string
	peerIDs       []string
	pubSub        messaging.PubSub
	kvstore       kvstore.KVStore
	keyinfoStore  keyinfo.Store
	identityStore identity.Store
	peerRegistry  PeerRegistry
}

func ComposeReadyKey(nodeID string) string {
	return fmt.Sprintf("ready/%s", nodeID)
}

func NewNode(
	nodeID string,
	peerIDs []string,
	pubSub messaging.PubSub,
	kvstore kvstore.KVStore,
	keyinfoStore keyinfo.Store,
	peerRegistry PeerRegistry,
	identityStore identity.Store,
) *Node {
	start := time.Now()
	elapsed := time.Since(start)
	logger.Info("Starting new CGGMP21 node", "nodeID", nodeID, "elapsed", elapsed.Milliseconds())

	node := &Node{
		nodeID:        nodeID,
		peerIDs:       peerIDs,
		pubSub:        pubSub,
		kvstore:       kvstore,
		keyinfoStore:  keyinfoStore,
		peerRegistry:  peerRegistry,
		identityStore: identityStore,
	}

	go peerRegistry.WatchPeersReady()
	return node
}

func (p *Node) ID() string {
	return p.nodeID
}

func (p *Node) CreateKeyGenSession(
	walletID string,
	threshold int,
	resultQueue messaging.MessageQueue,
) (KeyGenSession, error) {
	if !p.peerRegistry.ArePeersReady() {
		return nil, fmt.Errorf(
			"peers are not ready yet. ready: %d, expected: %d",
			len(p.peerRegistry.GetReadyPeers()),
			len(p.peerIDs)+1,
		)
	}

	readyPeerIDs := p.peerRegistry.GetReadyPeersIncludeSelf()
	selfPartyID, allPartyIDs := p.generatePartyIDs(PurposeKeygen, readyPeerIDs, DefaultVersion)
	
	session := newCGGMP21KeygenSession(
		walletID,
		p.pubSub,
		selfPartyID,
		allPartyIDs,
		threshold,
		p.kvstore,
		p.keyinfoStore,
		resultQueue,
		p.identityStore,
	)
	
	session.Init()
	return session, nil
}

func (p *Node) CreateSignSession(
	sessionID string,
	walletID string,
	messageHash []byte,
	signerPeerIDs []string,
	resultQueue messaging.MessageQueue,
	useBroadcast bool,
) (SignSession, error) {
	// Check if we have enough signers
	keyInfo, err := p.keyinfoStore.Get(walletID)
	if err != nil {
		return nil, fmt.Errorf("failed to get key info: %w", err)
	}

	if len(signerPeerIDs) < keyInfo.Threshold+1 {
		return nil, ErrNotEnoughParticipants
	}

	// Check if this node is in the signer list
	if !contains(signerPeerIDs, p.nodeID) {
		return nil, ErrNotInParticipantList
	}

	// Generate party IDs for signers
	version := p.getVersion(SessionTypeCGGMP21, walletID)
	selfPartyID, signerPartyIDs := p.generatePartyIDs(PurposeSign, signerPeerIDs, version)

	session, err := newCGGMP21SigningSession(
		sessionID,
		walletID,
		messageHash,
		p.pubSub,
		selfPartyID,
		signerPartyIDs,
		p.kvstore,
		p.keyinfoStore,
		resultQueue,
		p.identityStore,
		useBroadcast,
	)
	if err != nil {
		return nil, err
	}

	session.Init()
	return session, nil
}

func (p *Node) generatePartyIDs(purpose string, peerIDs []string, version int) (party.ID, []party.ID) {
	partyIDs := make([]party.ID, len(peerIDs))
	var selfPartyID party.ID

	for i, peerID := range peerIDs {
		partyID := createPartyID(peerID, purpose, version)
		partyIDs[i] = partyID
		if peerID == p.nodeID {
			selfPartyID = partyID
		}
	}

	return selfPartyID, partyIDs
}

func createPartyID(sessionID string, keyType string, version int) party.ID {
	if version == 0 {
		// Backward compatible version - just use sessionID
		return party.ID(sessionID)
	}
	// Include version in party ID
	return party.ID(fmt.Sprintf("%s:%s:%d", sessionID, keyType, version))
}

func (p *Node) getVersion(sessionType SessionType, walletID string) int {
	// In production, you might want to store and retrieve version info
	// For now, always use the default version
	return DefaultVersion
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}