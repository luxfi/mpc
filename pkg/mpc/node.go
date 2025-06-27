package mpc

import (
	"bytes"
	"fmt"
	"math/big"
	"time"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/fystack/mpcium/pkg/common/errors"
	"github.com/fystack/mpcium/pkg/identity"
	"github.com/fystack/mpcium/pkg/keyinfo"
	"github.com/fystack/mpcium/pkg/kvstore"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/google/uuid"
)

const (
	PurposeKeygen string = "keygen"
	PurposeSign   string = "sign"
)

type ID string

type Node struct {
	nodeID  string
	peerIDs []string

	pubSub         messaging.PubSub
	direct         messaging.DirectMessaging
	kvstore        kvstore.KVStore
	keyinfoStore   keyinfo.Store
	ecdsaPreParams *keygen.LocalPreParams
	identityStore  identity.Store

	peerRegistry PeerRegistry
}

func CreatePartyID(nodeID string, label string) *tss.PartyID {
	partyID := uuid.NewString()
	key := big.NewInt(0).SetBytes([]byte(nodeID))
	return tss.NewPartyID(partyID, label, key)
}

func PartyIDToNodeID(partyID *tss.PartyID) string {
	return string(partyID.KeyInt().Bytes())
}

func ComparePartyIDs(x, y *tss.PartyID) bool {
	return bytes.Equal(x.KeyInt().Bytes(), y.KeyInt().Bytes())
}

func ComposeReadyKey(nodeID string) string {
	return fmt.Sprintf("ready/%s", nodeID)
}

func NewNode(
	nodeID string,
	peerIDs []string,
	pubSub messaging.PubSub,
	direct messaging.DirectMessaging,
	kvstore kvstore.KVStore,
	keyinfoStore keyinfo.Store,
	peerRegistry PeerRegistry,
	identityStore identity.Store,
) *Node {
	start := time.Now()
	preParams, err := keygen.GeneratePreParams(5 * time.Minute)
	if err != nil {
		logger.Fatal("Generate pre params failed", err)
	}
	elapsed := time.Since(start)
	logger.Info("Starting new node, preparams is generated successfully!", "elapsed", elapsed.Milliseconds())

	go peerRegistry.WatchPeersReady()

	return &Node{
		nodeID:         nodeID,
		peerIDs:        peerIDs,
		pubSub:         pubSub,
		direct:         direct,
		kvstore:        kvstore,
		keyinfoStore:   keyinfoStore,
		ecdsaPreParams: preParams,
		peerRegistry:   peerRegistry,
		identityStore:  identityStore,
	}
}

func (p *Node) ID() string {
	return p.nodeID
}

func (p *Node) CreateKeyGenSession(
	sessionType SessionType,
	walletID string,
	threshold int,
	successQueue messaging.MessageQueue,
) (KeyGenSession, error) {
	if !p.peerRegistry.ArePeersReady() {
		return nil, fmt.Errorf("Not enough peers to create gen session! Expected %d, got %d", threshold+1, p.peerRegistry.GetReadyPeersCount())
	}

	switch sessionType {
	case SessionTypeECDSA:
		return p.createECDSAKeyGenSession(walletID, threshold, successQueue)
	case SessionTypeEDDSA:
		return p.createEDDSAKeyGenSession(walletID, threshold, successQueue)
	default:
		return nil, fmt.Errorf("Unknown session type: %s", sessionType)
	}
}

func (p *Node) createECDSAKeyGenSession(walletID string, threshold int, successQueue messaging.MessageQueue) (KeyGenSession, error) {
	readyPeerIDs := p.peerRegistry.GetReadyPeersIncludeSelf()
	selfPartyID, allPartyIDs := p.generatePartyIDs(PurposeKeygen, readyPeerIDs)
	session := newECDSAKeygenSession(
		walletID,
		p.pubSub,
		p.direct,
		readyPeerIDs,
		selfPartyID,
		allPartyIDs,
		threshold,
		p.ecdsaPreParams,
		p.kvstore,
		p.keyinfoStore,
		successQueue,
		p.identityStore,
	)
	return session, nil
}

func (p *Node) createEDDSAKeyGenSession(walletID string, threshold int, successQueue messaging.MessageQueue) (KeyGenSession, error) {
	readyPeerIDs := p.peerRegistry.GetReadyPeersIncludeSelf()
	selfPartyID, allPartyIDs := p.generatePartyIDs(PurposeKeygen, readyPeerIDs)
	session := newEDDSAKeygenSession(
		walletID,
		p.pubSub,
		p.direct,
		readyPeerIDs,
		selfPartyID,
		allPartyIDs,
		threshold,
		p.kvstore,
		p.keyinfoStore,
		successQueue,
		p.identityStore,
	)
	return session, nil
}

func (p *Node) CreateSigningSession(
	sessionType SessionType,
	walletID string,
	txID string,
	networkInternalCode string,
	threshold int,
	resultQueue messaging.MessageQueue,
) (SigningSession, error) {
	readyPeerIDs := p.peerRegistry.GetReadyPeersIncludeSelf()
	selfPartyID, allPartyIDs := p.generatePartyIDs(PurposeKeygen, readyPeerIDs)
	switch sessionType {
	case SessionTypeECDSA:
		return newECDSASigningSession(
			walletID,
			txID,
			networkInternalCode,
			p.pubSub,
			p.direct,
			readyPeerIDs,
			selfPartyID,
			allPartyIDs,
			threshold,
			p.ecdsaPreParams,
			p.kvstore,
			p.keyinfoStore,
			resultQueue,
			p.identityStore,
		), nil
	case SessionTypeEDDSA:
		return NewEDDSASigningSession(
			walletID,
			txID,
			networkInternalCode,
			p.pubSub,
			p.direct,
			readyPeerIDs,
			selfPartyID,
			allPartyIDs,
			threshold,
			p.kvstore,
			p.keyinfoStore,
			resultQueue,
			p.identityStore,
		), nil
	}

	return nil, errors.New("Unknown session type")
}

func (p *Node) generatePartyIDs(purpose string, readyPeerIDs []string) (self *tss.PartyID, all []*tss.PartyID) {
	var selfPartyID *tss.PartyID
	partyIDs := make([]*tss.PartyID, len(readyPeerIDs))
	for i, peerID := range readyPeerIDs {
		if peerID == p.nodeID {
			selfPartyID = CreatePartyID(peerID, purpose)
			partyIDs[i] = selfPartyID
		} else {
			partyIDs[i] = CreatePartyID(peerID, purpose)
		}
	}
	allPartyIDs := tss.SortPartyIDs(partyIDs, 0)
	return selfPartyID, allPartyIDs
}

func (p *Node) Close() {
	err := p.peerRegistry.Resign()
	if err != nil {
		logger.Error("Resign failed", err)
	}
}
