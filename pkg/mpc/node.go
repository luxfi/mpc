package mpc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"slices"
	"strconv"
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
	PurposeKeygen  string = "keygen"
	PurposeSign    string = "sign"
	PurposeReshare string = "reshare"

	BackwardCompatibleVersion int = 0
	DefaultVersion            int = 1
)

type ID string

type Node struct {
	nodeID  string
	peerIDs []string

	pubSub         messaging.PubSub
	direct         messaging.DirectMessaging
	kvstore        kvstore.KVStore
	keyinfoStore   keyinfo.Store
	ecdsaPreParams []*keygen.LocalPreParams
	identityStore  identity.Store

	peerRegistry PeerRegistry
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
	elapsed := time.Since(start)
	logger.Info("Starting new node, preparams is generated successfully!", "elapsed", elapsed.Milliseconds())

	node := &Node{
		nodeID:        nodeID,
		peerIDs:       peerIDs,
		pubSub:        pubSub,
		direct:        direct,
		kvstore:       kvstore,
		keyinfoStore:  keyinfoStore,
		peerRegistry:  peerRegistry,
		identityStore: identityStore,
	}
	node.ecdsaPreParams = node.generatePreParams()

	go peerRegistry.WatchPeersReady()
	return node
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
		return p.createECDSAKeyGenSession(walletID, threshold, DefaultVersion, successQueue)
	case SessionTypeEDDSA:
		return p.createEDDSAKeyGenSession(walletID, threshold, DefaultVersion, successQueue)
	default:
		return nil, fmt.Errorf("Unknown session type: %s", sessionType)
	}
}

func (p *Node) createECDSAKeyGenSession(walletID string, threshold int, version int, successQueue messaging.MessageQueue) (KeyGenSession, error) {
	readyPeerIDs := p.peerRegistry.GetReadyPeersIncludeSelf()
	selfPartyID, allPartyIDs := p.generatePartyIDs(PurposeKeygen, readyPeerIDs, version)
	session := newECDSAKeygenSession(
		walletID,
		p.pubSub,
		p.direct,
		readyPeerIDs,
		selfPartyID,
		allPartyIDs,
		threshold,
		p.ecdsaPreParams[0],
		p.kvstore,
		p.keyinfoStore,
		successQueue,
		p.identityStore,
	)
	return session, nil
}

func (p *Node) createEDDSAKeyGenSession(walletID string, threshold int, version int, successQueue messaging.MessageQueue) (KeyGenSession, error) {
	readyPeerIDs := p.peerRegistry.GetReadyPeersIncludeSelf()
	selfPartyID, allPartyIDs := p.generatePartyIDs(PurposeKeygen, readyPeerIDs, version)
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
	version := p.getVersion(sessionType, walletID)
	readyPeerIDs := p.peerRegistry.GetReadyPeersIncludeSelf()
	selfPartyID, allPartyIDs := p.generatePartyIDs(PurposeKeygen, readyPeerIDs, version)
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
			p.ecdsaPreParams[0],
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

func (p *Node) CreateReshareSession(
	sessionType SessionType,
	walletID string,
	oldThreshold int,
	newThreshold int,
	newPeerIDs []string,
	isNewPeer bool,
	successQueue messaging.MessageQueue,
) (ReshareSession, error) {
	if !p.peerRegistry.ArePeersReady() {
		return nil, fmt.Errorf("Not enough peers to create reshare session! Expected %d, got %d", newThreshold+1, p.peerRegistry.GetReadyPeersCount())
	}
	readyPeerIDs := p.peerRegistry.GetReadyPeersIncludeSelf()
	for _, peerID := range newPeerIDs {
		if slices.Contains(readyPeerIDs, peerID) {
			continue
		}
		return nil, fmt.Errorf("new peer %s is not ready", peerID)
	}

	// if current node is not in newPeerIDs and isNewPeer is true, return nil
	if !slices.Contains(newPeerIDs, p.nodeID) && isNewPeer {
		return nil, nil
	}

	version := p.getVersion(sessionType, walletID)
	var (
		selfPartyID *tss.PartyID
		preParams   *keygen.LocalPreParams
	)
	oldSelf, oldAllPartyIDs := p.generatePartyIDs(PurposeKeygen, readyPeerIDs, version)
	newSelf, newAllPartyIDs := p.generatePartyIDs(PurposeReshare, newPeerIDs, version+1)
	if isNewPeer {
		selfPartyID = newSelf
		preParams = p.ecdsaPreParams[1]
	} else {
		selfPartyID = oldSelf
		preParams = p.ecdsaPreParams[0]
	}
	switch sessionType {
	case SessionTypeECDSA:
		return NewECDSAReshareSession(
			walletID,
			p.pubSub,
			p.direct,
			readyPeerIDs,
			selfPartyID,
			oldAllPartyIDs,
			newAllPartyIDs,
			oldThreshold,
			newThreshold,
			preParams,
			p.kvstore,
			p.keyinfoStore,
			successQueue,
			p.identityStore,
			isNewPeer,
		), nil
	case SessionTypeEDDSA:
		return NewEDDSAReshareSession(
			walletID,
			p.pubSub,
			p.direct,
			readyPeerIDs,
			selfPartyID,
			oldAllPartyIDs,
			newAllPartyIDs,
			oldThreshold,
			newThreshold,
			p.kvstore,
			p.keyinfoStore,
			successQueue,
			p.identityStore,
			isNewPeer,
		), nil
	default:
		return nil, errors.New("Unknown session type")
	}
}

// generatePartyIDs generates the party IDs for the given purpose and version
// It returns the self party ID and all party IDs
// It also sorts the party IDs in place
func (n *Node) generatePartyIDs(
	label string,
	readyPeerIDs []string,
	version int,
) (self *tss.PartyID, all []*tss.PartyID) {
	// Pre-allocate slice with exact size needed
	partyIDs := make([]*tss.PartyID, 0, len(readyPeerIDs))

	// Create all party IDs in one pass
	for _, peerID := range readyPeerIDs {
		partyID := createPartyID(peerID, label, version)
		if peerID == n.nodeID {
			self = partyID
		}
		partyIDs = append(partyIDs, partyID)
	}

	// Sort party IDs in place
	all = tss.SortPartyIDs(partyIDs, 0)
	return
}

// createPartyID creates a new party ID for the given node ID, label and version
// It returns the party ID: random string
// Moniker: for routing messages
// Key: for mpc internal use (need persistent storage)
func createPartyID(nodeID string, label string, version int) *tss.PartyID {
	partyID := uuid.NewString()
	var key *big.Int
	if version == BackwardCompatibleVersion {
		key = big.NewInt(0).SetBytes([]byte(nodeID))
	} else {
		key = big.NewInt(0).SetBytes([]byte(nodeID + ":" + strconv.Itoa(version)))
	}
	return tss.NewPartyID(partyID, label, key)
}

func (p *Node) Close() {
	err := p.peerRegistry.Resign()
	if err != nil {
		logger.Error("Resign failed", err)
	}
}

func (p *Node) generatePreParams() []*keygen.LocalPreParams {
	start := time.Now()
	// Try to load from kvstore
	preParams := make([]*keygen.LocalPreParams, 2)
	for i := 0; i < 2; i++ {
		key := fmt.Sprintf("pre_params_%d", i)
		val, err := p.kvstore.Get(key)
		if err == nil && val != nil {
			preParams[i] = &keygen.LocalPreParams{}
			err = json.Unmarshal(val, preParams[i])
			if err != nil {
				logger.Fatal("Unmarshal pre params failed", err)
			}
			continue
		}
		// Not found, generate and save
		params, err := keygen.GeneratePreParams(5 * time.Minute)
		if err != nil {
			logger.Fatal("Generate pre params failed", err)
		}
		bytes, err := json.Marshal(params)
		if err != nil {
			logger.Fatal("Marshal pre params failed", err)
		}
		err = p.kvstore.Put(key, bytes)
		if err != nil {
			logger.Fatal("Save pre params failed", err)
		}
		preParams[i] = params
	}
	logger.Info("Generate pre params successfully!", "elapsed", time.Since(start).Milliseconds())
	return preParams
}

func (p *Node) getVersion(sessionType SessionType, walletID string) int {
	var composeKey string
	switch sessionType {
	case SessionTypeECDSA:
		composeKey = fmt.Sprintf("ecdsa:%s", walletID)
	case SessionTypeEDDSA:
		composeKey = fmt.Sprintf("eddsa:%s", walletID)
	default:
		logger.Fatal("Unknown session type", errors.New("Unknown session type"))
	}
	keyinfo, err := p.keyinfoStore.Get(composeKey)
	if err != nil {
		logger.Error("Get keyinfo failed", err, "walletID", walletID)
		return DefaultVersion
	}
	return keyinfo.Version
}
