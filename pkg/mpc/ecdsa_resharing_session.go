package mpc

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/resharing"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/luxfi/mpc/pkg/encoding"
	"github.com/luxfi/mpc/pkg/identity"
	"github.com/luxfi/mpc/pkg/keyinfo"
	"github.com/luxfi/mpc/pkg/kvstore"
	"github.com/luxfi/mpc/pkg/logger"
	"github.com/luxfi/mpc/pkg/messaging"
)

type ReshareSession interface {
	Session
	Init()
	Reshare(done func())
	GetPubKeyResult() []byte
}

type ecdsaReshareSession struct {
	*session
	isNewParty    bool
	newPeerIDs    []string
	reshareParams *tss.ReSharingParameters
	endCh         chan *keygen.LocalPartySaveData
}

func NewECDSAReshareSession(
	walletID string,
	pubSub messaging.PubSub,
	direct messaging.DirectMessaging,
	participantPeerIDs []string,
	selfID *tss.PartyID,
	oldPartyIDs []*tss.PartyID,
	newPartyIDs []*tss.PartyID,
	threshold int,
	newThreshold int,
	preParams *keygen.LocalPreParams,
	kvstore kvstore.KVStore,
	keyinfoStore keyinfo.Store,
	resultQueue messaging.MessageQueue,
	identityStore identity.Store,
	newPeerIDs []string,
	isNewParty bool,
	version int,
) *ecdsaReshareSession {
	session := session{
		walletID:           walletID,
		pubSub:             pubSub,
		direct:             direct,
		threshold:          threshold,
		participantPeerIDs: participantPeerIDs,
		selfPartyID:        selfID,
		partyIDs:           newPartyIDs,
		outCh:              make(chan tss.Message),
		ErrCh:              make(chan error),
		preParams:          preParams,
		kvstore:            kvstore,
		keyinfoStore:       keyinfoStore,
		version:            version,
		topicComposer: &TopicComposer{
			ComposeBroadcastTopic: func() string {
				return fmt.Sprintf("resharing:broadcast:ecdsa:%s", walletID)
			},
			ComposeDirectTopic: func(nodeID string) string {
				return fmt.Sprintf("resharing:direct:ecdsa:%s:%s", nodeID, walletID)
			},
		},
		composeKey: func(walletID string) string {
			return fmt.Sprintf("ecdsa:%s", walletID)
		},
		getRoundFunc:  GetEcdsaMsgRound,
		resultQueue:   resultQueue,
		sessionType:   SessionTypeECDSA,
		identityStore: identityStore,
	}
	reshareParams := tss.NewReSharingParameters(
		tss.S256(),
		tss.NewPeerContext(oldPartyIDs),
		tss.NewPeerContext(newPartyIDs),
		selfID,
		len(oldPartyIDs),
		threshold,
		len(newPartyIDs),
		newThreshold,
	)
	return &ecdsaReshareSession{
		session:       &session,
		reshareParams: reshareParams,
		isNewParty:    isNewParty,
		newPeerIDs:    newPeerIDs,
		endCh:         make(chan *keygen.LocalPartySaveData),
	}
}

func (s *ecdsaReshareSession) Init() {
	logger.Infof("Initializing resharing session with partyID: %s, newPartyIDs %s", s.selfPartyID, s.partyIDs)
	var share keygen.LocalPartySaveData

	if s.isNewParty {
		// New party → generate empty share
		share = keygen.NewLocalPartySaveData(len(s.partyIDs))
		share.LocalPreParams = *s.preParams
	} else {
		err := s.loadOldShareDataGeneric(s.walletID, s.GetVersion(), &share)
		if err != nil {
			s.ErrCh <- err
			return
		}
	}

	s.party = resharing.NewLocalParty(s.reshareParams, share, s.outCh, s.endCh)

	logger.Infof("[INITIALIZED] Initialized resharing session successfully partyID: %s, peerIDs %s, walletID %s, oldThreshold = %d, newThreshold = %d",
		s.selfPartyID, s.partyIDs, s.walletID, s.threshold, s.reshareParams.NewThreshold())
}

func (s *ecdsaReshareSession) Reshare(done func()) {
	logger.Info("Starting resharing", "walletID", s.walletID, "partyID", s.selfPartyID)
	go func() {
		if err := s.party.Start(); err != nil {
			s.ErrCh <- err
		}
	}()

	for {
		select {
		case saveData := <-s.endCh:
			// skip for old committee
			if saveData.ECDSAPub != nil {

				keyBytes, err := json.Marshal(saveData)
				if err != nil {
					s.ErrCh <- err
					return
				}

				newVersion := s.GetVersion() + 1
				key := s.composeKey(walletIDWithVersion(s.walletID, newVersion))
				if err := s.kvstore.Put(key, keyBytes); err != nil {
					s.ErrCh <- err
					return
				}

				keyInfo := keyinfo.KeyInfo{
					ParticipantPeerIDs: s.newPeerIDs,
					Threshold:          s.reshareParams.NewThreshold(),
					Version:            newVersion,
				}

				// Save key info with resharing flag
				if err := s.keyinfoStore.Save(s.composeKey(s.walletID), &keyInfo); err != nil {
					s.ErrCh <- err
					return
				}
				// Get public key
				publicKey := saveData.ECDSAPub
				pubKey := &ecdsa.PublicKey{
					Curve: publicKey.Curve(),
					X:     publicKey.X(),
					Y:     publicKey.Y(),
				}

				pubKeyBytes, err := encoding.EncodeS256PubKey(pubKey)
				if err != nil {
					logger.Error("failed to encode public key", err)
					s.ErrCh <- fmt.Errorf("failed to encode public key: %w", err)
					return
				}

				// Set the public key bytes
				s.pubkeyBytes = pubKeyBytes
				logger.Info("Generated public key bytes",
					"walletID", s.walletID,
					"pubKeyBytes", pubKeyBytes)
			}

			done()
			err := s.Close()
			if err != nil {
				logger.Error("Failed to close session", err)
			}
			return
		case msg := <-s.outCh:
			// Handle the message
			s.handleTssMessage(msg)
		}
	}
}
