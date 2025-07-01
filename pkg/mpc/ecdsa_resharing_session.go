package mpc

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/resharing"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/fystack/mpcium/pkg/common/errors"
	"github.com/fystack/mpcium/pkg/encoding"
	"github.com/fystack/mpcium/pkg/identity"
	"github.com/fystack/mpcium/pkg/keyinfo"
	"github.com/fystack/mpcium/pkg/kvstore"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
)

const (
	TypeReshareSuccess = "mpc.mpc_reshare_success.%s"
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
	reshareParams *tss.ReSharingParameters
	endCh         chan *keygen.LocalPartySaveData
}

type ReshareSuccessEvent struct {
	WalletID    string `json:"wallet_id"`
	ECDSAPubKey []byte `json:"ecdsa_pub_key"`
	EDDSAPubKey []byte `json:"eddsa_pub_key"`
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
	isNewParty bool,
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
		endCh:         make(chan *keygen.LocalPartySaveData),
	}
}

func (s *ecdsaReshareSession) Init() {
	logger.Infof("Initializing resharing session with partyID: %s, peerIDs %s", s.selfPartyID, s.partyIDs)
	var share keygen.LocalPartySaveData
	if s.isNewParty {
		// Initialize empty share data for new party
		share = keygen.NewLocalPartySaveData(len(s.partyIDs))
		share.LocalPreParams = *s.preParams
	} else {
		keyData, err := s.kvstore.Get(s.composeKey(s.walletID))
		if err != nil {
			s.ErrCh <- errors.Wrap(err, "Failed to get wallet data from KVStore")
			return
		}

		err = json.Unmarshal(keyData, &share)
		if err != nil {
			s.ErrCh <- fmt.Errorf("failed to unmarshal wallet data: %w", err)
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
			keyBytes, err := json.Marshal(saveData)
			if err != nil {
				s.ErrCh <- err
				return
			}

			if err := s.kvstore.Put(s.composeKey(s.walletID), keyBytes); err != nil {
				s.ErrCh <- err
				return
			}

			keyInfo := keyinfo.KeyInfo{
				ParticipantPeerIDs: s.participantPeerIDs,
				Threshold:          s.reshareParams.NewThreshold(),
			}

			// Save key info with resharing flag
			if err := s.keyinfoStore.Save(s.composeKey(s.walletID), &keyInfo); err != nil {
				s.ErrCh <- err
				return
			}

			// skip for old committee
			if saveData.ECDSAPub != nil {
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
			err = s.Close()
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
