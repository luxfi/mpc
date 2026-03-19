package mpc

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"

	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/threshold/pkg/party"
	blsThreshold "github.com/luxfi/threshold/protocols/bls"
	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog"

	"github.com/luxfi/mpc/pkg/event"
	"github.com/luxfi/mpc/pkg/identity"
	"github.com/luxfi/mpc/pkg/keyinfo"
	"github.com/luxfi/mpc/pkg/kvstore"
	"github.com/luxfi/mpc/pkg/messaging"
	"github.com/luxfi/mpc/pkg/types"
	"github.com/luxfi/mpc/pkg/utils"
)

// blsShareMessage is sent from the dealer to each party with their config share.
type blsShareMessage struct {
	SecretShare      []byte                      `json:"secret_share"`
	PublicKey        []byte                      `json:"public_key"`
	Threshold        int                         `json:"threshold"`
	TotalParties     int                         `json:"total_parties"`
	VerificationKeys map[party.ID][]byte         `json:"verification_keys"`
}

// BLSKeygenSession interface for BLS keygen
type BLSKeygenSession interface {
	Session
	// GetPublicKey returns the BLS group public key after keygen completes
	GetPublicKey() []byte
}

type blsKeygenSession struct {
	session
	config      *blsThreshold.Config
	resultMutex sync.Mutex
	done        bool
	resultErr   error
}

func newBLSKeygenSession(
	walletID string,
	pubSub messaging.PubSub,
	selfPartyID party.ID,
	partyIDs []party.ID,
	threshold int,
	kvstore kvstore.KVStore,
	keyinfoStore keyinfo.Store,
	resultQueue messaging.MessageQueue,
	identityStore identity.Store,
) *blsKeygenSession {
	return &blsKeygenSession{
		session: session{
			walletID:           walletID,
			pubSub:             pubSub,
			selfPartyID:        selfPartyID,
			partyIDs:           partyIDs,
			subscriberList:     []messaging.Subscription{},
			rounds:             1, // BLS keygen is single-round (dealer distributes)
			outCh:              make(chan msg, 100),
			errCh:              make(chan error, 10),
			finishCh:           make(chan bool, 1),
			externalFinishChan: make(chan string, 1),
			threshold:          threshold,
			kvstore:            kvstore,
			keyinfoStore:       keyinfoStore,
			resultQueue:        resultQueue,
			logger:             zerolog.New(utils.ZerologConsoleWriter()).With().Timestamp().Logger(),
			processing:         newDedupMap(),
			processingLock:     sync.Mutex{},
			topicComposer: &TopicComposer{
				ComposeBroadcastTopic: func() string {
					return fmt.Sprintf("keygen:broadcast:bls:%s", walletID)
				},
				ComposeDirectTopic: func(nodeID string) string {
					return fmt.Sprintf("keygen:direct:bls:%s:%s", nodeID, walletID)
				},
			},
			identityStore: identityStore,
		},
		done: false,
	}
}

// isDealer returns true if this node is the dealer (lowest sorted party ID).
func (s *blsKeygenSession) isDealer() bool {
	sorted := make([]string, len(s.partyIDs))
	for i, id := range s.partyIDs {
		sorted[i] = string(id)
	}
	sort.Strings(sorted)
	return sorted[0] == string(s.selfPartyID)
}

// ListenToIncomingMessageAsync subscribes to BLS keygen messages
func (s *blsKeygenSession) ListenToIncomingMessageAsync() {
	// Subscribe to direct messages (non-dealer nodes receive their share here)
	directTopic := s.topicComposer.ComposeDirectTopic(extractNodeID(string(s.selfPartyID)))
	directSub, err := s.pubSub.Subscribe(directTopic, func(m *nats.Msg) {
		s.logger.Debug().
			Str("topic", directTopic).
			Int("size", len(m.Data)).
			Msg("BLS: Received direct message")
		s.ProcessInboundMessage(m.Data)
	})

	if err != nil {
		s.logger.Error().Err(err).Msgf("BLS: Failed to subscribe to direct topic %s", directTopic)
		s.errCh <- err
		return
	}

	s.subscriberList = append(s.subscriberList, directSub)

	s.logger.Info().
		Str("direct", directTopic).
		Bool("isDealer", s.isDealer()).
		Msg("BLS: Listening to incoming messages")
}

func (s *blsKeygenSession) Init() {
	s.logger.Info().
		Str("walletID", s.walletID).
		Int("threshold", s.threshold).
		Int("partyCount", len(s.partyIDs)).
		Str("selfPartyID", string(s.selfPartyID)).
		Bool("isDealer", s.isDealer()).
		Msg("[BLS] Initializing BLS keygen session")
}

func (s *blsKeygenSession) ProcessInboundMessage(msgBytes []byte) {
	s.processingLock.Lock()
	defer s.processingLock.Unlock()

	// Unmarshal wire format
	inboundMessage := &types.Message{}
	if err := json.Unmarshal(msgBytes, inboundMessage); err != nil {
		s.logger.Error().Err(err).Msg("BLS: ProcessInboundMessage unmarshal error")
		return
	}

	// Verify Ed25519 signature on the wire message
	if err := s.verifyInboundSignature(inboundMessage); err != nil {
		s.logger.Warn().Err(err).Str("sender", inboundMessage.SenderNodeID).Msg("Dropping message with invalid signature")
		return
	}

	// Deduplication
	msgHashStr := fmt.Sprintf("%x", utils.GetMessageHash(inboundMessage.Body))
	if s.processing.seen(msgHashStr) {
		return
	}

	// Parse the share message
	var shareMsg blsShareMessage
	if err := json.Unmarshal(inboundMessage.Body, &shareMsg); err != nil {
		s.logger.Error().Err(err).Msg("BLS: Failed to unmarshal share message")
		return
	}

	// Reconstruct the BLS config from the share message
	sk, err := bls.SecretKeyFromBytes(shareMsg.SecretShare)
	if err != nil {
		s.logger.Error().Err(err).Msg("BLS: Failed to unmarshal secret share")
		s.errCh <- err
		return
	}

	pk, err := bls.PublicKeyFromCompressedBytes(shareMsg.PublicKey)
	if err != nil {
		s.logger.Error().Err(err).Msg("BLS: Failed to unmarshal public key")
		s.errCh <- err
		return
	}

	vks := make(map[party.ID]*bls.PublicKey, len(shareMsg.VerificationKeys))
	for id, vkBytes := range shareMsg.VerificationKeys {
		vk, err := bls.PublicKeyFromCompressedBytes(vkBytes)
		if err != nil {
			s.logger.Error().Err(err).Str("partyID", string(id)).Msg("BLS: Failed to unmarshal verification key")
			s.errCh <- err
			return
		}
		vks[id] = vk
	}

	s.resultMutex.Lock()
	s.config = blsThreshold.NewConfig(
		s.selfPartyID,
		shareMsg.Threshold,
		shareMsg.TotalParties,
		sk,
		pk,
		vks,
	)
	s.done = true
	s.resultMutex.Unlock()

	s.finishCh <- true
}

func (s *blsKeygenSession) ProcessOutboundMessage() {
	s.logger.Info().Msgf("BLS: ProcessOutboundMessage started: %s", s.walletID)

	if s.isDealer() {
		// Dealer: generate shares and distribute
		s.runDealer()
	}

	// Wait for finish (dealer finishes after distributing, non-dealer after receiving)
	select {
	case <-s.finishCh:
		s.logger.Info().Msg("BLS: Received finish message during ProcessOutboundMessage")
		s.publishResult()
		return
	case err := <-s.errCh:
		s.logger.Error().Err(err).Msg("BLS: Received error during ProcessOutboundMessage")
		s.resultMutex.Lock()
		s.resultErr = err
		s.resultMutex.Unlock()
		s.publishResult()
		return
	}
}

func (s *blsKeygenSession) runDealer() {
	ctx := context.Background()

	dealer := &blsThreshold.TrustedDealer{
		Threshold:    s.threshold,
		TotalParties: len(s.partyIDs),
	}

	shares, groupPK, err := dealer.GenerateShares(ctx, s.partyIDs)
	if err != nil {
		s.logger.Error().Err(err).Msg("BLS: Dealer failed to generate shares")
		s.resultMutex.Lock()
		s.resultErr = err
		s.resultMutex.Unlock()
		s.finishCh <- true
		return
	}

	// Get verification keys
	vks := blsThreshold.GetVerificationKeys(shares)

	// Serialize verification keys once
	vkBytes := make(map[party.ID][]byte, len(vks))
	for id, vk := range vks {
		vkBytes[id] = bls.PublicKeyToCompressedBytes(vk)
	}

	pkBytes := bls.PublicKeyToCompressedBytes(groupPK)

	// Send each party its share
	for _, partyID := range s.partyIDs {
		sk := shares[partyID]
		shareMsg := blsShareMessage{
			SecretShare:      bls.SecretKeyToBytes(sk),
			PublicKey:        pkBytes,
			Threshold:        s.threshold,
			TotalParties:     len(s.partyIDs),
			VerificationKeys: vkBytes,
		}

		body, err := json.Marshal(shareMsg)
		if err != nil {
			s.logger.Error().Err(err).Str("partyID", string(partyID)).Msg("BLS: Failed to marshal share for party")
			s.resultMutex.Lock()
			s.resultErr = err
			s.resultMutex.Unlock()
			s.finishCh <- true
			return
		}

		if partyID == s.selfPartyID {
			// Dealer stores its own config directly
			s.resultMutex.Lock()
			s.config = blsThreshold.NewConfig(
				s.selfPartyID,
				s.threshold,
				len(s.partyIDs),
				sk,
				groupPK,
				vks,
			)
			s.done = true
			s.resultMutex.Unlock()
			continue
		}

		// Send to other parties via direct message
		wireMsg := &types.Message{
			SessionID:    s.walletID,
			SenderID:     string(s.selfPartyID),
			RecipientIDs: []string{string(partyID)},
			Body:         body,
			IsBroadcast:  false,
		}

		s.sendMsg(wireMsg)

		s.logger.Info().
			Str("partyID", string(partyID)).
			Msg("BLS: Sent share to party")
	}

	// Dealer is done
	s.finishCh <- true
}

func (s *blsKeygenSession) publishResult() {
	s.resultMutex.Lock()
	defer s.resultMutex.Unlock()

	if s.resultErr != nil {
		s.logger.Error().Err(s.resultErr).Msg("BLS: keygen failed with error")
		failureEvent := event.CreateKeygenFailure(
			s.walletID,
			map[string]any{
				"error":    s.resultErr.Error(),
				"protocol": "BLS",
			},
		)
		evtData, _ := json.Marshal(failureEvent)
		if err := s.resultQueue.Enqueue(fmt.Sprintf("mpc.mpc_keygen_result.%s", s.walletID), evtData, nil); err != nil {
			s.logger.Error().Err(err).Msg("BLS: failed to publish keygen failure event")
		}
		// Always send to externalFinishChan so WaitForFinish() doesn't block forever
		s.externalFinishChan <- ""
		return
	}

	if s.config == nil {
		s.logger.Error().Msg("BLS: No config available after keygen completion")
		s.externalFinishChan <- ""
		return
	}

	// Save key share with bls prefix using CBOR
	shareBytes, err := MarshalBLSConfig(s.config)
	if err != nil {
		s.logger.Error().Err(err).Msg("BLS: Failed to marshal key share")
		s.externalFinishChan <- ""
		return
	}

	blsKey := fmt.Sprintf("bls:%s", s.walletID)
	if err := s.kvstore.Put(blsKey, shareBytes); err != nil {
		s.logger.Error().Err(err).Msgf("BLS: Failed to save key share for wallet %s", s.walletID)
		s.externalFinishChan <- ""
		return
	}

	// Get public key hex
	var pubKeyHex string
	pkBytes := bls.PublicKeyToCompressedBytes(s.config.PublicKey)
	if len(pkBytes) > 0 {
		pubKeyHex = fmt.Sprintf("%x", pkBytes)
		s.logger.Info().
			Int("configPubKeyLen", len(pkBytes)).
			Str("pubKeyHex", pubKeyHex).
			Msg("[BLS-PUBLISH] PublicKey available")
	} else {
		s.logger.Warn().Msg("[BLS-PUBLISH] PublicKey is empty!")
	}

	// Notify via external finish channel
	s.externalFinishChan <- pubKeyHex

	s.logger.Info().
		Str("walletID", s.walletID).
		Str("publicKey", pubKeyHex).
		Msg("BLS keygen completed successfully")
}

func (s *blsKeygenSession) Stop() {
	close(s.outCh)
	close(s.errCh)
}

func (s *blsKeygenSession) WaitForFinish() string {
	return <-s.externalFinishChan
}

// GetPublicKey returns the BLS group public key after keygen completes
func (s *blsKeygenSession) GetPublicKey() []byte {
	s.resultMutex.Lock()
	defer s.resultMutex.Unlock()
	if s.config != nil && s.config.PublicKey != nil {
		return bls.PublicKeyToCompressedBytes(s.config.PublicKey)
	}
	return nil
}
