package mpc

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/threshold/pkg/party"
	blsThreshold "github.com/luxfi/threshold/protocols/bls"
	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog"

	"github.com/luxfi/mpc/pkg/encoding"
	"github.com/luxfi/mpc/pkg/event"
	"github.com/luxfi/mpc/pkg/identity"
	"github.com/luxfi/mpc/pkg/keyinfo"
	"github.com/luxfi/mpc/pkg/kvstore"
	"github.com/luxfi/mpc/pkg/messaging"
	"github.com/luxfi/mpc/pkg/types"
	"github.com/luxfi/mpc/pkg/utils"
)

// blsSignShareMessage is broadcast by each signer with their partial signature.
type blsSignShareMessage struct {
	PartyID   party.ID `json:"party_id"`
	Signature []byte   `json:"signature"` // BLS signature bytes (96 bytes, compressed G2)
}

// BLSSignSession is the interface for BLS signing sessions
type BLSSignSession interface {
	Session
}

type blsSigningSession struct {
	session
	config      *blsThreshold.Config
	messageHash []byte
	signerIDs   []party.ID

	resultMutex sync.Mutex
	done        bool
	resultErr   error

	// Collected signature shares from all signers
	shares     []*blsThreshold.SignatureShare
	sharesLock sync.Mutex
}

func newBLSSigningSession(
	sessionID string,
	walletID string,
	messageHash []byte,
	pubSub messaging.PubSub,
	selfPartyID party.ID,
	signerIDs []party.ID,
	kvstore kvstore.KVStore,
	keyinfoStore keyinfo.Store,
	resultQueue messaging.MessageQueue,
	identityStore identity.Store,
	orgID string,
) (*blsSigningSession, error) {
	// Load and unmarshal key share inside withSecretErasure so that raw
	// share bytes on the stack are zeroed after parsing completes.
	blsKey := fmt.Sprintf("bls:%s", walletID)
	var config *blsThreshold.Config
	var loadErr error
	withSecretErasure(func() {
		shareBytes, err := GetKeyShareWithFallback(kvstore, orgID, blsKey)
		if err != nil {
			loadErr = fmt.Errorf("failed to get BLS key share: %w", err)
			return
		}
		config, err = UnmarshalBLSConfig(shareBytes)
		if err != nil {
			loadErr = fmt.Errorf("failed to unmarshal BLS key share: %w", err)
		}
	})
	if loadErr != nil {
		return nil, loadErr
	}

	return &blsSigningSession{
		session: session{
			walletID:           walletID,
			sessionID:          sessionID,
			pubSub:             pubSub,
			selfPartyID:        selfPartyID,
			partyIDs:           signerIDs,
			subscriberList:     []messaging.Subscription{},
			rounds:             1, // BLS signing is single-round (sign + aggregate)
			outCh:              make(chan msg, 100),
			errCh:              make(chan error, 10),
			finishCh:           make(chan bool, 1),
			externalFinishChan: make(chan string, 1),
			threshold:          config.Threshold,
			kvstore:            kvstore,
			keyinfoStore:       keyinfoStore,
			resultQueue:        resultQueue,
			logger:             zerolog.New(utils.ZerologConsoleWriter()).With().Timestamp().Logger(),
			processing:         newDedupMap(),
			processingLock:     sync.Mutex{},
			topicComposer: &TopicComposer{
				ComposeBroadcastTopic: func() string {
					return fmt.Sprintf("sign:broadcast:bls:%s", sessionID)
				},
				ComposeDirectTopic: func(nodeID string) string {
					return fmt.Sprintf("sign:direct:bls:%s:%s", nodeID, sessionID)
				},
			},
			identityStore: identityStore,
		},
		config:      config,
		messageHash: messageHash,
		signerIDs:   signerIDs,
		shares:      make([]*blsThreshold.SignatureShare, 0, len(signerIDs)),
		done:        false,
	}, nil
}

// ListenToIncomingMessageAsync subscribes to BLS signing messages
func (s *blsSigningSession) ListenToIncomingMessageAsync() {
	// Subscribe to broadcast messages (all signers broadcast their partial sig)
	broadcastTopic := s.topicComposer.ComposeBroadcastTopic()
	broadcastSub, err := s.pubSub.Subscribe(broadcastTopic, func(m *nats.Msg) {
		s.logger.Debug().
			Str("topic", broadcastTopic).
			Int("size", len(m.Data)).
			Msg("BLS: Received broadcast message")
		s.ProcessInboundMessage(m.Data)
	})

	if err != nil {
		s.logger.Error().Err(err).Msgf("BLS: Failed to subscribe to broadcast topic %s", broadcastTopic)
		s.errCh <- err
		return
	}

	s.subscriberList = append(s.subscriberList, broadcastSub)

	s.logger.Info().
		Str("broadcast", broadcastTopic).
		Msg("BLS: Listening to incoming signing messages")
}

func (s *blsSigningSession) Init() {
	s.logger.Info().
		Str("sessionID", s.sessionID).
		Str("walletID", s.walletID).
		Hex("messageHash", s.messageHash).
		Interface("signerIDs", s.signerIDs).
		Msg("Initializing BLS signing session")
}

func (s *blsSigningSession) ProcessInboundMessage(msgBytes []byte) {
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

	// Parse the signature share message
	var shareMsg blsSignShareMessage
	if err := json.Unmarshal(inboundMessage.Body, &shareMsg); err != nil {
		s.logger.Error().Err(err).Msg("BLS: Failed to unmarshal signature share")
		return
	}

	// Reconstruct the BLS signature
	sig, err := bls.SignatureFromBytes(shareMsg.Signature)
	if err != nil {
		s.logger.Error().Err(err).Str("partyID", string(shareMsg.PartyID)).Msg("BLS: Invalid signature share")
		return
	}

	// Verify the partial signature before accepting
	share := &blsThreshold.SignatureShare{
		PartyID:   shareMsg.PartyID,
		Signature: sig,
	}

	if !s.config.VerifyPartialSignature(share, s.messageHash) {
		s.logger.Warn().
			Str("partyID", string(shareMsg.PartyID)).
			Msg("BLS: Partial signature verification failed, rejecting")
		return
	}

	s.sharesLock.Lock()
	s.shares = append(s.shares, share)
	shareCount := len(s.shares)
	s.sharesLock.Unlock()

	s.logger.Info().
		Str("partyID", string(shareMsg.PartyID)).
		Int("shareCount", shareCount).
		Int("threshold", s.config.Threshold).
		Msg("BLS: Accepted verified signature share")

	// Check if we have enough shares to aggregate
	if shareCount >= s.config.Threshold {
		s.resultMutex.Lock()
		if !s.done {
			s.done = true
			s.resultMutex.Unlock()
			s.finishCh <- true
		} else {
			s.resultMutex.Unlock()
		}
	}
}

func (s *blsSigningSession) ProcessOutboundMessage() {
	s.logger.Info().Msgf("BLS ProcessOutboundMessage started: %s", s.sessionID)

	// Sign locally with our share and broadcast
	share, err := s.config.Sign(s.messageHash)
	if err != nil {
		s.logger.Error().Err(err).Msg("BLS: Failed to create partial signature")
		s.resultMutex.Lock()
		s.resultErr = err
		s.resultMutex.Unlock()
		s.publishResult()
		return
	}

	// Add our own share
	s.sharesLock.Lock()
	s.shares = append(s.shares, share)
	shareCount := len(s.shares)
	s.sharesLock.Unlock()

	// Broadcast our signature share
	shareMsg := blsSignShareMessage{
		PartyID:   s.selfPartyID,
		Signature: bls.SignatureToBytes(share.Signature),
	}
	body, err := json.Marshal(shareMsg)
	if err != nil {
		s.logger.Error().Err(err).Msg("BLS: Failed to marshal signature share")
		s.resultMutex.Lock()
		s.resultErr = err
		s.resultMutex.Unlock()
		s.publishResult()
		return
	}

	wireMsg := &types.Message{
		SessionID:   s.sessionID,
		SenderID:    string(s.selfPartyID),
		Body:        body,
		IsBroadcast: true,
	}
	s.sendMsg(wireMsg)

	s.logger.Info().
		Str("partyID", string(s.selfPartyID)).
		Int("shareCount", shareCount).
		Msg("BLS: Broadcast our signature share")

	// Check if our share alone meets threshold (unlikely but possible for t=1)
	if shareCount >= s.config.Threshold {
		s.resultMutex.Lock()
		if !s.done {
			s.done = true
			s.resultMutex.Unlock()
			s.finishCh <- true
		} else {
			s.resultMutex.Unlock()
		}
	}

	// Wait for enough shares to aggregate
	select {
	case <-s.finishCh:
		s.logger.Info().Msg("BLS: Received finish - aggregating signatures")
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

func (s *blsSigningSession) publishResult() {
	s.resultMutex.Lock()
	defer s.resultMutex.Unlock()

	if s.resultErr != nil {
		failureEvent := event.CreateSignFailure(
			s.sessionID,
			s.walletID,
			map[string]any{
				"error":    s.resultErr.Error(),
				"protocol": "BLS",
			},
		)
		evtData, _ := encoding.StructToJsonBytes(failureEvent)
		if err := s.resultQueue.Enqueue(fmt.Sprintf("%s.%s", event.SigningResultTopicBase, s.walletID), evtData, nil); err != nil {
			s.logger.Error().Err(err).Msg("BLS: failed to publish sign failure event")
		}
		s.externalFinishChan <- ""
		return
	}

	// Aggregate collected shares
	s.sharesLock.Lock()
	shares := make([]*blsThreshold.SignatureShare, len(s.shares))
	copy(shares, s.shares)
	s.sharesLock.Unlock()

	aggSig, err := blsThreshold.AggregateSignatures(shares, s.config.Threshold)
	if err != nil {
		s.logger.Error().Err(err).Msg("BLS: Failed to aggregate signatures")
		s.externalFinishChan <- ""
		return
	}

	// Verify the aggregated signature
	if !s.config.VerifyAggregateSignature(s.messageHash, aggSig) {
		s.logger.Error().Msg("BLS: Aggregated signature verification failed")
		s.externalFinishChan <- ""
		return
	}

	sigBytes := bls.SignatureToBytes(aggSig)

	s.logger.Info().
		Str("sessionID", s.sessionID).
		Str("walletID", s.walletID).
		Int("sigLen", len(sigBytes)).
		Msg("BLS signing completed successfully")

	// Create success event - use the Signature field (same as EdDSA pattern)
	successEvent := event.SigningResultEvent{
		ResultType: event.ResultTypeSuccess,
		WalletID:   s.walletID,
		TxID:       s.sessionID,
		Signature:  sigBytes,
	}

	evtData, _ := encoding.StructToJsonBytes(successEvent)
	if err := s.resultQueue.Enqueue(fmt.Sprintf("%s.%s", event.SigningResultTopicBase, s.walletID), evtData, nil); err != nil {
		s.logger.Error().Err(err).Msg("BLS: failed to publish sign success event")
	}

	// Send to externalFinishChan so WaitForFinish() unblocks
	s.externalFinishChan <- hex.EncodeToString(sigBytes)
}

func (s *blsSigningSession) Stop() {
	close(s.outCh)
	close(s.errCh)
}

func (s *blsSigningSession) WaitForFinish() string {
	return <-s.externalFinishChan
}
