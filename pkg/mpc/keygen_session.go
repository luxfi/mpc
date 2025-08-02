package mpc

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/luxfi/cggmp21/pkg/math/curve"
	"github.com/luxfi/cggmp21/pkg/party"
	"github.com/luxfi/cggmp21/pkg/pool"
	"github.com/luxfi/cggmp21/pkg/protocol"
	"github.com/luxfi/cggmp21/protocols/cmp"
	"github.com/luxfi/cggmp21/protocols/cmp/config"
	"github.com/luxfi/mpc/pkg/encoding"
	"github.com/luxfi/mpc/pkg/event"
	"github.com/luxfi/mpc/pkg/identity"
	"github.com/luxfi/mpc/pkg/keyinfo"
	"github.com/luxfi/mpc/pkg/kvstore"
	"github.com/luxfi/mpc/pkg/messaging"
	"github.com/luxfi/mpc/pkg/types"
	"github.com/luxfi/mpc/pkg/utils"
	"github.com/rs/zerolog"
)

type KeyGenSession interface {
	Session
}

type cggmp21KeygenSession struct {
	session
	handler     *protocol.MultiHandler
	pool        *pool.Pool
	config      *config.Config
	messagesCh  chan *protocol.Message
	resultMutex sync.Mutex
	done        bool
	resultErr   error
}

func newCGGMP21KeygenSession(
	walletID string,
	pubSub messaging.PubSub,
	selfPartyID party.ID,
	partyIDs []party.ID,
	threshold int,
	kvstore kvstore.KVStore,
	keyinfoStore keyinfo.Store,
	resultQueue messaging.MessageQueue,
	identityStore identity.Store,
) *cggmp21KeygenSession {
	// Create thread pool
	threadPool := pool.NewPool(0) // Use max threads

	return &cggmp21KeygenSession{
		session: session{
			walletID:           walletID,
			pubSub:             pubSub,
			selfPartyID:        selfPartyID,
			partyIDs:           partyIDs,
			subscriberList:     []messaging.Subscriber{},
			rounds:             5, // CGGMP21 keygen has 5 rounds
			outCh:              make(chan msg, 100),
			errCh:              make(chan error, 10),
			finishCh:           make(chan bool, 1),
			externalFinishChan: make(chan string, 1),
			threshold:          threshold,
			kvstore:            kvstore,
			keyinfoStore:       keyinfoStore,
			resultQueue:        resultQueue,
			logger:             zerolog.New(utils.ZerologConsoleWriter()).With().Timestamp().Logger(),
			processing:         make(map[string]bool),
			processingLock:     sync.Mutex{},
			topicComposer: &TopicComposer{
				ComposeBroadcastTopic: func() string {
					return fmt.Sprintf("keygen:broadcast:cggmp21:%s", walletID)
				},
				ComposeDirectTopic: func(nodeID string) string {
					return fmt.Sprintf("keygen:direct:cggmp21:%s:%s", nodeID, walletID)
				},
			},
			identityStore: identityStore,
		},
		pool:       threadPool,
		messagesCh: make(chan *protocol.Message, 100),
		done:       false,
	}
}

func (s *cggmp21KeygenSession) Init() {
	s.logger.Info().
		Int("threshold", s.threshold).
		Interface("partyIDs", s.partyIDs).
		Msg("Initializing CGGMP21 keygen session")

	// Create CGGMP21 keygen protocol
	startFunc := cmp.Keygen(curve.Secp256k1{}, s.selfPartyID, s.partyIDs, s.threshold, s.pool)
	
	// Create handler
	handler, err := protocol.NewMultiHandler(startFunc, nil)
	if err != nil {
		s.logger.Fatal().Err(err).Msg("Failed to create keygen handler")
		return
	}
	
	s.handler = handler
	
	// Start message handling goroutine
	go s.handleProtocolMessages()
	
	s.logger.Info().
		Str("partyID", string(s.selfPartyID)).
		Interface("peerIDs", s.partyIDs).
		Str("walletID", s.walletID).
		Msg("[INITIALIZED] CGGMP21 keygen session initialized successfully")
}

func (s *cggmp21KeygenSession) handleProtocolMessages() {
	for {
		select {
		case msg, ok := <-s.handler.Listen():
			if !ok {
				// Protocol finished
				s.resultMutex.Lock()
				s.done = true
				result, err := s.handler.Result()
				if err != nil {
					s.resultErr = err
					s.errCh <- err
				} else {
					s.config = result.(*config.Config)
				}
				s.resultMutex.Unlock()
				s.finishCh <- true
				return
			}
			
			// Convert protocol message to our message format
			outMsg := msg{
				FromPartyID: msg.From,
				ToPartyIDs:  msg.To,
				IsBroadcast: msg.Broadcast,
				Data:        msg.Data,
			}
			
			s.outCh <- outMsg
			
		case protoMsg := <-s.messagesCh:
			// Handle incoming message
			if !s.handler.CanAccept(protoMsg) {
				s.logger.Warn().Msgf("Handler cannot accept message from %s", protoMsg.From)
				continue
			}
			
			if err := s.handler.Update(protoMsg); err != nil {
				s.logger.Error().Err(err).Msgf("Failed to update handler with message from %s", protoMsg.From)
			}
		}
	}
}

func (s *cggmp21KeygenSession) ProcessInboundMessage(msgBytes []byte) {
	s.processingLock.Lock()
	defer s.processingLock.Unlock()

	inboundMessage := &types.Message{}
	if err := encoding.JsonBytesToStruct(msgBytes, inboundMessage); err != nil {
		s.logger.Error().Err(err).Msg("ProcessInboundMessage unmarshal error")
		return
	}

	msgHash := utils.GetMessageHash(msgBytes)
	if s.processing[msgHash] {
		return
	}
	s.processing[msgHash] = true

	// Convert to protocol message
	protoMsg := &protocol.Message{
		From:      party.ID(inboundMessage.SenderID),
		To:        convertToPartyIDs(inboundMessage.RecipientIDs),
		Data:      inboundMessage.Body,
		Broadcast: inboundMessage.IsBroadcast,
	}
	
	// Send to handler
	s.messagesCh <- protoMsg
}

func (s *cggmp21KeygenSession) ProcessOutboundMessage() {
	s.logger.Info().Msgf("ProcessOutboundMessage started: %s", s.walletID)
	for {
		select {
		case m := <-s.outCh:
			// Convert party IDs back to strings
			recipientIDs := make([]string, len(m.ToPartyIDs))
			for i, pid := range m.ToPartyIDs {
				recipientIDs[i] = string(pid)
			}
			
			msgWireBytes := &types.Message{
				SessionID:    s.walletID,
				SenderID:     string(m.FromPartyID),
				RecipientIDs: recipientIDs,
				Body:         m.Data,
				IsBroadcast:  m.IsBroadcast,
			}
			
			s.sendMsg(msgWireBytes)
			
		case err := <-s.errCh:
			s.logger.Error().Err(err).Msg("Received error during ProcessOutboundMessage")
			
		case <-s.finishCh:
			s.logger.Info().Msg("Received finish message during ProcessOutboundMessage")
			s.publishResult()
			return
		}
	}
}

func (s *cggmp21KeygenSession) publishResult() {
	s.resultMutex.Lock()
	defer s.resultMutex.Unlock()
	
	if s.resultErr != nil {
		failureEvent := event.CreateKeygenFailure(
			s.walletID,
			map[string]any{
				"error": s.resultErr.Error(),
			},
		)
		if err := s.resultQueue.Publish(failureEvent); err != nil {
			s.logger.Error().Err(err).Msg("failed to publish keygen failure event")
		}
		return
	}
	
	if s.config == nil {
		s.logger.Error().Msg("No config available after keygen completion")
		return
	}
	
	// Save key share
	shareBytes, err := json.Marshal(s.config)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to marshal key share")
		return
	}
	
	if err := s.kvstore.Set(s.walletID, shareBytes); err != nil {
		s.logger.Error().Err(err).Msgf("Failed to save key share for wallet %s", s.walletID)
		return
	}
	
	// Convert public key to hex
	pubKeyBytes := s.config.PublicPoint().Bytes()
	pubKeyHex := fmt.Sprintf("%x", pubKeyBytes)
	
	// Save key info
	keyInfo := keyinfo.NewKeyInfo(
		s.walletID,
		types.KeyType("CGGMP21"),
		pubKeyHex,
		s.threshold,
		convertFromPartyIDs(s.partyIDs),
	)
	
	if err := s.keyinfoStore.Save(s.walletID, keyInfo); err != nil {
		s.logger.Error().Err(err).Msgf("Failed to save key info for wallet %s", s.walletID)
		return
	}
	
	// Publish success event
	successEvent := event.CreateKeygenSuccess(
		s.walletID,
		pubKeyHex,
		map[string]any{
			"threshold": s.threshold,
			"parties":   len(s.partyIDs),
			"protocol":  "CGGMP21",
		},
	)
	
	if err := s.resultQueue.Publish(successEvent); err != nil {
		s.logger.Error().Err(err).Msg("failed to publish keygen success event")
	}
	
	s.logger.Info().
		Str("walletID", s.walletID).
		Str("publicKey", pubKeyHex).
		Msg("CGGMP21 keygen completed successfully")
}

func (s *cggmp21KeygenSession) Stop() {
	if s.pool != nil {
		s.pool.TearDown()
	}
	close(s.outCh)
	close(s.errCh)
	close(s.messagesCh)
}

func (s *cggmp21KeygenSession) WaitForFinish() string {
	return <-s.externalFinishChan
}

// Helper functions
func convertToPartyIDs(ids []string) []party.ID {
	result := make([]party.ID, len(ids))
	for i, id := range ids {
		result[i] = party.ID(id)
	}
	return result
}

func convertFromPartyIDs(ids []party.ID) []string {
	result := make([]string, len(ids))
	for i, id := range ids {
		result[i] = string(id)
	}
	return result
}