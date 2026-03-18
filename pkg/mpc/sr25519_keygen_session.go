package mpc

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	log "github.com/luxfi/log"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/frost"
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

// SR25519KeygenSession interface for SR25519 keygen
type SR25519KeygenSession interface {
	Session
	// GetPublicKey returns the SR25519 public key after keygen completes
	GetPublicKey() []byte
}

type sr25519KeygenSession struct {
	session
	handler        *protocol.Handler
	config         *frost.Config
	messagesCh     chan *protocol.Message
	resultMutex    sync.Mutex
	done           bool
	resultErr      error
	protocolLogger log.Logger
}

func newSR25519KeygenSession(
	walletID string,
	pubSub messaging.PubSub,
	selfPartyID party.ID,
	partyIDs []party.ID,
	threshold int,
	kvstore kvstore.KVStore,
	keyinfoStore keyinfo.Store,
	resultQueue messaging.MessageQueue,
	identityStore identity.Store,
) *sr25519KeygenSession {
	return &sr25519KeygenSession{
		session: session{
			walletID:           walletID,
			pubSub:             pubSub,
			selfPartyID:        selfPartyID,
			partyIDs:           partyIDs,
			subscriberList:     []messaging.Subscription{},
			rounds:             3, // FROST keygen has 3 rounds
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
					return fmt.Sprintf("keygen:broadcast:sr25519:%s", walletID)
				},
				ComposeDirectTopic: func(nodeID string) string {
					return fmt.Sprintf("keygen:direct:sr25519:%s:%s", nodeID, walletID)
				},
			},
			identityStore: identityStore,
		},
		messagesCh: make(chan *protocol.Message, 100),
		done:       false,
	}
}

// ListenToIncomingMessageAsync subscribes to SR25519 keygen messages
func (s *sr25519KeygenSession) ListenToIncomingMessageAsync() {
	// Subscribe to broadcast messages
	broadcastTopic := s.topicComposer.ComposeBroadcastTopic()
	broadcastSub, err := s.pubSub.Subscribe(broadcastTopic, func(m *nats.Msg) {
		s.logger.Debug().
			Str("topic", broadcastTopic).
			Int("size", len(m.Data)).
			Msg("SR25519: Received broadcast message")
		s.ProcessInboundMessage(m.Data)
	})

	if err != nil {
		s.logger.Error().Err(err).Msgf("SR25519: Failed to subscribe to broadcast topic %s", broadcastTopic)
		s.errCh <- err
		return
	}

	s.subscriberList = append(s.subscriberList, broadcastSub)

	// Subscribe to direct messages
	directTopic := s.topicComposer.ComposeDirectTopic(extractNodeID(string(s.selfPartyID)))
	directSub, err := s.pubSub.Subscribe(directTopic, func(m *nats.Msg) {
		s.logger.Debug().
			Str("topic", directTopic).
			Int("size", len(m.Data)).
			Msg("SR25519: Received direct message")
		s.ProcessInboundMessage(m.Data)
	})

	if err != nil {
		s.logger.Error().Err(err).Msgf("SR25519: Failed to subscribe to direct topic %s", directTopic)
		s.errCh <- err
		return
	}

	s.subscriberList = append(s.subscriberList, directSub)

	s.logger.Info().
		Str("broadcast", broadcastTopic).
		Str("direct", directTopic).
		Msg("SR25519: Listening to incoming messages")
}

func (s *sr25519KeygenSession) Init() {
	s.logger.Info().
		Str("walletID", s.walletID).
		Int("threshold", s.threshold).
		Int("partyCount", len(s.partyIDs)).
		Str("selfPartyID", string(s.selfPartyID)).
		Msg("[SR25519] Initializing SR25519 keygen session")

	// Create protocol logger
	s.protocolLogger = log.NewTestLogger(log.InfoLevel)

	// Create FROST keygen protocol for Ristretto255 (sr25519)
	// Uses local Ristretto255 type implementing curve.Curve interface
	startFunc := frost.Keygen(Ristretto255{}, s.selfPartyID, s.partyIDs, s.threshold)

	// Create handler with proper context, logging, and session ID
	ctx := context.Background()
	handler, err := protocol.NewHandler(
		ctx,
		s.protocolLogger,
		nil, // No prometheus registry
		startFunc,
		[]byte(s.walletID),
		protocol.DefaultConfig(),
	)
	if err != nil {
		s.logger.Error().Err(err).Msg("[SR25519] ERROR: Failed to create handler")
		s.errCh <- err
		return
	}

	s.handler = handler

	// Start message handling goroutine
	go s.handleProtocolMessages()

	s.logger.Info().
		Str("partyID", string(s.selfPartyID)).
		Interface("peerIDs", s.partyIDs).
		Str("walletID", s.walletID).
		Msg("[INITIALIZED] SR25519 keygen session initialized successfully")
}

func (s *sr25519KeygenSession) handleProtocolMessages() {
	for {
		select {
		case protoMsg, ok := <-s.handler.Listen():
			if !ok {
				// Protocol finished
				s.logger.Info().Msg("[SR25519-PROTOCOL] handler.Listen() returned !ok - protocol finished")
				s.resultMutex.Lock()
				s.done = true
				result, err := s.handler.Result()
				if err != nil {
					s.logger.Error().Err(err).Msg("[SR25519-PROTOCOL] handler.Result() returned error")
					s.resultErr = err
					s.errCh <- err
				} else {
					s.config = result.(*frost.Config)
					if s.config != nil && s.config.PublicKey != nil {
						pubBytes, _ := s.config.PublicKey.MarshalBinary()
						s.logger.Info().
							Int("publicKeyLen", len(pubBytes)).
							Str("publicKeyHex", fmt.Sprintf("%x", pubBytes)).
							Msg("[SR25519-PROTOCOL] handler.Result() returned valid config")
					} else {
						s.logger.Warn().Msg("[SR25519-PROTOCOL] handler.Result() returned nil config!")
					}
				}
				s.resultMutex.Unlock()
				s.finishCh <- true
				return
			}

			// Serialize the full protocol message
			protoBytes, err := protoMsg.MarshalBinary()
			if err != nil {
				s.logger.Error().Err(err).Msg("SR25519: Failed to marshal protocol message")
				continue
			}

			// Determine recipients for routing
			var toPartyIDs []party.ID
			if !protoMsg.Broadcast && protoMsg.To != "" {
				toPartyIDs = []party.ID{protoMsg.To}
			}

			s.logger.Debug().
				Str("from", string(protoMsg.From)).
				Str("to", string(protoMsg.To)).
				Bool("broadcast", protoMsg.Broadcast).
				Int("round", int(protoMsg.RoundNumber)).
				Int("dataLen", len(protoBytes)).
				Msg("SR25519: Protocol emitted message")

			outMsg := msg{
				FromPartyID: protoMsg.From,
				ToPartyIDs:  toPartyIDs,
				IsBroadcast: protoMsg.Broadcast,
				Data:        protoBytes,
			}

			s.outCh <- outMsg

		case protoMsg := <-s.messagesCh:
			// Handle incoming message
			s.logger.Info().
				Str("from", string(protoMsg.From)).
				Str("to", string(protoMsg.To)).
				Bool("broadcast", protoMsg.Broadcast).
				Int("round", int(protoMsg.RoundNumber)).
				Hex("ssid", protoMsg.SSID).
				Int("dataLen", len(protoMsg.Data)).
				Msg("SR25519: Received protocol message, checking CanAccept")

			if !s.handler.CanAccept(protoMsg) {
				s.logger.Warn().
					Str("from", string(protoMsg.From)).
					Str("to", string(protoMsg.To)).
					Bool("broadcast", protoMsg.Broadcast).
					Int("round", int(protoMsg.RoundNumber)).
					Hex("ssid", protoMsg.SSID).
					Str("selfPartyID", string(s.selfPartyID)).
					Msg("SR25519: Handler cannot accept message")
				continue
			}

			s.logger.Debug().
				Str("from", string(protoMsg.From)).
				Msg("SR25519: Handler accepted message")
			s.handler.Accept(protoMsg)
		}
	}
}

func (s *sr25519KeygenSession) ProcessInboundMessage(msgBytes []byte) {
	s.processingLock.Lock()
	defer s.processingLock.Unlock()

	// First, unmarshal the wire format to get routing info
	inboundMessage := &types.Message{}
	if err := json.Unmarshal(msgBytes, inboundMessage); err != nil {
		s.logger.Error().Err(err).Msg("SR25519: ProcessInboundMessage unmarshal error")
		return
	}

	// Deduplication check using message body hash
	msgHashStr := fmt.Sprintf("%x", utils.GetMessageHash(inboundMessage.Body))
	if s.processing[msgHashStr] {
		return
	}
	s.processing[msgHashStr] = true

	// Deserialize the full protocol message from the body
	protoMsg := &protocol.Message{}
	if err := protoMsg.UnmarshalBinary(inboundMessage.Body); err != nil {
		s.logger.Error().Err(err).Msg("SR25519: Failed to unmarshal protocol message")
		return
	}

	s.logger.Debug().
		Str("from", string(protoMsg.From)).
		Bool("broadcast", protoMsg.Broadcast).
		Int("round", int(protoMsg.RoundNumber)).
		Int("dataLen", len(protoMsg.Data)).
		Msg("SR25519: Received protocol message")

	// Send to handler
	s.messagesCh <- protoMsg
}

func (s *sr25519KeygenSession) ProcessOutboundMessage() {
	s.logger.Info().Msgf("SR25519: ProcessOutboundMessage started: %s", s.walletID)
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
			s.logger.Error().Err(err).Msg("SR25519: Received error during ProcessOutboundMessage")

		case <-s.finishCh:
			s.logger.Info().Msg("SR25519: Received finish message during ProcessOutboundMessage")
			s.publishResult()
			return
		}
	}
}

func (s *sr25519KeygenSession) publishResult() {
	s.resultMutex.Lock()
	defer s.resultMutex.Unlock()

	if s.resultErr != nil {
		s.logger.Error().Err(s.resultErr).Msg("SR25519: keygen failed with error")
		failureEvent := event.CreateKeygenFailure(
			s.walletID,
			map[string]any{
				"error":    s.resultErr.Error(),
				"protocol": "SR25519",
			},
		)
		evtData, _ := json.Marshal(failureEvent)
		if err := s.resultQueue.Enqueue(fmt.Sprintf("mpc.mpc_keygen_result.%s", s.walletID), evtData, nil); err != nil {
			s.logger.Error().Err(err).Msg("SR25519: failed to publish keygen failure event")
		}
		// Always send to externalFinishChan so WaitForFinish() doesn't block forever
		s.externalFinishChan <- ""
		return
	}

	if s.config == nil {
		s.logger.Error().Msg("SR25519: No config available after keygen completion")
		s.externalFinishChan <- ""
		return
	}

	// Save key share with sr25519 prefix using CBOR (JSON doesn't preserve crypto types)
	shareBytes, err := MarshalSR25519Config(s.config)
	if err != nil {
		s.logger.Error().Err(err).Msg("SR25519: Failed to marshal key share")
		s.externalFinishChan <- ""
		return
	}

	// Save with sr25519: prefix to distinguish from ECDSA and FROST keys
	sr25519Key := fmt.Sprintf("sr25519:%s", s.walletID)
	if err := s.kvstore.Put(sr25519Key, shareBytes); err != nil {
		s.logger.Error().Err(err).Msgf("SR25519: Failed to save key share for wallet %s", s.walletID)
		s.externalFinishChan <- ""
		return
	}

	// Get public key hex
	var pubKeyHex string
	if s.config != nil && s.config.PublicKey != nil {
		pubBytes, err := s.config.PublicKey.MarshalBinary()
		if err == nil && len(pubBytes) > 0 {
			pubKeyHex = fmt.Sprintf("%x", pubBytes)
			s.logger.Info().
				Int("configPubKeyLen", len(pubBytes)).
				Str("pubKeyHex", pubKeyHex).
				Msg("[SR25519-PUBLISH] PublicKey available")
		} else {
			s.logger.Warn().Msg("[SR25519-PUBLISH] PublicKey marshal failed or empty")
		}
	} else {
		s.logger.Warn().
			Bool("configNil", s.config == nil).
			Msg("[SR25519-PUBLISH] PublicKey is empty or config is nil!")
	}

	// Notify via external finish channel
	s.logger.Info().Str("sendingPubKeyHex", pubKeyHex).Msg("[SR25519-PUBLISH] Sending to externalFinishChan")
	s.externalFinishChan <- pubKeyHex

	s.logger.Info().
		Str("walletID", s.walletID).
		Str("publicKey", pubKeyHex).
		Msg("SR25519 keygen completed successfully")
}

func (s *sr25519KeygenSession) Stop() {
	close(s.outCh)
	close(s.errCh)
	close(s.messagesCh)
}

func (s *sr25519KeygenSession) WaitForFinish() string {
	return <-s.externalFinishChan
}

// GetPublicKey returns the SR25519 public key after keygen completes
func (s *sr25519KeygenSession) GetPublicKey() []byte {
	s.resultMutex.Lock()
	defer s.resultMutex.Unlock()
	if s.config != nil && s.config.PublicKey != nil {
		pubBytes, err := s.config.PublicKey.MarshalBinary()
		if err == nil {
			return pubBytes
		}
	}
	return nil
}
