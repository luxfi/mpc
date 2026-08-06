package mpc

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"

	log "github.com/luxfi/log"
	"github.com/nats-io/nats.go"

	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/frost"
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

// ed25519SignStart names the signing primitive for the Ed25519 route, once, so
// the daemon and the tests cannot drift onto different ones.
//
// It must be SignEd25519 and never the generic Sign. Over this same config, Sign
// emits 64 bytes in exactly the same shape, but its challenge is BLAKE3 and its S
// is big-endian, so it looks like an Ed25519 signature and no verifier on earth
// accepts it.
//
// message is the message, not a digest: PureEdDSA hashes it inside the challenge.
func ed25519SignStart(config *frost.Config, signers []party.ID, message []byte) protocol.StartFunc {
	return frost.SignEd25519(config, signers, message)
}

// FROSTSignSession is the interface for Ed25519 signing sessions.
type FROSTSignSession interface {
	Session
}

type frostSigningSession struct {
	session
	handler *protocol.Handler
	pool    *pool.Pool
	config  *frost.Config
	// signature is the RFC 8032 encoding, R ‖ S with S little-endian, exactly
	// what crypto/ed25519.Verify accepts.
	signature []byte
	// message is the message itself, NOT a digest of it. PureEdDSA hashes the
	// message inside the challenge, so anything hashed here would be signed as
	// a digest of a digest and rejected on chain. Solana signs the serialized
	// transaction message; TON signs the 32 bytes of the cell hash — in both
	// cases these are the bytes the caller handed us, unchanged.
	message        []byte
	messagesCh     chan *protocol.Message
	resultMutex    sync.Mutex
	done           bool
	resultErr      error
	signerIDs      []party.ID
	useBroadcast   bool
	protocolLogger log.Logger
}

func newFROSTSigningSession(
	sessionID string,
	walletID string,
	message []byte,
	pubSub messaging.PubSub,
	selfPartyID party.ID,
	signerIDs []party.ID,
	kvstore kvstore.KVStore,
	keyinfoStore keyinfo.Store,
	resultQueue messaging.MessageQueue,
	identityStore identity.Store,
	useBroadcast bool,
	orgID string,
) (*frostSigningSession, error) {
	// Load and unmarshal key share inside withSecretErasure so that raw
	// share bytes on the stack are zeroed after parsing completes.
	shareKey := Ed25519ShareKey(walletID)
	var config *frost.Config
	var loadErr error
	withSecretErasure(func() {
		shareBytes, err := GetKeyShareWithFallback(kvstore, orgID, shareKey)
		if err != nil {
			loadErr = fmt.Errorf("failed to get Ed25519 key share: %w", err)
			return
		}
		defer func() {
			for i := range shareBytes {
				shareBytes[i] = 0
			}
		}()
		// CBOR, and every point is decoded through curve.Ed25519, so a share
		// belonging to another curve cannot load at all.
		config, err = UnmarshalEd25519Config(shareBytes)
		if err != nil {
			loadErr = fmt.Errorf("failed to unmarshal Ed25519 key share: %w", err)
		}
	})
	if loadErr != nil {
		return nil, loadErr
	}

	// Create thread pool
	threadPool := pool.NewPool(0) // Use max threads

	return &frostSigningSession{
		session: session{
			walletID:           walletID,
			sessionID:          sessionID,
			pubSub:             pubSub,
			selfPartyID:        selfPartyID,
			partyIDs:           signerIDs,
			subscriberList:     []messaging.Subscription{},
			rounds:             3, // FROST signing has 3 rounds
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
					return fmt.Sprintf("sign:broadcast:ed25519:%s", sessionID)
				},
				ComposeDirectTopic: func(nodeID string) string {
					return fmt.Sprintf("sign:direct:ed25519:%s:%s", nodeID, sessionID)
				},
			},
			identityStore: identityStore,
		},
		pool:       threadPool,
		config:     config,
		messagesCh: make(chan *protocol.Message, 100),
		// Passed through untouched — see the field comment on message.
		message:      message,
		signerIDs:    signerIDs,
		useBroadcast: useBroadcast,
		done:         false,
	}, nil
}

// ListenToIncomingMessageAsync subscribes to FROST signing messages
func (s *frostSigningSession) ListenToIncomingMessageAsync() {
	// Subscribe to broadcast messages
	broadcastTopic := s.topicComposer.ComposeBroadcastTopic()
	broadcastSub, err := s.pubSub.Subscribe(broadcastTopic, func(m *nats.Msg) {
		s.logger.Debug().
			Str("topic", broadcastTopic).
			Int("size", len(m.Data)).
			Msg("FROST: Received broadcast message")
		s.ProcessInboundMessage(m.Data)
	})

	if err != nil {
		s.logger.Error().Err(err).Msgf("FROST: Failed to subscribe to broadcast topic %s", broadcastTopic)
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
			Msg("FROST: Received direct message")
		s.ProcessInboundMessage(m.Data)
	})

	if err != nil {
		s.logger.Error().Err(err).Msgf("FROST: Failed to subscribe to direct topic %s", directTopic)
		s.errCh <- err
		return
	}

	s.subscriberList = append(s.subscriberList, directSub)

	s.logger.Info().
		Str("broadcast", broadcastTopic).
		Str("direct", directTopic).
		Msg("FROST: Listening to incoming signing messages")
}

func (s *frostSigningSession) Init() {
	s.logger.Info().
		Str("sessionID", s.sessionID).
		Str("walletID", s.walletID).
		Int("messageLen", len(s.message)).
		Interface("signerIDs", s.signerIDs).
		Bool("useBroadcast", s.useBroadcast).
		Msg("Initializing FROST signing session")

	// Create protocol logger
	s.protocolLogger = log.NewTestLogger(log.InfoLevel)

	startFunc := ed25519SignStart(s.config, s.signerIDs, s.message)

	// Create handler with timeout context for signing operations
	ctx, cancel := context.WithTimeout(context.Background(), SigningTimeout)
	handler, err := protocol.NewHandler(
		ctx,
		s.protocolLogger,
		nil, // No prometheus registry
		startFunc,
		[]byte(s.sessionID),
		protocol.DefaultConfig(),
	)
	if err != nil {
		cancel()
		s.logger.Fatal().Err(err).Msg("Failed to create FROST signing handler")
		return
	}

	// Timeout watchdog
	go func() {
		<-ctx.Done()
		cancel()
		if ctx.Err() == context.DeadlineExceeded {
			s.logger.Error().
				Str("sessionID", s.sessionID).
				Dur("timeout", SigningTimeout).
				Msg("FROST signing session timed out")
			select {
			case s.externalFinishChan <- "":
			default:
			}
		}
	}()

	s.handler = handler

	// Start message handling goroutine
	go s.handleProtocolMessages()

	s.logger.Info().
		Str("sessionID", s.sessionID).
		Str("partyID", string(s.selfPartyID)).
		Interface("signerIDs", s.signerIDs).
		Msg("[INITIALIZED] FROST signing session initialized successfully")
}

func (s *frostSigningSession) handleProtocolMessages() {
	for {
		select {
		case protoMsg, ok := <-s.handler.Listen():
			if !ok {
				// Protocol finished
				s.resultMutex.Lock()
				s.done = true
				result, err := s.handler.Result()
				if err != nil {
					s.resultErr = err
					s.errCh <- err
				} else {
					// SignEd25519 resolves to a VALUE, not a pointer — asserting
					// *frost.Ed25519Signature here would panic.
					sig, ok := result.(frost.Ed25519Signature)
					if !ok {
						err := fmt.Errorf("Ed25519 signing returned %T, want frost.Ed25519Signature", result)
						s.resultErr = err
						s.errCh <- err
					} else if encoded, mErr := sig.MarshalBinary(); mErr != nil {
						s.resultErr = fmt.Errorf("failed to encode Ed25519 signature: %w", mErr)
						s.errCh <- s.resultErr
					} else {
						s.signature = encoded
					}
				}
				s.resultMutex.Unlock()
				s.finishCh <- true
				return
			}

			// Serialize the full protocol message
			protoBytes, err := protoMsg.MarshalBinary()
			if err != nil {
				s.logger.Error().Err(err).Msg("FROST: Failed to marshal protocol message")
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
				Int("recipients", len(toPartyIDs)).
				Int("dataLen", len(protoBytes)).
				Msg("FROST: Protocol emitted message")

			outMsg := msg{
				FromPartyID: protoMsg.From,
				ToPartyIDs:  toPartyIDs,
				IsBroadcast: protoMsg.Broadcast,
				Data:        protoBytes,
			}

			s.outCh <- outMsg

		case protoMsg := <-s.messagesCh:
			// Handle incoming message
			s.logger.Debug().
				Str("from", string(protoMsg.From)).
				Bool("broadcast", protoMsg.Broadcast).
				Int("round", int(protoMsg.RoundNumber)).
				Int("dataLen", len(protoMsg.Data)).
				Msg("FROST: Received protocol message, checking CanAccept")

			if !s.handler.CanAccept(protoMsg) {
				s.logger.Warn().
					Str("from", string(protoMsg.From)).
					Bool("broadcast", protoMsg.Broadcast).
					Msg("FROST: Handler cannot accept message")
				continue
			}

			s.logger.Debug().
				Str("from", string(protoMsg.From)).
				Msg("FROST: Handler accepted message")
			s.handler.Accept(protoMsg)
		}
	}
}

func (s *frostSigningSession) ProcessInboundMessage(msgBytes []byte) {
	s.processingLock.Lock()
	defer s.processingLock.Unlock()

	// First, unmarshal the wire format
	inboundMessage := &types.Message{}
	if err := encoding.JsonBytesToStruct(msgBytes, inboundMessage); err != nil {
		s.logger.Error().Err(err).Msg("FROST: ProcessInboundMessage unmarshal error")
		return
	}

	// Verify Ed25519 signature on the wire message
	if err := s.verifyInboundSignature(inboundMessage); err != nil {
		s.logger.Warn().Err(err).Str("sender", inboundMessage.SenderNodeID).Msg("Dropping message with invalid signature")
		return
	}

	// Deduplication check
	msgHashStr := fmt.Sprintf("%x", utils.GetMessageHash(inboundMessage.Body))
	if s.processing.seen(msgHashStr) {
		return
	}

	// Deserialize the full protocol message from the body
	protoMsg := &protocol.Message{}
	if err := protoMsg.UnmarshalBinary(inboundMessage.Body); err != nil {
		s.logger.Error().Err(err).Msg("FROST: Failed to unmarshal protocol message")
		return
	}

	s.logger.Debug().
		Str("from", string(protoMsg.From)).
		Bool("broadcast", protoMsg.Broadcast).
		Int("round", int(protoMsg.RoundNumber)).
		Int("dataLen", len(protoMsg.Data)).
		Msg("FROST: Received protocol message")

	// Send to handler
	s.messagesCh <- protoMsg
}

func (s *frostSigningSession) ProcessOutboundMessage() {
	s.logger.Info().Msgf("FROST ProcessOutboundMessage started: %s", s.sessionID)
	for {
		select {
		case m := <-s.outCh:
			// Convert party IDs back to strings
			recipientIDs := make([]string, len(m.ToPartyIDs))
			for i, pid := range m.ToPartyIDs {
				recipientIDs[i] = string(pid)
			}

			msgWireBytes := &types.Message{
				SessionID:    s.sessionID,
				SenderID:     string(m.FromPartyID),
				RecipientIDs: recipientIDs,
				Body:         m.Data,
				IsBroadcast:  m.IsBroadcast,
			}

			s.sendMsg(msgWireBytes)

		case err := <-s.errCh:
			s.logger.Error().Err(err).Msg("FROST: Received error during ProcessOutboundMessage")

		case <-s.finishCh:
			s.logger.Info().Msg("FROST: Received finish message during ProcessOutboundMessage")
			s.publishResult()
			return
		}
	}
}

func (s *frostSigningSession) publishResult() {
	s.resultMutex.Lock()
	defer s.resultMutex.Unlock()

	if s.resultErr != nil {
		failureEvent := event.CreateSignFailure(
			s.sessionID,
			s.walletID,
			map[string]any{
				"error":    s.resultErr.Error(),
				"protocol": "FROST",
			},
		)
		evtData, _ := encoding.StructToJsonBytes(failureEvent)
		if err := s.resultQueue.Enqueue(fmt.Sprintf("%s.%s", event.SigningResultTopicBase, s.walletID), evtData, nil); err != nil {
			s.logger.Error().Err(err).Msg("FROST: failed to publish sign failure event")
		}
		s.externalFinishChan <- ""
		return
	}

	if len(s.signature) != 64 {
		s.logger.Error().Int("sigLen", len(s.signature)).Msg("FROST: Invalid signature after signing completion (expected 64 bytes)")
		s.externalFinishChan <- ""
		return
	}

	// RFC 8032 encoding: R (32 bytes) ‖ S (32 bytes, little-endian).
	fullSignature := s.signature

	s.logger.Info().
		Str("sessionID", s.sessionID).
		Str("walletID", s.walletID).
		Hex("sigR", fullSignature[:32]).
		Hex("sigS", fullSignature[32:]).
		Int("sigLen", len(fullSignature)).
		Msg("FROST/Ed25519 signing completed successfully")

	// Create success event with EdDSA signature format
	successEvent := event.SigningResultEvent{
		ResultType: event.ResultTypeSuccess,
		WalletID:   s.walletID,
		TxID:       s.sessionID,
		// For EdDSA, use the Signature field with full 64-byte signature
		Signature: fullSignature,
	}

	evtData, _ := encoding.StructToJsonBytes(successEvent)
	if err := s.resultQueue.Enqueue(fmt.Sprintf("%s.%s", event.SigningResultTopicBase, s.walletID), evtData, nil); err != nil {
		s.logger.Error().Err(err).Msg("FROST: failed to publish sign success event")
	}

	// IMPORTANT: Send to externalFinishChan so WaitForFinish() unblocks
	s.externalFinishChan <- hex.EncodeToString(fullSignature)
}

func (s *frostSigningSession) Stop() {
	if s.pool != nil {
		s.pool.TearDown()
	}
	close(s.outCh)
	close(s.errCh)
	close(s.messagesCh)
}

func (s *frostSigningSession) WaitForFinish() string {
	return <-s.externalFinishChan
}
