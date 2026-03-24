package mpc

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"

	log "github.com/luxfi/log"
	"github.com/nats-io/nats.go"

	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/frost"
	"github.com/luxfi/threshold/protocols/frost/sign"
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

// DefaultSigningContext is the default Schnorrkel signing context for Substrate.
const DefaultSigningContext = "substrate"

// SR25519SignSession is the interface for SR25519 signing sessions
type SR25519SignSession interface {
	Session
}

type sr25519SigningSession struct {
	session
	handler        *protocol.Handler
	config         *frost.Config
	signature      *sign.Signature // FROST Schnorr signature (R || z)
	messagesCh     chan *protocol.Message
	resultMutex    sync.Mutex
	done           bool
	resultErr      error
	messageHash    []byte
	signingContext string
	signerIDs      []party.ID
	useBroadcast   bool
	protocolLogger log.Logger
}

// prepareSigningMessage prepends the signing context to the message hash,
// following the Schnorrkel convention used by Substrate/Polkadot.
// The signed payload is: signingContext || messageHash.
func prepareSigningMessage(signingContext string, messageHash []byte) []byte {
	ctx := []byte(signingContext)
	result := make([]byte, len(ctx)+len(messageHash))
	copy(result, ctx)
	copy(result[len(ctx):], messageHash)
	return result
}

func newSR25519SigningSession(
	sessionID string,
	walletID string,
	messageHash []byte,
	signingContext string,
	pubSub messaging.PubSub,
	selfPartyID party.ID,
	signerIDs []party.ID,
	kvstore kvstore.KVStore,
	keyinfoStore keyinfo.Store,
	resultQueue messaging.MessageQueue,
	identityStore identity.Store,
	useBroadcast bool,
	orgID string,
) (*sr25519SigningSession, error) {
	// Load and unmarshal key share inside withSecretErasure so that raw
	// share bytes on the stack are zeroed after parsing completes.
	sr25519Key := fmt.Sprintf("sr25519:%s", walletID)
	var config *frost.Config
	var loadErr error
	withSecretErasure(func() {
		shareBytes, err := GetKeyShareWithFallback(kvstore, orgID, sr25519Key)
		if err != nil {
			loadErr = fmt.Errorf("failed to get SR25519 key share: %w", err)
			return
		}
		defer func() {
			for i := range shareBytes {
				shareBytes[i] = 0
			}
		}()
		// Config is stored as CBOR (to properly preserve crypto types)
		config, err = UnmarshalSR25519Config(shareBytes)
		if err != nil {
			loadErr = fmt.Errorf("failed to unmarshal SR25519 key share: %w", err)
		}
	})
	if loadErr != nil {
		return nil, loadErr
	}

	// Default signing context
	if signingContext == "" {
		signingContext = DefaultSigningContext
	}

	// Prepare the message with signing context prefix
	signedMessage := prepareSigningMessage(signingContext, messageHash)

	return &sr25519SigningSession{
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
					return fmt.Sprintf("sign:broadcast:sr25519:%s", sessionID)
				},
				ComposeDirectTopic: func(nodeID string) string {
					return fmt.Sprintf("sign:direct:sr25519:%s:%s", nodeID, sessionID)
				},
			},
			identityStore: identityStore,
		},
		config:         config,
		messagesCh:     make(chan *protocol.Message, 100),
		messageHash:    signedMessage,
		signingContext: signingContext,
		signerIDs:      signerIDs,
		useBroadcast:   useBroadcast,
		done:           false,
	}, nil
}

// ListenToIncomingMessageAsync subscribes to SR25519 signing messages
func (s *sr25519SigningSession) ListenToIncomingMessageAsync() {
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
		Msg("SR25519: Listening to incoming signing messages")
}

func (s *sr25519SigningSession) Init() {
	s.logger.Info().
		Str("sessionID", s.sessionID).
		Str("walletID", s.walletID).
		Hex("messageHash", s.messageHash).
		Str("signingContext", s.signingContext).
		Interface("signerIDs", s.signerIDs).
		Bool("useBroadcast", s.useBroadcast).
		Msg("Initializing SR25519 signing session")

	// Create protocol logger
	s.protocolLogger = log.NewTestLogger(log.InfoLevel)

	// Create FROST signing protocol for Ristretto255 (non-taproot)
	startFunc := frost.Sign(s.config, s.signerIDs, s.messageHash)

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
		s.logger.Fatal().Err(err).Msg("Failed to create SR25519 signing handler")
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
				Msg("SR25519 signing session timed out")
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
		Msg("[INITIALIZED] SR25519 signing session initialized successfully")
}

func (s *sr25519SigningSession) handleProtocolMessages() {
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
					// FROST Sign returns *sign.Signature (R point + z scalar)
					s.signature = result.(*sign.Signature)
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
				Int("recipients", len(toPartyIDs)).
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
			s.logger.Debug().
				Str("from", string(protoMsg.From)).
				Bool("broadcast", protoMsg.Broadcast).
				Int("round", int(protoMsg.RoundNumber)).
				Int("dataLen", len(protoMsg.Data)).
				Msg("SR25519: Received protocol message, checking CanAccept")

			if !s.handler.CanAccept(protoMsg) {
				s.logger.Warn().
					Str("from", string(protoMsg.From)).
					Bool("broadcast", protoMsg.Broadcast).
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

func (s *sr25519SigningSession) ProcessInboundMessage(msgBytes []byte) {
	s.processingLock.Lock()
	defer s.processingLock.Unlock()

	// First, unmarshal the wire format
	inboundMessage := &types.Message{}
	if err := encoding.JsonBytesToStruct(msgBytes, inboundMessage); err != nil {
		s.logger.Error().Err(err).Msg("SR25519: ProcessInboundMessage unmarshal error")
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

func (s *sr25519SigningSession) ProcessOutboundMessage() {
	s.logger.Info().Msgf("SR25519 ProcessOutboundMessage started: %s", s.sessionID)
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
			s.logger.Error().Err(err).Msg("SR25519: Received error during ProcessOutboundMessage")

		case <-s.finishCh:
			s.logger.Info().Msg("SR25519: Received finish message during ProcessOutboundMessage")
			s.publishResult()
			return
		}
	}
}

func (s *sr25519SigningSession) publishResult() {
	s.resultMutex.Lock()
	defer s.resultMutex.Unlock()

	if s.resultErr != nil {
		failureEvent := event.CreateSignFailure(
			s.sessionID,
			s.walletID,
			map[string]any{
				"error":    s.resultErr.Error(),
				"protocol": "SR25519",
			},
		)
		evtData, _ := encoding.StructToJsonBytes(failureEvent)
		if err := s.resultQueue.Enqueue(fmt.Sprintf("%s.%s", event.SigningResultTopicBase, s.walletID), evtData, nil); err != nil {
			s.logger.Error().Err(err).Msg("SR25519: failed to publish sign failure event")
		}
		s.externalFinishChan <- ""
		return
	}

	if s.signature == nil {
		s.logger.Error().Msg("SR25519: nil signature after signing completion")
		s.externalFinishChan <- ""
		return
	}

	// Marshal signature to bytes: R (32 bytes) || z (32 bytes) = 64 bytes
	// For Ristretto255: R is 32 bytes (ristretto point), z is 32 bytes (ristretto scalar)
	fullSignature, err := s.signature.MarshalBinary()
	if err != nil {
		s.logger.Error().Err(err).Msg("SR25519: failed to marshal signature")
		s.externalFinishChan <- ""
		return
	}

	s.logger.Info().
		Str("sessionID", s.sessionID).
		Str("walletID", s.walletID).
		Int("sigLen", len(fullSignature)).
		Str("signingContext", s.signingContext).
		Msg("SR25519 signing completed successfully")

	// Create success event with SR25519 signature
	// Use the Signature field (same as EdDSA) since both are Schnorr-based
	successEvent := event.SigningResultEvent{
		ResultType: event.ResultTypeSuccess,
		WalletID:   s.walletID,
		TxID:       s.sessionID,
		Signature:  fullSignature,
	}

	evtData, _ := encoding.StructToJsonBytes(successEvent)
	if err := s.resultQueue.Enqueue(fmt.Sprintf("%s.%s", event.SigningResultTopicBase, s.walletID), evtData, nil); err != nil {
		s.logger.Error().Err(err).Msg("SR25519: failed to publish sign success event")
	}

	// Send to externalFinishChan so WaitForFinish() unblocks
	s.externalFinishChan <- hex.EncodeToString(fullSignature)
}

func (s *sr25519SigningSession) Stop() {
	close(s.outCh)
	close(s.errCh)
	close(s.messagesCh)
}

func (s *sr25519SigningSession) WaitForFinish() string {
	return <-s.externalFinishChan
}

// VerifySR25519Signature verifies a FROST/Ristretto255 signature against the public key.
// This is used for local verification of threshold signatures.
func VerifySR25519Signature(publicKey *Ristretto255Point, signingContext string, message []byte, sig *sign.Signature) bool {
	signedMessage := prepareSigningMessage(signingContext, message)
	return sig.Verify(publicKey, signedMessage)
}
