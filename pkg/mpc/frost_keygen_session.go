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

	"github.com/luxfi/mpc/pkg/identity"
	"github.com/luxfi/mpc/pkg/keyinfo"
	"github.com/luxfi/mpc/pkg/kvstore"
	"github.com/luxfi/mpc/pkg/messaging"
	"github.com/luxfi/mpc/pkg/types"
	"github.com/luxfi/mpc/pkg/utils"
)

// FROSTKeygenSession runs FROST distributed key generation over edwards25519.
//
// The group is not incidental. The key this ceremony produces is a plain RFC
// 8032 Ed25519 public key: base58-encoded it is a Solana address, and it is the
// key a TON wallet contract stores. It must therefore come from
// frost.KeygenEd25519 and from nothing else. FROST over secp256k1 (the Taproot
// entry point this session used to call) yields a 32-byte key too, which is why
// the mistake is invisible downstream — the length matches, the address parses,
// and the funds never move.
type FROSTKeygenSession interface {
	Session
	// GetPublicKey returns the 32-byte Ed25519 public key after keygen completes.
	GetPublicKey() []byte
}

// ed25519KeygenStart names the keygen primitive for the Ed25519 route, once.
//
// It exists so that the ceremony the daemon runs and the ceremony the tests run
// cannot drift apart. If the tests called frost.KeygenEd25519 directly they would
// be asserting on a copy of this decision rather than on the decision itself, and
// would keep passing while the session quietly ran something else — which is
// exactly how the Taproot bug survived: the tests and the code agreed about the
// name "EdDSA" and disagreed about the curve.
//
// KeygenTaproot (BIP-340 over secp256k1) must never appear here. Its key is also
// 32 bytes, so it passes every downstream check and mints a Solana address the
// ring can never sign for.
func ed25519KeygenStart(selfID party.ID, participants []party.ID, threshold int) protocol.StartFunc {
	return frost.KeygenEd25519(selfID, participants, threshold)
}

type frostKeygenSession struct {
	session
	handler        *protocol.Handler
	config         *frost.Config
	messagesCh     chan *protocol.Message
	resultMutex    sync.Mutex
	done           bool
	resultErr      error
	protocolLogger log.Logger
}

func newFROSTKeygenSession(
	walletID string,
	pubSub messaging.PubSub,
	selfPartyID party.ID,
	partyIDs []party.ID,
	threshold int,
	kvstore kvstore.KVStore,
	keyinfoStore keyinfo.Store,
	resultQueue messaging.MessageQueue,
	identityStore identity.Store,
	orgID string,
) *frostKeygenSession {
	return &frostKeygenSession{
		session: session{
			walletID:           walletID,
			orgID:              orgID,
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
			processing:         newDedupMap(),
			processingLock:     sync.Mutex{},
			// The topic names the curve, not just the scheme. FROST is defined
			// over any prime-order group, so "frost" alone does not say what a
			// peer is about to agree with us on; a peer running a different
			// group under the same topic would be a silent mixed-curve
			// ceremony. Naming the group keeps that unreachable.
			topicComposer: &TopicComposer{
				ComposeBroadcastTopic: func() string {
					return fmt.Sprintf("keygen:broadcast:ed25519:%s", walletID)
				},
				ComposeDirectTopic: func(nodeID string) string {
					return fmt.Sprintf("keygen:direct:ed25519:%s:%s", nodeID, walletID)
				},
			},
			identityStore: identityStore,
		},
		messagesCh: make(chan *protocol.Message, 100),
		done:       false,
	}
}

// ListenToIncomingMessageAsync subscribes to FROST keygen messages
func (s *frostKeygenSession) ListenToIncomingMessageAsync() {
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
	// Use extractNodeID to match how sendMsg publishes (strips :keygen:1 suffix)
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
		Msg("FROST: Listening to incoming messages")
}

func (s *frostKeygenSession) Init() {
	s.logger.Info().
		Str("walletID", s.walletID).
		Int("threshold", s.threshold).
		Int("partyCount", len(s.partyIDs)).
		Str("selfPartyID", string(s.selfPartyID)).
		Msg("[FROST] Initializing FROST keygen session")

	// Create protocol logger
	s.protocolLogger = log.NewTestLogger(log.InfoLevel)
	s.logger.Info().Msg("[FROST] Protocol logger created")

	s.logger.Info().Msg("[FROST] Creating KeygenEd25519 start function")
	startFunc := ed25519KeygenStart(s.selfPartyID, s.partyIDs, s.threshold)
	s.logger.Info().Msg("[FROST] KeygenEd25519 start function created")

	// Create handler with timeout context for DKG operations
	ctx, cancel := context.WithTimeout(context.Background(), KeygenTimeout)
	s.logger.Info().Msg("[FROST] Creating protocol handler")
	handler, err := protocol.NewHandler(
		ctx,
		s.protocolLogger,
		nil, // No prometheus registry
		startFunc,
		[]byte(s.walletID),
		protocol.DefaultConfig(),
	)
	if err != nil {
		cancel()
		s.logger.Error().Err(err).Msg("[FROST] ERROR: Failed to create handler")
		s.errCh <- err
		return
	}
	s.logger.Info().Msg("[FROST] Protocol handler created successfully")

	s.handler = handler

	// Start message handling goroutine
	go s.handleProtocolMessages()

	// Timeout watchdog
	go func() {
		<-ctx.Done()
		cancel()
		if ctx.Err() == context.DeadlineExceeded {
			s.logger.Error().
				Str("walletID", s.walletID).
				Dur("timeout", KeygenTimeout).
				Msg("FROST keygen session timed out")
			select {
			case s.externalFinishChan <- "":
			default:
			}
		}
	}()

	s.logger.Info().
		Str("partyID", string(s.selfPartyID)).
		Interface("peerIDs", s.partyIDs).
		Str("walletID", s.walletID).
		Msg("[INITIALIZED] FROST keygen session initialized successfully")
}

func (s *frostKeygenSession) handleProtocolMessages() {
	for {
		select {
		case protoMsg, ok := <-s.handler.Listen():
			if !ok {
				// Protocol finished
				s.logger.Info().Msg("[FROST-PROTOCOL] handler.Listen() returned !ok - protocol finished")
				s.resultMutex.Lock()
				s.done = true
				result, err := s.handler.Result()
				if err != nil {
					s.logger.Error().Err(err).Msg("[FROST-PROTOCOL] handler.Result() returned error")
					s.resultErr = err
					s.errCh <- err
				} else {
					cfg, ok := result.(*frost.Config)
					if !ok {
						// A different concrete type means a different curve ran.
						// Refuse it rather than reach into it: the whole point of
						// this session is that only an Ed25519 config may leave it.
						err := fmt.Errorf("FROST keygen returned %T, want *frost.Config over edwards25519", result)
						s.logger.Error().Err(err).Msg("[FROST-PROTOCOL] wrong config type from keygen")
						s.resultErr = err
						s.errCh <- err
					} else {
						s.config = cfg
						if pubBytes, mErr := cfg.PublicKey.MarshalBinary(); mErr == nil {
							s.logger.Info().
								Int("publicKeyLen", len(pubBytes)).
								Str("publicKeyHex", fmt.Sprintf("%x", pubBytes)).
								Msg("[FROST-PROTOCOL] handler.Result() returned valid config")
						} else {
							s.logger.Warn().Err(mErr).Msg("[FROST-PROTOCOL] could not marshal public key")
						}
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
			s.logger.Info().
				Str("from", string(protoMsg.From)).
				Str("to", string(protoMsg.To)).
				Bool("broadcast", protoMsg.Broadcast).
				Int("round", int(protoMsg.RoundNumber)).
				Hex("ssid", protoMsg.SSID).
				Int("dataLen", len(protoMsg.Data)).
				Msg("FROST: Received protocol message, checking CanAccept")

			if !s.handler.CanAccept(protoMsg) {
				s.logger.Warn().
					Str("from", string(protoMsg.From)).
					Str("to", string(protoMsg.To)).
					Bool("broadcast", protoMsg.Broadcast).
					Int("round", int(protoMsg.RoundNumber)).
					Hex("ssid", protoMsg.SSID).
					Str("selfPartyID", string(s.selfPartyID)).
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

func (s *frostKeygenSession) ProcessInboundMessage(msgBytes []byte) {
	s.processingLock.Lock()
	defer s.processingLock.Unlock()

	// First, unmarshal the wire format to get routing info
	inboundMessage := &types.Message{}
	if err := json.Unmarshal(msgBytes, inboundMessage); err != nil {
		s.logger.Error().Err(err).Msg("FROST: ProcessInboundMessage unmarshal error")
		return
	}

	// Verify Ed25519 signature on the wire message
	if err := s.verifyInboundSignature(inboundMessage); err != nil {
		s.logger.Warn().Err(err).Str("sender", inboundMessage.SenderNodeID).Msg("Dropping message with invalid signature")
		return
	}

	// Deduplication check using message body hash
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

func (s *frostKeygenSession) ProcessOutboundMessage() {
	s.logger.Info().Msgf("FROST: ProcessOutboundMessage started: %s", s.walletID)
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
			s.logger.Error().Err(err).Msg("FROST: Received error during ProcessOutboundMessage")

		case <-s.finishCh:
			s.logger.Info().Msg("FROST: Received finish message during ProcessOutboundMessage")
			s.publishResult()
			return
		}
	}
}

func (s *frostKeygenSession) publishResult() {
	s.resultMutex.Lock()
	defer s.resultMutex.Unlock()

	if s.resultErr != nil {
		// Report the failure to the caller and to nobody else. This ceremony is
		// one leg of a wallet's key set, not the wallet's verdict: a wallet whose
		// secp256k1 leg succeeded is still a good wallet with no Solana address.
		// Publishing a keygen failure from here would race the orchestrator's
		// success event on the same subject, and whichever landed first would
		// win — so the leg reports, and only the orchestrator publishes.
		s.logger.Error().Err(s.resultErr).Msg("FROST: Ed25519 keygen failed with error")
		// IMPORTANT: Always send to externalFinishChan so WaitForFinish() doesn't block forever
		s.externalFinishChan <- ""
		return
	}

	if s.config == nil {
		s.logger.Error().Msg("FROST: No config available after keygen completion")
		// IMPORTANT: Always send to externalFinishChan so WaitForFinish() doesn't block forever
		s.externalFinishChan <- ""
		return
	}

	// CBOR, not JSON: the curve types have no JSON marshalers and would
	// round-trip to nothing.
	shareBytes, err := MarshalEd25519Config(s.config)
	if err != nil {
		s.logger.Error().Err(err).Msg("FROST: Failed to marshal key share")
		// IMPORTANT: Always send to externalFinishChan so WaitForFinish() doesn't block forever
		s.externalFinishChan <- ""
		return
	}

	if err := s.kvstore.Put(OrgScopedKey(s.orgID, Ed25519ShareKey(s.walletID)), shareBytes); err != nil {
		s.logger.Error().Err(err).Msgf("FROST: Failed to save key share for wallet %s", s.walletID)
		// IMPORTANT: Always send to externalFinishChan so WaitForFinish() doesn't block forever
		s.externalFinishChan <- ""
		return
	}

	// Publish the public key only if it re-encodes cleanly. An empty string here
	// means no eddsa_pub_key and therefore no Solana address — the system
	// declining to name an address it is not certain it can sign for, which is
	// the correct outcome, not a degraded one.
	var pubKeyHex string
	pubBytes, err := s.config.PublicKey.MarshalBinary()
	if err != nil || len(pubBytes) != 32 {
		s.logger.Error().Err(err).
			Int("pubKeyLen", len(pubBytes)).
			Msg("[FROST-PUBLISH] Ed25519 public key did not marshal to 32 bytes; publishing nothing")
	} else {
		pubKeyHex = fmt.Sprintf("%x", pubBytes)
		s.logger.Info().
			Int("configPubKeyLen", len(pubBytes)).
			Str("pubKeyHex", pubKeyHex).
			Msg("[FROST-PUBLISH] Ed25519 PublicKey available")
	}

	// Notify via external finish channel
	s.logger.Info().Str("sendingPubKeyHex", pubKeyHex).Msg("[FROST-PUBLISH] Sending to externalFinishChan")
	s.externalFinishChan <- pubKeyHex

	s.logger.Info().
		Str("walletID", s.walletID).
		Str("publicKey", pubKeyHex).
		Msg("FROST keygen completed successfully")
}

func (s *frostKeygenSession) Stop() {
	close(s.outCh)
	close(s.errCh)
	close(s.messagesCh)
}

func (s *frostKeygenSession) WaitForFinish() string {
	return <-s.externalFinishChan
}

// GetPublicKey returns the 32-byte Ed25519 public key after keygen completes,
// or nil if there is not one. nil is a usable answer; a wrong 32 bytes is not.
func (s *frostKeygenSession) GetPublicKey() []byte {
	s.resultMutex.Lock()
	defer s.resultMutex.Unlock()
	if s.config == nil || s.config.PublicKey == nil {
		return nil
	}
	pubBytes, err := s.config.PublicKey.MarshalBinary()
	if err != nil {
		return nil
	}
	return pubBytes
}
