package mpc

import (
	"strings"
	"sync"
	"time"

	"github.com/luxfi/threshold/pkg/party"
	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog"

	"github.com/luxfi/mpc/pkg/common/errors"
	"github.com/luxfi/mpc/pkg/encoding"
	"github.com/luxfi/mpc/pkg/identity"
	"github.com/luxfi/mpc/pkg/keyinfo"
	"github.com/luxfi/mpc/pkg/kvstore"
	"github.com/luxfi/mpc/pkg/messaging"
	"github.com/luxfi/mpc/pkg/types"
)

const (
	// KeygenTimeout is the maximum duration for a DKG session.
	KeygenTimeout = 5 * time.Minute
	// SigningTimeout is the maximum duration for a signing session.
	SigningTimeout = 30 * time.Second
	// ReshareTimeout is the maximum duration for a reshare session.
	ReshareTimeout = 5 * time.Minute
)

const (
	// dedupTTL is how long a dedup entry is retained before cleanup.
	dedupTTL = 10 * time.Minute
	// dedupCleanupInterval is how often the cleanup goroutine runs.
	dedupCleanupInterval = 2 * time.Minute
)

// dedupMap is a thread-safe map with TTL-based expiry for message dedup.
type dedupMap struct {
	mu      sync.Mutex
	entries map[string]time.Time
	stopCh  chan struct{}
}

func newDedupMap() *dedupMap {
	d := &dedupMap{
		entries: make(map[string]time.Time),
		stopCh:  make(chan struct{}),
	}
	go d.cleanupLoop()
	return d
}

// seen returns true if the key was already seen (not expired). If not seen,
// it records the key and returns false.
func (d *dedupMap) seen(key string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if t, ok := d.entries[key]; ok && time.Since(t) < dedupTTL {
		return true
	}
	d.entries[key] = time.Now()
	return false
}

func (d *dedupMap) cleanupLoop() {
	ticker := time.NewTicker(dedupCleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			d.mu.Lock()
			now := time.Now()
			for k, t := range d.entries {
				if now.Sub(t) >= dedupTTL {
					delete(d.entries, k)
				}
			}
			d.mu.Unlock()
		case <-d.stopCh:
			return
		}
	}
}

func (d *dedupMap) stop() {
	select {
	case <-d.stopCh:
	default:
		close(d.stopCh)
	}
}

type SessionType string

const (
	TypeGenerateWalletResultFmt = "mpc.mpc_keygen_result.%s"
	TypeReshareWalletResultFmt  = "mpc.mpc_reshare_result.%s"

	SessionTypeCGGMP21 SessionType = "session_cggmp21"
	SessionTypeECDSA   SessionType = "ecdsa"
	SessionTypeEDDSA   SessionType = "eddsa"
	SessionTypeSR25519 SessionType = "sr25519"
	SessionTypeBLS     SessionType = "bls"
)

var (
	ErrNotEnoughParticipants = errors.New("Not enough participants to sign")
	ErrNotInParticipantList  = errors.New("Node is not in the participant list")
)

type TopicComposer struct {
	ComposeBroadcastTopic func() string
	ComposeDirectTopic    func(nodeID string) string
}

type KeyComposerFn func(id string) string

type Session interface {
	ListenToIncomingMessageAsync()
	ErrChan() <-chan error
	Init()
	ProcessOutboundMessage()
	WaitForFinish() string
}

type session struct {
	walletID           string
	sessionID          string
	pubSub             messaging.PubSub
	selfPartyID        party.ID
	partyIDs           []party.ID
	subscriberList     []messaging.Subscription
	rounds             int
	outCh              chan msg
	errCh              chan error
	finishCh           chan bool
	externalFinishChan chan string
	threshold          int
	kvstore            kvstore.KVStore
	keyinfoStore       keyinfo.Store
	resultQueue        messaging.MessageQueue
	logger             zerolog.Logger
	processing         *dedupMap
	processingLock     sync.Mutex // kept for backward compat in concrete sessions
	topicComposer      *TopicComposer
	identityStore      identity.Store
}

type msg struct {
	FromPartyID party.ID
	ToPartyIDs  []party.ID
	IsBroadcast bool
	Data        []byte
}

func (s *session) ListenToIncomingMessageAsync() {
	// Subscribe to broadcast messages
	broadcastTopic := s.topicComposer.ComposeBroadcastTopic()
	broadcastSub, err := s.pubSub.Subscribe(broadcastTopic, func(m *nats.Msg) {
		s.logger.Debug().
			Str("topic", broadcastTopic).
			Int("size", len(m.Data)).
			Msg("Received broadcast message")
		s.ProcessInboundMessage(m.Data)
	})

	if err != nil {
		s.logger.Error().Err(err).Msgf("Failed to subscribe to broadcast topic %s", broadcastTopic)
		s.errCh <- err
		return
	}

	s.subscriberList = append(s.subscriberList, broadcastSub)

	// Subscribe to direct messages
	directTopic := s.topicComposer.ComposeDirectTopic(string(s.selfPartyID))
	directSub, err := s.pubSub.Subscribe(directTopic, func(m *nats.Msg) {
		s.logger.Debug().
			Str("topic", directTopic).
			Int("size", len(m.Data)).
			Msg("Received direct message")
		s.ProcessInboundMessage(m.Data)
	})

	if err != nil {
		s.logger.Error().Err(err).Msgf("Failed to subscribe to direct topic %s", directTopic)
		s.errCh <- err
		return
	}

	s.subscriberList = append(s.subscriberList, directSub)

	s.logger.Info().
		Str("broadcast", broadcastTopic).
		Str("direct", directTopic).
		Msg("Listening to incoming messages")
}

func (s *session) ProcessInboundMessage(msgBytes []byte) {
	// Base session does not process messages. Concrete session types (e.g.
	// cggmp21KeygenSession, frostKeygenSession) override this method. If
	// this base implementation is reached, it means a session was used
	// without being properly embedded. Log an error and discard the message
	// rather than crashing the process.
	s.logger.Error().
		Str("walletID", s.walletID).
		Int("msgLen", len(msgBytes)).
		Msg("ProcessInboundMessage called on base session (not overridden); message discarded")
}

func (s *session) ProcessOutboundMessage() {
	// Base session does not process outbound messages. Concrete session
	// types override this. Log an error and return gracefully rather than
	// crashing the process.
	s.logger.Error().
		Str("walletID", s.walletID).
		Msg("ProcessOutboundMessage called on base session (not overridden); no-op")
}

// extractNodeID extracts the raw node ID from a party ID that may have suffixes
// e.g., "nodeID:keygen:1" -> "nodeID"
func extractNodeID(partyID string) string {
	// Check for the pattern nodeID:purpose:version
	parts := strings.Split(partyID, ":")
	if len(parts) >= 1 {
		return parts[0]
	}
	return partyID
}

func (s *session) sendMsg(message *types.Message) {
	// Set sender node ID and sign the message with Ed25519 for authentication
	message.SenderNodeID = extractNodeID(string(s.selfPartyID))
	if s.identityStore != nil {
		s.identityStore.SignWireMessage(message)
	}

	data, err := encoding.StructToJsonBytes(message)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to marshal message")
		return
	}

	if message.IsBroadcast {
		topic := s.topicComposer.ComposeBroadcastTopic()
		if err := s.pubSub.Publish(topic, data); err != nil {
			s.logger.Error().Err(err).Msgf("Failed to publish broadcast message to %s", topic)
		} else {
			s.logger.Debug().Str("topic", topic).Msg("Published broadcast message")
		}
	} else {
		// Send to specific recipients
		for _, recipient := range message.RecipientIDs {
			// Extract raw nodeID from party ID (e.g., "nodeID:keygen:1" -> "nodeID")
			nodeID := extractNodeID(recipient)
			topic := s.topicComposer.ComposeDirectTopic(nodeID)
			if err := s.pubSub.Publish(topic, data); err != nil {
				s.logger.Error().Err(err).Msgf("Failed to publish direct message to %s", topic)
			} else {
				s.logger.Debug().
					Str("topic", topic).
					Str("recipient", recipient).
					Str("nodeID", nodeID).
					Msg("Published direct message")
			}
		}
	}
}

// verifyInboundSignature checks the Ed25519 signature on an inbound wire message.
// Returns nil if the signature is valid or if the identity store is not configured.
func (s *session) verifyInboundSignature(msg *types.Message) error {
	if s.identityStore == nil {
		return nil
	}
	return s.identityStore.VerifyWireMessage(msg)
}

func (s *session) ErrChan() <-chan error {
	return s.errCh
}

func (s *session) unsubscribe() {
	for _, sub := range s.subscriberList {
		if err := sub.Unsubscribe(); err != nil {
			s.logger.Error().Err(err).Msg("Failed to unsubscribe")
		}
	}
	s.subscriberList = nil
}

func (s *session) Stop() {
	s.unsubscribe()
}

// Helper function to get party routing destination
func PartyIDToRoutingDest(partyID party.ID) string {
	// Extract node ID from party ID if it contains version info
	nodeID := string(partyID)
	// Simple extraction - in production you'd have more robust parsing
	return nodeID
}
