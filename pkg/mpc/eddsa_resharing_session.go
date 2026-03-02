package mpc

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"

	"github.com/luxfi/threshold/pkg/party"
	"github.com/rs/zerolog"

	"github.com/luxfi/mpc/pkg/keyinfo"
	"github.com/luxfi/mpc/pkg/kvstore"
	"github.com/luxfi/mpc/pkg/messaging"
	"github.com/luxfi/mpc/pkg/protocol"
	"github.com/luxfi/mpc/pkg/protocol/frost"
	"github.com/luxfi/mpc/pkg/types"
	"github.com/luxfi/mpc/pkg/utils"
)

// reshareProtocolMessage adapts types.Message fields to protocol.Message interface
// for routing inbound wire-format messages into the FROST protocol party.
type reshareProtocolMessage struct {
	from      string
	to        []string
	data      []byte
	broadcast bool
}

func (m *reshareProtocolMessage) GetFrom() string   { return m.from }
func (m *reshareProtocolMessage) GetTo() []string   { return m.to }
func (m *reshareProtocolMessage) GetData() []byte   { return m.data }
func (m *reshareProtocolMessage) IsBroadcast() bool { return m.broadcast }

// eddsaReshareSession implements ReshareSession for EdDSA using FROST
type eddsaReshareSession struct {
	session
	isNewPeer    bool
	pubKeyResult []byte
	kvstore      kvstore.KVStore
	keyinfoStore keyinfo.Store
	resultQueue  messaging.MessageQueue
	protocol     protocol.Protocol
	party        protocol.Party
	config       protocol.KeyGenConfig
	newThreshold int
	newNodeIDs   []string
}

// newEdDSAReshareSession creates a new EdDSA reshare session
func newEdDSAReshareSession(
	walletID string,
	threshold int,
	newThreshold int,
	newNodeIDs []string,
	isNewPeer bool,
	pubSub messaging.PubSub,
	kvstore kvstore.KVStore,
	keyinfoStore keyinfo.Store,
	resultQueue messaging.MessageQueue,
	selfNodeID string,
) (*eddsaReshareSession, error) {
	// Generate session ID for resharing
	sessionID := fmt.Sprintf("reshare-%s", walletID)

	// For resharing, we need to determine the party IDs
	var partyIDs []party.ID

	if !isNewPeer {
		// For old peers, get the existing key info to find current parties
		keyInfo, err := keyinfoStore.Get(walletID)
		if err != nil {
			return nil, fmt.Errorf("failed to get key info for resharing: %w", err)
		}

		// Old peers use their existing party IDs
		for _, id := range keyInfo.ParticipantPeerIDs {
			partyIDs = append(partyIDs, party.ID(id))
		}
	} else {
		// New peers use the new node IDs
		for _, id := range newNodeIDs {
			partyIDs = append(partyIDs, party.ID(id))
		}
	}

	// Create FROST protocol
	protocol := frost.NewFROSTProtocol()

	s := &eddsaReshareSession{
		session: session{
			walletID:           walletID,
			sessionID:          sessionID,
			pubSub:             pubSub,
			selfPartyID:        party.ID(selfNodeID),
			partyIDs:           partyIDs,
			subscriberList:     []messaging.Subscription{},
			rounds:             3, // FROST has fewer rounds
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
					return fmt.Sprintf("reshare:broadcast:frost:%s", walletID)
				},
				ComposeDirectTopic: func(nodeID string) string {
					return fmt.Sprintf("reshare:direct:frost:%s:%s", nodeID, walletID)
				},
			},
			identityStore: nil, // Not needed for resharing
		},
		isNewPeer:    isNewPeer,
		kvstore:      kvstore,
		keyinfoStore: keyinfoStore,
		resultQueue:  resultQueue,
		protocol:     protocol,
		newThreshold: newThreshold,
		newNodeIDs:   newNodeIDs,
	}

	// Load existing config for old peers
	if !isNewPeer {
		config, err := s.loadConfig(walletID)
		if err != nil {
			return nil, fmt.Errorf("failed to load existing config: %w", err)
		}
		s.config = config
	}

	return s, nil
}

// Init initializes the reshare session
func (s *eddsaReshareSession) Init() {
	s.logger.Info().
		Str("sessionID", s.sessionID).
		Bool("isNewPeer", s.isNewPeer).
		Int("threshold", s.threshold).
		Int("newThreshold", s.newThreshold).
		Msg("Initializing EdDSA/FROST reshare session")
}

// Reshare starts the resharing protocol
func (s *eddsaReshareSession) Reshare(done func()) {
	defer done()

	s.logger.Info().
		Str("sessionID", s.sessionID).
		Bool("isNewPeer", s.isNewPeer).
		Int("threshold", s.threshold).
		Msg("Starting EdDSA/FROST reshare session")

	// Create the protocol party
	var err error
	if s.isNewPeer {
		// New peers participate in key generation with the new committee
		s.party, err = s.protocol.KeyGen(
			string(s.selfPartyID),
			convertFromPartyIDs(s.partyIDs),
			s.newThreshold,
		)
	} else {
		// Old peers run the refresh protocol
		s.party, err = s.protocol.Refresh(s.config)
	}

	if err != nil {
		s.errCh <- fmt.Errorf("failed to create reshare party: %w", err)
		return
	}

	// Start listening for messages
	s.ListenToIncomingMessageAsync()
	go s.ProcessOutboundMessage()

	// Wait for protocol to complete
	<-s.finishCh

	// Process the result
	if s.party.Done() {
		result, err := s.party.Result()
		if err != nil {
			s.errCh <- fmt.Errorf("reshare protocol failed: %w", err)
			return
		}

		// Handle the result
		if newConfig, ok := result.(protocol.KeyGenConfig); ok {
			// Save the new configuration
			if err := s.saveConfig(newConfig); err != nil {
				s.errCh <- fmt.Errorf("failed to save reshare result: %w", err)
				return
			}

			// Extract the Ed25519/Taproot public key from the FROST result.
			// The frostConfigAdapter (from pkg/protocol/frost/) exposes
			// GetPublicKeyBytes() which returns the raw public key bytes.
			type eddsaPubKeyProvider interface {
				GetPublicKeyBytes() []byte
			}
			if provider, ok := newConfig.(eddsaPubKeyProvider); ok {
				s.pubKeyResult = provider.GetPublicKeyBytes()
			} else {
				// Fallback: try to serialize the config and extract from the
				// serialized data. FROST TaprootConfig stores PublicKey as a
				// 32-byte x-only key in the JSON/CBOR representation.
				if configData, err := newConfig.Serialize(); err == nil {
					var rawMap map[string]json.RawMessage
					if json.Unmarshal(configData, &rawMap) == nil {
						if pubKeyRaw, exists := rawMap["PublicKey"]; exists {
							var pubKeyBytes []byte
							if json.Unmarshal(pubKeyRaw, &pubKeyBytes) == nil && len(pubKeyBytes) > 0 {
								s.pubKeyResult = pubKeyBytes
							}
						}
					}
				}
			}

			pubKeyHex := fmt.Sprintf("%x", s.pubKeyResult)
			s.logger.Info().
				Str("sessionID", s.sessionID).
				Bool("isNewPeer", s.isNewPeer).
				Str("publicKey", pubKeyHex).
				Msg("EdDSA/FROST reshare completed successfully")
		} else {
			s.errCh <- fmt.Errorf("unexpected result type from reshare: %T", result)
		}
	}
}

// ProcessInboundMessage handles incoming protocol messages from the transport
// layer and routes them to the FROST reshare protocol party.
func (s *eddsaReshareSession) ProcessInboundMessage(msgBytes []byte) {
	s.processingLock.Lock()
	defer s.processingLock.Unlock()

	// Unmarshal wire format to extract routing info and body
	inboundMessage := &types.Message{}
	if err := json.Unmarshal(msgBytes, inboundMessage); err != nil {
		s.logger.Error().Err(err).Msg("EdDSA reshare: failed to unmarshal inbound message")
		return
	}

	// Deduplication check using body hash
	msgHashStr := fmt.Sprintf("%x", utils.GetMessageHash(inboundMessage.Body))
	if s.processing[msgHashStr] {
		return
	}
	s.processing[msgHashStr] = true

	if s.party == nil {
		s.logger.Warn().Msg("EdDSA reshare: protocol party not initialized, dropping message")
		return
	}

	// Create a protocol message adapter and route to the party
	protoMsg := &reshareProtocolMessage{
		from:      inboundMessage.SenderID,
		to:        inboundMessage.RecipientIDs,
		data:      inboundMessage.Body,
		broadcast: inboundMessage.IsBroadcast,
	}

	if err := s.party.Update(protoMsg); err != nil {
		s.logger.Debug().Err(err).
			Str("from", inboundMessage.SenderID).
			Msg("EdDSA reshare: party rejected message")
	}
}

// ProcessOutboundMessage reads outgoing protocol messages from the FROST
// reshare party and sends them to remote peers via the transport layer.
func (s *eddsaReshareSession) ProcessOutboundMessage() {
	s.logger.Info().Str("sessionID", s.sessionID).Msg("EdDSA reshare: ProcessOutboundMessage started")

	if s.party == nil {
		s.logger.Error().Msg("EdDSA reshare: protocol party not initialized")
		return
	}

	msgCh := s.party.Messages()

	for {
		select {
		case protoMsg, ok := <-msgCh:
			if !ok {
				// Protocol completed; check result and signal finish
				s.logger.Info().Msg("EdDSA reshare: protocol messages channel closed")
				s.finishCh <- true
				return
			}

			// Wrap protocol message in wire format and send
			wireMsg := &types.Message{
				SessionID:    s.walletID,
				SenderID:     string(s.selfPartyID),
				RecipientIDs: protoMsg.GetTo(),
				Body:         protoMsg.GetData(),
				IsBroadcast:  protoMsg.IsBroadcast(),
			}

			s.sendMsg(wireMsg)

		case err := <-s.errCh:
			s.logger.Error().Err(err).Msg("EdDSA reshare: error during ProcessOutboundMessage")
		}
	}
}

// GetPubKeyResult returns the public key after successful resharing
func (s *eddsaReshareSession) GetPubKeyResult() []byte {
	return s.pubKeyResult
}

// IsNewPeer returns true if this node is joining as a new peer
func (s *eddsaReshareSession) IsNewPeer() bool {
	return s.isNewPeer
}

// ErrChan returns the error channel
func (s *eddsaReshareSession) ErrChan() <-chan error {
	return s.errCh
}

// Stop stops the session
func (s *eddsaReshareSession) Stop() {
	// Protocol doesn't have Close method
	close(s.outCh)
	close(s.errCh)
}

// WaitForFinish waits for the session to complete
func (s *eddsaReshareSession) WaitForFinish() string {
	return <-s.externalFinishChan
}

// loadConfig loads the existing key configuration
func (s *eddsaReshareSession) loadConfig(walletID string) (protocol.KeyGenConfig, error) {
	// Get key info
	keyInfo, err := s.keyinfoStore.Get(walletID)
	if err != nil {
		return nil, err
	}

	// Load the key share data
	keyShareData, err := s.kvstore.Get(walletID)
	if err != nil {
		return nil, err
	}

	// Create a config adapter for EdDSA
	return &eddsaKeyGenConfigAdapter{
		keyInfo:      keyInfo,
		keyShareData: keyShareData,
		walletID:     walletID,
	}, nil
}

// saveConfig saves the new key configuration after resharing
func (s *eddsaReshareSession) saveConfig(config protocol.KeyGenConfig) error {
	// Serialize the config
	configData, err := config.Serialize()
	if err != nil {
		return fmt.Errorf("failed to serialize config: %w", err)
	}

	// Save to kvstore
	if err := s.kvstore.Put(s.walletID, configData); err != nil {
		return fmt.Errorf("failed to save share data: %w", err)
	}

	// Update key info
	keyInfo := &keyinfo.KeyInfo{
		ParticipantPeerIDs: s.newNodeIDs,
		Threshold:          s.newThreshold,
		Version:            1,
	}

	if err := s.keyinfoStore.Save(s.walletID, keyInfo); err != nil {
		return fmt.Errorf("failed to save key info: %w", err)
	}

	return nil
}

// eddsaKeyGenConfigAdapter adapts stored key data to protocol.KeyGenConfig interface for EdDSA
type eddsaKeyGenConfigAdapter struct {
	keyInfo      *keyinfo.KeyInfo
	keyShareData []byte
	walletID     string
}

func (a *eddsaKeyGenConfigAdapter) GetPartyID() string {
	// Extract from the stored data
	var data map[string]interface{}
	if err := json.Unmarshal(a.keyShareData, &data); err != nil {
		return ""
	}
	if id, ok := data["ID"].(string); ok {
		return id
	}
	return ""
}

func (a *eddsaKeyGenConfigAdapter) GetThreshold() int {
	return a.keyInfo.Threshold
}

func (a *eddsaKeyGenConfigAdapter) GetPublicKey() *ecdsa.PublicKey {
	// EdDSA doesn't use ECDSA public keys
	return nil
}

// GetPublicKeyEd25519 returns the Ed25519 public key
func (a *eddsaKeyGenConfigAdapter) GetPublicKeyEd25519() ed25519.PublicKey {
	// Extract from stored data
	var data map[string]interface{}
	if err := json.Unmarshal(a.keyShareData, &data); err != nil {
		return nil
	}

	// This is a simplified version - actual implementation would need proper parsing
	return nil
}

func (a *eddsaKeyGenConfigAdapter) GetShare() *big.Int {
	// EdDSA shares are handled differently
	return nil
}

func (a *eddsaKeyGenConfigAdapter) GetSharePublicKey() *ecdsa.PublicKey {
	// EdDSA doesn't use ECDSA public keys
	return nil
}

func (a *eddsaKeyGenConfigAdapter) GetPartyIDs() []string {
	return a.keyInfo.ParticipantPeerIDs
}

func (a *eddsaKeyGenConfigAdapter) Serialize() ([]byte, error) {
	return a.keyShareData, nil
}
