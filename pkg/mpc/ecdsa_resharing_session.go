package mpc

import (
	"crypto/ecdsa"
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
	"github.com/luxfi/mpc/pkg/protocol/cggmp21"
	"github.com/luxfi/mpc/pkg/types"
	"github.com/luxfi/mpc/pkg/utils"
)

// cggmp21ReshareSession implements ReshareSession for ECDSA using CGGMP21
type cggmp21ReshareSession struct {
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

// newCGGMP21ReshareSession creates a new CGGMP21 reshare session
func newCGGMP21ReshareSession(
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
) (*cggmp21ReshareSession, error) {
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

	// Create CGGMP21 protocol
	protocol := cggmp21.NewCGGMP21Protocol()

	s := &cggmp21ReshareSession{
		session: session{
			walletID:           walletID,
			sessionID:          sessionID,
			pubSub:             pubSub,
			selfPartyID:        party.ID(selfNodeID),
			partyIDs:           partyIDs,
			subscriberList:     []messaging.Subscription{},
			rounds:             5, // CGGMP21 has 5 rounds
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
					return fmt.Sprintf("reshare:broadcast:cggmp21:%s", walletID)
				},
				ComposeDirectTopic: func(nodeID string) string {
					return fmt.Sprintf("reshare:direct:cggmp21:%s:%s", nodeID, walletID)
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
func (s *cggmp21ReshareSession) Init() {
	s.logger.Info().
		Str("sessionID", s.sessionID).
		Bool("isNewPeer", s.isNewPeer).
		Int("threshold", s.threshold).
		Int("newThreshold", s.newThreshold).
		Msg("Initializing CGGMP21 reshare session")
}

// Reshare starts the resharing protocol
func (s *cggmp21ReshareSession) Reshare(done func()) {
	defer done()

	s.logger.Info().
		Str("sessionID", s.sessionID).
		Bool("isNewPeer", s.isNewPeer).
		Int("threshold", s.threshold).
		Msg("Starting CGGMP21 reshare session")

	// Create the protocol party
	var err error
	if s.isNewPeer {
		// New peers participate in key generation with the new committee
		// For new peers, this is essentially a new key generation
		// but coordinated with the refresh protocol of old peers
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

		// Handle the result based on peer type
		if newConfig, ok := result.(protocol.KeyGenConfig); ok {
			// Save the new configuration
			if err := s.saveConfig(newConfig); err != nil {
				s.errCh <- fmt.Errorf("failed to save reshare result: %w", err)
				return
			}

			// Extract public key for result
			pubKey := newConfig.GetPublicKey()
			if pubKey != nil {
				pubKeyBytes := append(pubKey.X.Bytes(), pubKey.Y.Bytes()...)
				s.pubKeyResult = pubKeyBytes
			}

			s.logger.Info().
				Str("sessionID", s.sessionID).
				Bool("isNewPeer", s.isNewPeer).
				Msg("CGGMP21 reshare completed successfully")
		} else {
			s.errCh <- fmt.Errorf("unexpected result type from reshare: %T", result)
		}
	}
}

// ProcessInboundMessage handles incoming protocol messages from the transport
// layer and routes them to the CGGMP21 reshare protocol party.
func (s *cggmp21ReshareSession) ProcessInboundMessage(msgBytes []byte) {
	s.processingLock.Lock()
	defer s.processingLock.Unlock()

	// Unmarshal wire format
	inboundMessage := &types.Message{}
	if err := json.Unmarshal(msgBytes, inboundMessage); err != nil {
		s.logger.Error().Err(err).Msg("CGGMP21 reshare: failed to unmarshal inbound message")
		return
	}

	// Deduplication
	msgHashStr := fmt.Sprintf("%x", utils.GetMessageHash(inboundMessage.Body))
	if s.processing[msgHashStr] {
		return
	}
	s.processing[msgHashStr] = true

	if s.party == nil {
		s.logger.Warn().Msg("CGGMP21 reshare: protocol party not initialized, dropping message")
		return
	}

	// Route to protocol party via the protocol.Message interface
	protoMsg := &reshareProtocolMessage{
		from:      inboundMessage.SenderID,
		to:        inboundMessage.RecipientIDs,
		data:      inboundMessage.Body,
		broadcast: inboundMessage.IsBroadcast,
	}

	if err := s.party.Update(protoMsg); err != nil {
		s.logger.Debug().Err(err).
			Str("from", inboundMessage.SenderID).
			Msg("CGGMP21 reshare: party rejected message")
	}
}

// ProcessOutboundMessage reads outgoing protocol messages from the CGGMP21
// reshare party and sends them to peers via the transport layer.
func (s *cggmp21ReshareSession) ProcessOutboundMessage() {
	s.logger.Info().Str("sessionID", s.sessionID).Msg("CGGMP21 reshare: ProcessOutboundMessage started")

	if s.party == nil {
		s.logger.Error().Msg("CGGMP21 reshare: protocol party not initialized")
		return
	}

	msgCh := s.party.Messages()

	for {
		select {
		case protoMsg, ok := <-msgCh:
			if !ok {
				// Protocol completed
				s.logger.Info().Msg("CGGMP21 reshare: protocol messages channel closed")
				s.finishCh <- true
				return
			}

			wireMsg := &types.Message{
				SessionID:    s.walletID,
				SenderID:     string(s.selfPartyID),
				RecipientIDs: protoMsg.GetTo(),
				Body:         protoMsg.GetData(),
				IsBroadcast:  protoMsg.IsBroadcast(),
			}

			s.sendMsg(wireMsg)

		case err := <-s.errCh:
			s.logger.Error().Err(err).Msg("CGGMP21 reshare: error during ProcessOutboundMessage")
		}
	}
}

// GetPubKeyResult returns the public key after successful resharing
func (s *cggmp21ReshareSession) GetPubKeyResult() []byte {
	return s.pubKeyResult
}

// IsNewPeer returns true if this node is joining as a new peer
func (s *cggmp21ReshareSession) IsNewPeer() bool {
	return s.isNewPeer
}

// ErrChan returns the error channel
func (s *cggmp21ReshareSession) ErrChan() <-chan error {
	return s.errCh
}

// Stop stops the session
func (s *cggmp21ReshareSession) Stop() {
	// Protocol doesn't have Close method
	close(s.outCh)
	close(s.errCh)
}

// WaitForFinish waits for the session to complete
func (s *cggmp21ReshareSession) WaitForFinish() string {
	return <-s.externalFinishChan
}

// loadConfig loads the existing key configuration
func (s *cggmp21ReshareSession) loadConfig(walletID string) (protocol.KeyGenConfig, error) {
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

	// Create a config adapter that implements protocol.KeyGenConfig
	return &keyGenConfigAdapter{
		keyInfo:      keyInfo,
		keyShareData: keyShareData,
		walletID:     walletID,
	}, nil
}

// saveConfig saves the new key configuration after resharing
func (s *cggmp21ReshareSession) saveConfig(config protocol.KeyGenConfig) error {
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

// keyGenConfigAdapter adapts stored key data to protocol.KeyGenConfig interface
type keyGenConfigAdapter struct {
	keyInfo      *keyinfo.KeyInfo
	keyShareData []byte
	walletID     string
}

func (a *keyGenConfigAdapter) GetPartyID() string {
	// Extract from the stored data - this is implementation specific
	var data map[string]interface{}
	if err := json.Unmarshal(a.keyShareData, &data); err != nil {
		return ""
	}
	if id, ok := data["ID"].(string); ok {
		return id
	}
	return ""
}

func (a *keyGenConfigAdapter) GetThreshold() int {
	return a.keyInfo.Threshold
}

func (a *keyGenConfigAdapter) GetPublicKey() *ecdsa.PublicKey {
	// Extract from stored data
	var data map[string]interface{}
	if err := json.Unmarshal(a.keyShareData, &data); err != nil {
		return nil
	}

	// This is a simplified version - actual implementation would need proper parsing
	return nil
}

func (a *keyGenConfigAdapter) GetShare() *big.Int {
	// Extract from the stored data
	var data map[string]interface{}
	if err := json.Unmarshal(a.keyShareData, &data); err != nil {
		return nil
	}

	// This is a simplified version - actual implementation would need proper parsing
	return nil
}

func (a *keyGenConfigAdapter) GetSharePublicKey() *ecdsa.PublicKey {
	// This would need to be extracted from the stored data
	// For now, return nil as it's not critical for refresh
	return nil
}

func (a *keyGenConfigAdapter) GetPartyIDs() []string {
	return a.keyInfo.ParticipantPeerIDs
}

func (a *keyGenConfigAdapter) Serialize() ([]byte, error) {
	return a.keyShareData, nil
}
