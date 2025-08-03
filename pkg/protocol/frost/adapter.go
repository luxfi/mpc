package frost

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/luxfi/mpc/pkg/protocol"
	// "github.com/luxfi/threshold/pkg/math/curve" // Not used directly anymore
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	mpsProtocol "github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/frost"
)

// FROSTProtocol implements the Protocol interface using FROST for EdDSA
type FROSTProtocol struct {
	pool *pool.Pool
}

// NewFROSTProtocol creates a new FROST protocol adapter
func NewFROSTProtocol() *FROSTProtocol {
	return &FROSTProtocol{
		pool: pool.NewPool(0), // Use max threads
	}
}

// Close cleans up resources
func (p *FROSTProtocol) Close() {
	if p.pool != nil {
		p.pool.TearDown()
	}
}

// Name returns the protocol name
func (p *FROSTProtocol) Name() string {
	return "FROST"
}

// KeyGen starts a distributed key generation for EdDSA
func (p *FROSTProtocol) KeyGen(selfID string, partyIDs []string, threshold int) (protocol.Party, error) {
	// Convert string IDs to party.ID
	ids := make([]party.ID, len(partyIDs))
	for i, id := range partyIDs {
		ids[i] = party.ID(id)
	}

	// Create the FROST keygen protocol for Ed25519/Taproot
	startFunc := frost.KeygenTaproot(party.ID(selfID), ids, threshold)

	// Create handler
	handler, err := mpsProtocol.NewMultiHandler(startFunc, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create FROST keygen handler: %w", err)
	}

	return &frostPartyAdapter{
		handler: handler,
		selfID:  selfID,
	}, nil
}

// Refresh refreshes shares from an existing config
func (p *FROSTProtocol) Refresh(cfg protocol.KeyGenConfig) (protocol.Party, error) {
	// Convert to FROST config
	_, err := toFROSTConfig(cfg)
	if err != nil {
		return nil, err
	}

	// Create refresh protocol
	// For now, return error as we need proper config type
	return nil, errors.New("FROST refresh not yet implemented")
}

// Sign starts a signing protocol
func (p *FROSTProtocol) Sign(cfg protocol.KeyGenConfig, signers []string, messageHash []byte) (protocol.Party, error) {
	// Convert to FROST config
	_, err := toFROSTConfig(cfg)
	if err != nil {
		return nil, err
	}

	// Convert signer IDs
	signerIDs := make([]party.ID, len(signers))
	for i, id := range signers {
		signerIDs[i] = party.ID(id)
	}

	// Create sign protocol
	// For now, return error as we need proper config type
	return nil, errors.New("FROST signing not yet implemented")
}

// PreSign starts a presigning protocol
func (p *FROSTProtocol) PreSign(cfg protocol.KeyGenConfig, signers []string) (protocol.Party, error) {
	// FROST doesn't support presigning in the same way as ECDSA protocols
	return nil, errors.New("FROST protocol does not support presigning")
}

// PreSignOnline completes a signature with a presignature
func (p *FROSTProtocol) PreSignOnline(cfg protocol.KeyGenConfig, preSig protocol.PreSignature, messageHash []byte) (protocol.Party, error) {
	// FROST doesn't support presigning in the same way as ECDSA protocols
	return nil, errors.New("FROST protocol does not support presigning")
}

// frostPartyAdapter adapts mpsProtocol.Handler to protocol.Party
type frostPartyAdapter struct {
	handler *mpsProtocol.MultiHandler
	selfID  string
	mu      sync.Mutex
	done    bool
	result  interface{}
	err     error
}

func (p *frostPartyAdapter) Update(msg protocol.Message) error {
	// Convert to MPS message format
	// If broadcast, To is nil. Otherwise, it's the first recipient
	var to party.ID
	if !msg.IsBroadcast() && len(msg.GetTo()) > 0 {
		to = party.ID(msg.GetTo()[0])
	}

	mpsMsg := &mpsProtocol.Message{
		From:      party.ID(msg.GetFrom()),
		To:        to,
		Broadcast: msg.IsBroadcast(),
		Data:      msg.GetData(),
	}

	// Check if handler can accept the message
	if !p.handler.CanAccept(mpsMsg) {
		return errors.New("message rejected by handler")
	}

	// Update handler with message
	// Note: MultiHandler doesn't have Update method, we need to send via Accept
	p.handler.Accept(mpsMsg)
	return nil
}

func (p *frostPartyAdapter) Messages() <-chan protocol.Message {
	ch := make(chan protocol.Message)

	go func() {
		defer close(ch)

		for {
			select {
			case msg, ok := <-p.handler.Listen():
				if !ok {
					// Protocol finished
					p.mu.Lock()
					p.done = true
					p.result, p.err = p.handler.Result()
					p.mu.Unlock()
					return
				}

				// Convert and send message
				var toList []string
				if !msg.Broadcast && msg.To != "" {
					toList = []string{string(msg.To)}
				}

				ch <- &messageAdapter{
					from:      string(msg.From),
					to:        toList,
					data:      msg.Data,
					broadcast: msg.Broadcast,
				}
			}
		}
	}()

	return ch
}

func (p *frostPartyAdapter) Errors() <-chan error {
	// FROST doesn't have a separate error channel
	// Errors are returned in Result()
	ch := make(chan error)
	close(ch)
	return ch
}

func (p *frostPartyAdapter) Done() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.done
}

func (p *frostPartyAdapter) Result() (interface{}, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.done {
		return nil, errors.New("protocol not finished")
	}

	if p.err != nil {
		return nil, p.err
	}

	// Convert result to appropriate type
	switch r := p.result.(type) {
	case *frost.Signature:
		return &frostSignatureAdapter{sig: r}, nil
	default:
		// For config results, wrap them in the adapter
		// TODO: Check the actual type when we have access to FROST config
		return &frostConfigAdapter{config: r}, nil
	}
}

// messageAdapter implements protocol.Message
type messageAdapter struct {
	from      string
	to        []string
	data      []byte
	broadcast bool
}

func (m *messageAdapter) GetFrom() string   { return m.from }
func (m *messageAdapter) GetTo() []string   { return m.to }
func (m *messageAdapter) GetData() []byte   { return m.data }
func (m *messageAdapter) IsBroadcast() bool { return m.broadcast }

// frostConfigAdapter implements protocol.KeyGenConfig for FROST
type frostConfigAdapter struct {
	// TODO: Update this when we have access to the actual FROST config type
	config interface{} // Will be *frost.Config or similar
}

func (c *frostConfigAdapter) GetPartyID() string {
	// TODO: Implement when we have the actual FROST config type
	return ""
}

func (c *frostConfigAdapter) GetThreshold() int {
	// TODO: Implement when we have the actual FROST config type
	return 0
}

// GetPublicKey returns nil for EdDSA as it uses different key type
func (c *frostConfigAdapter) GetPublicKey() *ecdsa.PublicKey {
	// FROST uses Ed25519, not ECDSA
	// This is a limitation of the current interface design
	return nil
}

// GetPublicKeyEd25519 returns the Ed25519 public key
func (c *frostConfigAdapter) GetPublicKeyEd25519() ed25519.PublicKey {
	// TODO: Implement when we have the actual FROST config type
	return nil
}

func (c *frostConfigAdapter) GetShare() *big.Int {
	// TODO: Implement when we have the actual FROST config type
	return nil
}

func (c *frostConfigAdapter) GetSharePublicKey() *ecdsa.PublicKey {
	// FROST uses Ed25519, not ECDSA
	return nil
}

func (c *frostConfigAdapter) GetPartyIDs() []string {
	// TODO: Implement when we have the actual FROST config type
	return nil
}

func (c *frostConfigAdapter) Serialize() ([]byte, error) {
	// TODO: Implement when we have the actual FROST config type
	return json.Marshal(c.config)
}

// frostSignatureAdapter implements protocol.Signature for FROST
type frostSignatureAdapter struct {
	sig *frost.Signature
}

func (s *frostSignatureAdapter) GetR() *big.Int {
	// FROST signatures have an R point, convert X coordinate to big.Int
	if s.sig.R != nil && s.sig.R.XScalar() != nil {
		bytes, _ := s.sig.R.XScalar().MarshalBinary()
		return new(big.Int).SetBytes(bytes)
	}
	return new(big.Int)
}

func (s *frostSignatureAdapter) GetS() *big.Int {
	// FROST signatures don't have a direct S component
	// This is a limitation of the current interface
	return new(big.Int)
}

func (s *frostSignatureAdapter) Verify(pubKey *ecdsa.PublicKey, message []byte) bool {
	// This adapter doesn't support ECDSA verification
	return false
}

// VerifyEd25519 verifies an Ed25519 signature
func (s *frostSignatureAdapter) VerifyEd25519(pubKey ed25519.PublicKey, message []byte) bool {
	// Use the FROST signature's own Verify method
	// TODO: Need to convert ed25519.PublicKey to curve.Point
	return false
}

func (s *frostSignatureAdapter) Serialize() ([]byte, error) {
	// Marshal the signature using JSON for now
	return json.Marshal(s.sig)
}

// Helper functions

func convertToPartyIDs(ids []string) []party.ID {
	if ids == nil {
		return nil
	}
	result := make([]party.ID, len(ids))
	for i, id := range ids {
		result[i] = party.ID(id)
	}
	return result
}

func convertFromPartyIDs(ids []party.ID) []string {
	if ids == nil {
		return nil
	}
	result := make([]string, len(ids))
	for i, id := range ids {
		result[i] = string(id)
	}
	return result
}

func toFROSTConfig(cfg protocol.KeyGenConfig) (interface{}, error) {
	// Try to cast directly first
	if adapter, ok := cfg.(*frostConfigAdapter); ok {
		return adapter.config, nil
	}

	// Otherwise, we need to reconstruct
	// This is a simplified version - in production you'd need proper serialization
	return nil, errors.New("config conversion not implemented for non-FROST configs")
}
