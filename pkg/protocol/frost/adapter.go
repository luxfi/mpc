package frost

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/fxamacker/cbor/v2"
	log "github.com/luxfi/log"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	mpsProtocol "github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/frost"

	"github.com/luxfi/mpc/pkg/protocol"
)

// FROSTProtocol implements the Protocol interface using FROST for EdDSA
type FROSTProtocol struct {
	pool   *pool.Pool
	logger log.Logger
}

// NewFROSTProtocol creates a new FROST protocol adapter
func NewFROSTProtocol() *FROSTProtocol {
	return &FROSTProtocol{
		pool:   pool.NewPool(0), // Use max threads
		logger: log.NewTestLogger(log.InfoLevel),
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

	// Create handler with proper context, logging, and session ID
	ctx := context.Background()
	sessionID := []byte(fmt.Sprintf("frost-keygen-%s", selfID))
	handler, err := mpsProtocol.NewHandler(
		ctx,
		p.logger,
		nil, // No prometheus registry
		startFunc,
		sessionID,
		mpsProtocol.DefaultConfig(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create FROST keygen handler: %w", err)
	}

	return &frostPartyAdapter{
		handler:   handler,
		selfID:    selfID,
		isTaproot: true,
	}, nil
}

// Refresh refreshes shares from an existing config
func (p *FROSTProtocol) Refresh(cfg protocol.KeyGenConfig) (protocol.Party, error) {
	// Convert to FROST config
	frostConfig, err := toFROSTConfig(cfg)
	if err != nil {
		return nil, err
	}

	// Get party IDs from config
	partyIDs := cfg.GetPartyIDs()
	ids := make([]party.ID, len(partyIDs))
	for i, id := range partyIDs {
		ids[i] = party.ID(id)
	}

	// Create refresh protocol
	startFunc := frost.Refresh(frostConfig, ids)

	// Create handler with proper context, logging, and session ID
	ctx := context.Background()
	sessionID := []byte(fmt.Sprintf("frost-refresh-%s", cfg.GetPartyID()))
	handler, err := mpsProtocol.NewHandler(
		ctx,
		p.logger,
		nil, // No prometheus registry
		startFunc,
		sessionID,
		mpsProtocol.DefaultConfig(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create FROST refresh handler: %w", err)
	}

	return &frostPartyAdapter{
		handler:   handler,
		selfID:    cfg.GetPartyID(),
		isTaproot: false,
	}, nil
}

// Sign starts a signing protocol
func (p *FROSTProtocol) Sign(cfg protocol.KeyGenConfig, signers []string, messageHash []byte) (protocol.Party, error) {
	// Convert to FROST config
	frostConfig, err := toFROSTConfig(cfg)
	if err != nil {
		return nil, err
	}

	// Convert signer IDs
	signerIDs := make([]party.ID, len(signers))
	for i, id := range signers {
		signerIDs[i] = party.ID(id)
	}

	// Create sign protocol
	startFunc := frost.Sign(frostConfig, signerIDs, messageHash)

	// Create handler with proper context, logging, and session ID
	ctx := context.Background()
	sessionID := []byte(fmt.Sprintf("frost-sign-%s-%x", cfg.GetPartyID(), messageHash[:8]))
	handler, err := mpsProtocol.NewHandler(
		ctx,
		p.logger,
		nil, // No prometheus registry
		startFunc,
		sessionID,
		mpsProtocol.DefaultConfig(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create FROST sign handler: %w", err)
	}

	return &frostPartyAdapter{
		handler:   handler,
		selfID:    cfg.GetPartyID(),
		isTaproot: false,
	}, nil
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
	handler   *mpsProtocol.Handler
	selfID    string
	isTaproot bool
	mu        sync.Mutex
	done      bool
	result    interface{}
	err       error
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
	case *frost.Config:
		return &frostConfigAdapter{
			config:    r,
			isTaproot: false,
		}, nil
	case *frost.TaprootConfig:
		return &frostConfigAdapter{
			taprootConfig: r,
			isTaproot:     true,
		}, nil
	default:
		return nil, fmt.Errorf("unexpected result type: %T", r)
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
	config        *frost.Config
	taprootConfig *frost.TaprootConfig
	isTaproot     bool
}

func (c *frostConfigAdapter) GetPartyID() string {
	if c.isTaproot && c.taprootConfig != nil {
		return string(c.taprootConfig.ID)
	}
	if c.config != nil {
		return string(c.config.ID)
	}
	return ""
}

func (c *frostConfigAdapter) GetThreshold() int {
	if c.isTaproot && c.taprootConfig != nil {
		return c.taprootConfig.Threshold
	}
	if c.config != nil {
		return c.config.Threshold
	}
	return 0
}

// GetPublicKey returns the public key as an ecdsa.PublicKey.
// For Taproot configs (secp256k1), we recover the full point from the x-only key.
// For regular FROST configs, we convert the curve.Point to ecdsa.PublicKey.
func (c *frostConfigAdapter) GetPublicKey() *ecdsa.PublicKey {
	if c.isTaproot && c.taprootConfig != nil {
		pkBytes := c.taprootConfig.PublicKey
		if len(pkBytes) != 32 {
			return nil
		}
		return xOnlyToECDSA(pkBytes)
	}
	if c.config != nil && c.config.PublicKey != nil && !c.config.PublicKey.IsIdentity() {
		compressed, err := c.config.PublicKey.MarshalBinary()
		if err != nil || len(compressed) != 33 {
			return nil
		}
		return compressedToECDSA(compressed)
	}
	return nil
}

// GetPublicKeyBytes returns the public key as bytes
func (c *frostConfigAdapter) GetPublicKeyBytes() []byte {
	if c.isTaproot && c.taprootConfig != nil {
		return c.taprootConfig.PublicKey
	}
	if c.config != nil && c.config.PublicKey != nil {
		bytes, _ := c.config.PublicKey.MarshalBinary()
		return bytes
	}
	return nil
}

func (c *frostConfigAdapter) GetShare() *big.Int {
	if c.isTaproot && c.taprootConfig != nil {
		bytes, _ := c.taprootConfig.PrivateShare.MarshalBinary()
		return new(big.Int).SetBytes(bytes)
	}
	if c.config != nil && c.config.PrivateShare != nil {
		bytes, _ := c.config.PrivateShare.MarshalBinary()
		return new(big.Int).SetBytes(bytes)
	}
	return nil
}

func (c *frostConfigAdapter) GetSharePublicKey() *ecdsa.PublicKey {
	// FROST uses Ed25519/Schnorr, not ECDSA
	return nil
}

func (c *frostConfigAdapter) GetPartyIDs() []string {
	if c.isTaproot && c.taprootConfig != nil {
		ids := make([]string, 0, len(c.taprootConfig.VerificationShares))
		for id := range c.taprootConfig.VerificationShares {
			ids = append(ids, string(id))
		}
		return ids
	}
	if c.config != nil && c.config.VerificationShares != nil {
		ids := make([]string, 0, len(c.config.VerificationShares.Points))
		for id := range c.config.VerificationShares.Points {
			ids = append(ids, string(id))
		}
		return ids
	}
	return nil
}

func (c *frostConfigAdapter) Serialize() ([]byte, error) {
	if c.isTaproot && c.taprootConfig != nil {
		// Use CBOR serialization: crypto types (Secp256k1Scalar, Secp256k1Point) lack JSON marshalers
		return marshalTaprootConfig(c.taprootConfig)
	}
	if c.config != nil {
		// Regular FROST Config also has curve types without JSON marshalers
		return marshalFROSTRegularConfig(c.config)
	}
	return nil, errors.New("no config to serialize")
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
	// FROST uses Schnorr signatures, not ECDSA
	return false
}

func (s *frostSignatureAdapter) Serialize() ([]byte, error) {
	// Use MarshalBinary which correctly handles curve.Point R and curve.Scalar z
	return s.sig.MarshalBinary()
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

func toFROSTConfig(cfg protocol.KeyGenConfig) (*frost.Config, error) {
	// Try to cast directly first
	if adapter, ok := cfg.(*frostConfigAdapter); ok {
		if adapter.config != nil {
			return adapter.config, nil
		}
		// If it's a Taproot config, convert to regular Config for signing
		if adapter.taprootConfig != nil {
			tc := adapter.taprootConfig
			publicKey, err := curve.Secp256k1{}.LiftX(tc.PublicKey)
			if err != nil {
				return nil, fmt.Errorf("failed to lift taproot public key: %w", err)
			}
			verificationShares := make(map[party.ID]curve.Point, len(tc.VerificationShares))
			for k, v := range tc.VerificationShares {
				verificationShares[k] = v
			}
			return &frost.Config{
				ID:                 tc.ID,
				Threshold:          tc.Threshold,
				PrivateShare:       tc.PrivateShare,
				PublicKey:          publicKey,
				ChainKey:           tc.ChainKey,
				VerificationShares: party.NewPointMap(verificationShares),
			}, nil
		}
	}

	// Otherwise, deserialize via CBOR
	data, err := cfg.Serialize()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize config: %w", err)
	}

	config, err := unmarshalFROSTRegularConfig(data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal as FROST config: %w", err)
	}

	return config, nil
}

// ============================================================================
// CBOR serialization for regular FROST Config (non-Taproot)
// ============================================================================

type frostRegularConfigMarshal struct {
	ID                 party.ID
	Threshold          int
	PrivateShare       []byte
	PublicKey          []byte // 33 bytes compressed
	ChainKey           []byte
	VerificationShares []frostVerificationShareMarshal
}

type frostVerificationShareMarshal struct {
	ID    party.ID
	Point []byte // 33 bytes compressed
}

func marshalFROSTRegularConfig(config *frost.Config) ([]byte, error) {
	privateBytes, err := config.PrivateShare.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private share: %w", err)
	}

	pubBytes, err := config.PublicKey.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	shares := make([]frostVerificationShareMarshal, 0, len(config.VerificationShares.Points))
	for id, point := range config.VerificationShares.Points {
		pointBytes, err := point.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal verification share for %s: %w", id, err)
		}
		shares = append(shares, frostVerificationShareMarshal{
			ID:    id,
			Point: pointBytes,
		})
	}

	cm := &frostRegularConfigMarshal{
		ID:                 config.ID,
		Threshold:          config.Threshold,
		PrivateShare:       privateBytes,
		PublicKey:          pubBytes,
		ChainKey:           config.ChainKey,
		VerificationShares: shares,
	}

	return cbor.Marshal(cm)
}

func unmarshalFROSTRegularConfig(data []byte) (*frost.Config, error) {
	cm := &frostRegularConfigMarshal{}
	if err := cbor.Unmarshal(data, cm); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	group := curve.Secp256k1{}

	privateShare := group.NewScalar()
	if err := privateShare.UnmarshalBinary(cm.PrivateShare); err != nil {
		return nil, fmt.Errorf("failed to unmarshal private share: %w", err)
	}

	publicKey := group.NewPoint()
	if err := publicKey.UnmarshalBinary(cm.PublicKey); err != nil {
		return nil, fmt.Errorf("failed to unmarshal public key: %w", err)
	}

	verificationShares := make(map[party.ID]curve.Point, len(cm.VerificationShares))
	for _, vs := range cm.VerificationShares {
		point := group.NewPoint()
		if err := point.UnmarshalBinary(vs.Point); err != nil {
			return nil, fmt.Errorf("failed to unmarshal verification share for %s: %w", vs.ID, err)
		}
		verificationShares[vs.ID] = point
	}

	return &frost.Config{
		ID:                 cm.ID,
		Threshold:          cm.Threshold,
		PrivateShare:       privateShare,
		PublicKey:          publicKey,
		ChainKey:           cm.ChainKey,
		VerificationShares: party.NewPointMap(verificationShares),
	}, nil
}

// marshalTaprootConfig serializes a TaprootConfig to CBOR bytes.
// Crypto types (Secp256k1Scalar, Secp256k1Point) do not have JSON marshalers,
// so we use a flat intermediate struct with raw byte slices.
type taprootConfigMarshal struct {
	ID                 party.ID
	Threshold          int
	PrivateShare       []byte // 32 bytes (Secp256k1Scalar)
	PublicKey          []byte // 32 bytes (x-only Taproot public key)
	ChainKey           []byte // 32 bytes
	VerificationShares []taprootVerificationShareMarshal
}

type taprootVerificationShareMarshal struct {
	ID    party.ID
	Point []byte // 33 bytes (compressed Secp256k1Point)
}

func marshalTaprootConfig(config *frost.TaprootConfig) ([]byte, error) {
	privateShareBytes, err := config.PrivateShare.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private share: %w", err)
	}

	shares := make([]taprootVerificationShareMarshal, 0, len(config.VerificationShares))
	for id, point := range config.VerificationShares {
		pointBytes, err := point.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal verification share for %s: %w", id, err)
		}
		shares = append(shares, taprootVerificationShareMarshal{
			ID:    id,
			Point: pointBytes,
		})
	}

	cm := &taprootConfigMarshal{
		ID:                 config.ID,
		Threshold:          config.Threshold,
		PrivateShare:       privateShareBytes,
		PublicKey:          config.PublicKey,
		ChainKey:           config.ChainKey,
		VerificationShares: shares,
	}

	return cbor.Marshal(cm)
}

// ============================================================================
// secp256k1 curve helpers for ecdsa.PublicKey conversion
// ============================================================================

var secp256k1CurveParams *elliptic.CurveParams

func init() {
	secp256k1CurveParams = &elliptic.CurveParams{
		Name:    "secp256k1",
		BitSize: 256,
	}
	secp256k1CurveParams.P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	secp256k1CurveParams.N, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	secp256k1CurveParams.B = big.NewInt(7)
	secp256k1CurveParams.Gx, _ = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	secp256k1CurveParams.Gy, _ = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
}

func ellipticSecp256k1() elliptic.Curve {
	return secp256k1CurveParams
}

// xOnlyToECDSA converts a 32-byte x-only public key (BIP-340) to ecdsa.PublicKey with even Y.
func xOnlyToECDSA(xBytes []byte) *ecdsa.PublicKey {
	x := new(big.Int).SetBytes(xBytes)
	p := secp256k1CurveParams.P

	// y^2 = x^3 + 7 mod p
	x3 := new(big.Int).Mul(x, x)
	x3.Mod(x3, p)
	x3.Mul(x3, x)
	x3.Mod(x3, p)
	y2 := new(big.Int).Add(x3, big.NewInt(7))
	y2.Mod(y2, p)

	exp := new(big.Int).Add(p, big.NewInt(1))
	exp.Rsh(exp, 2)
	y := new(big.Int).Exp(y2, exp, p)

	check := new(big.Int).Mul(y, y)
	check.Mod(check, p)
	if check.Cmp(y2) != 0 {
		return nil
	}

	// BIP-340 uses even Y
	if y.Bit(0) != 0 {
		y.Sub(p, y)
	}

	return &ecdsa.PublicKey{Curve: ellipticSecp256k1(), X: x, Y: y}
}

// compressedToECDSA converts a 33-byte compressed secp256k1 point to ecdsa.PublicKey.
func compressedToECDSA(compressed []byte) *ecdsa.PublicKey {
	if len(compressed) != 33 {
		return nil
	}
	x := new(big.Int).SetBytes(compressed[1:33])
	p := secp256k1CurveParams.P

	x3 := new(big.Int).Mul(x, x)
	x3.Mod(x3, p)
	x3.Mul(x3, x)
	x3.Mod(x3, p)
	y2 := new(big.Int).Add(x3, big.NewInt(7))
	y2.Mod(y2, p)

	exp := new(big.Int).Add(p, big.NewInt(1))
	exp.Rsh(exp, 2)
	y := new(big.Int).Exp(y2, exp, p)

	check := new(big.Int).Mul(y, y)
	check.Mod(check, p)
	if check.Cmp(y2) != 0 {
		return nil
	}

	isOdd := compressed[0] == 0x03
	if y.Bit(0) == 1 != isOdd {
		y.Sub(p, y)
	}

	return &ecdsa.PublicKey{Curve: ellipticSecp256k1(), X: x, Y: y}
}
