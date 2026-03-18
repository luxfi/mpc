package mpc

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/frost"
)

// sr25519ConfigMarshal is the CBOR-friendly representation of a FROST Config
// using the Ristretto255 curve (sr25519).
type sr25519ConfigMarshal struct {
	ID                 party.ID
	Threshold          int
	PrivateShare       []byte // 32 bytes (Ristretto255Scalar)
	PublicKey          []byte // 32 bytes (Ristretto255Point)
	ChainKey           []byte // 32 bytes
	VerificationShares []sr25519VerificationShareMarshal
}

type sr25519VerificationShareMarshal struct {
	ID    party.ID
	Point []byte // 32 bytes (Ristretto255Point)
}

// MarshalSR25519Config serializes a FROST Config (Ristretto255) to CBOR bytes.
// MUST use CBOR: Ristretto255 crypto types do not have JSON marshalers.
func MarshalSR25519Config(config *frost.Config) ([]byte, error) {
	if config == nil {
		return nil, fmt.Errorf("config is nil")
	}

	// Marshal private share (Ristretto255Scalar)
	privateShareBytes, err := config.PrivateShare.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private share: %w", err)
	}

	// Marshal public key (Ristretto255Point)
	publicKeyBytes, err := config.PublicKey.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	// Marshal verification shares
	shares := make([]sr25519VerificationShareMarshal, 0, len(config.VerificationShares.Points))
	for id, point := range config.VerificationShares.Points {
		pointBytes, err := point.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal verification share for %s: %w", id, err)
		}
		shares = append(shares, sr25519VerificationShareMarshal{
			ID:    id,
			Point: pointBytes,
		})
	}

	cm := &sr25519ConfigMarshal{
		ID:                 config.ID,
		Threshold:          config.Threshold,
		PrivateShare:       privateShareBytes,
		PublicKey:          publicKeyBytes,
		ChainKey:           config.ChainKey,
		VerificationShares: shares,
	}

	return cbor.Marshal(cm)
}

// UnmarshalSR25519Config deserializes CBOR bytes to a FROST Config (Ristretto255).
func UnmarshalSR25519Config(data []byte) (*frost.Config, error) {
	cm := &sr25519ConfigMarshal{}
	if err := cbor.Unmarshal(data, cm); err != nil {
		return nil, fmt.Errorf("failed to unmarshal SR25519 config: %w", err)
	}

	// Use local Ristretto255 curve type (same package)
	group := Ristretto255{}

	// Unmarshal private share
	privateShare := group.NewScalar()
	if err := privateShare.UnmarshalBinary(cm.PrivateShare); err != nil {
		return nil, fmt.Errorf("failed to unmarshal private share: %w", err)
	}

	// Unmarshal public key
	publicKey := group.NewPoint()
	if err := publicKey.UnmarshalBinary(cm.PublicKey); err != nil {
		return nil, fmt.Errorf("failed to unmarshal public key: %w", err)
	}

	// Unmarshal verification shares
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
