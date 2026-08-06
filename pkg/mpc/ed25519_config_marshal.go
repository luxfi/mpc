package mpc

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/frost"
)

// Ed25519ShareKey is the kvstore key holding a wallet's Ed25519 FROST share.
//
// Keygen writes it and signing reads it, so it is defined once: two spellings of
// this prefix would mean a wallet whose key exists but cannot be found, which
// presents as an address that takes deposits and never signs.
//
// The prefix is "ed25519:" rather than "frost:" because FROST is a scheme
// family, not a group. Shares written under the old "frost:" prefix were BIP-340
// over secp256k1 and can never satisfy an Ed25519 verifier, so leaving them
// unreachable is the intent, not a migration gap.
func Ed25519ShareKey(walletID string) string {
	return fmt.Sprintf("ed25519:%s", walletID)
}

// ed25519ConfigMarshal is the CBOR-friendly representation of a FROST Config
// over edwards25519. Every field is a fixed-width encoding of a crypto type,
// which is why this cannot be JSON: the curve types have no JSON marshalers and
// silently round-trip to nothing.
type ed25519ConfigMarshal struct {
	ID                 party.ID
	Threshold          int
	PrivateShare       []byte // 32 bytes (Ed25519Scalar)
	PublicKey          []byte // 32 bytes (Ed25519Point, RFC 8032 encoding)
	ChainKey           []byte // 32 bytes
	VerificationShares []ed25519VerificationShareMarshal
}

type ed25519VerificationShareMarshal struct {
	ID    party.ID
	Point []byte // 32 bytes (Ed25519Point)
}

// MarshalEd25519Config serializes a FROST Config over edwards25519 to CBOR.
func MarshalEd25519Config(config *frost.Config) ([]byte, error) {
	if config == nil {
		return nil, fmt.Errorf("config is nil")
	}

	privateShareBytes, err := config.PrivateShare.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private share: %w", err)
	}

	publicKeyBytes, err := config.PublicKey.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	shares := make([]ed25519VerificationShareMarshal, 0, len(config.VerificationShares.Points))
	for id, point := range config.VerificationShares.Points {
		pointBytes, err := point.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal verification share for %s: %w", id, err)
		}
		shares = append(shares, ed25519VerificationShareMarshal{
			ID:    id,
			Point: pointBytes,
		})
	}

	cm := &ed25519ConfigMarshal{
		ID:                 config.ID,
		Threshold:          config.Threshold,
		PrivateShare:       privateShareBytes,
		PublicKey:          publicKeyBytes,
		ChainKey:           config.ChainKey,
		VerificationShares: shares,
	}

	return cbor.Marshal(cm)
}

// UnmarshalEd25519Config deserializes CBOR bytes to a FROST Config over
// edwards25519.
//
// Every point goes through curve.Ed25519's decoder, which rejects anything that
// is not a canonical point in the prime-order subgroup, so this is a curve check
// and not merely a parse.
//
// It is not a proof of provenance, and should not be described as one. A point
// from another curve can coincidentally be a valid edwards25519 point — for a
// 32-byte encoding that happens about one time in sixteen — so a foreign share
// is rejected with overwhelming but not certain probability. What actually keeps
// a wrong-curve share out is that only the Ed25519 ceremony ever writes to this
// key, and the ceremony is pinned by type, not by inspection.
func UnmarshalEd25519Config(data []byte) (*frost.Config, error) {
	cm := &ed25519ConfigMarshal{}
	if err := cbor.Unmarshal(data, cm); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Ed25519 config: %w", err)
	}

	group := curve.Ed25519{}

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
