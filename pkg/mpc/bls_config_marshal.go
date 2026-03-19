package mpc

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/threshold/pkg/party"
	blsThreshold "github.com/luxfi/threshold/protocols/bls"
)

// blsConfigMarshal is the CBOR-friendly representation of a BLS threshold Config.
// MUST use CBOR: bls.PublicKey and bls.SecretKey do not have JSON marshalers.
type blsConfigMarshal struct {
	ID               party.ID
	Threshold        int
	TotalParties     int
	PublicKey        []byte // 48 bytes (compressed G1 point)
	SecretShare      []byte // 32 bytes (BLS secret key)
	VerificationKeys []blsVerificationKeyMarshal
}

type blsVerificationKeyMarshal struct {
	ID  party.ID
	Key []byte // 48 bytes (compressed G1 point)
}

// MarshalBLSConfig serializes a BLS threshold Config to CBOR bytes.
func MarshalBLSConfig(config *blsThreshold.Config) ([]byte, error) {
	if config == nil {
		return nil, fmt.Errorf("config is nil")
	}

	// Marshal public key
	pkBytes := bls.PublicKeyToCompressedBytes(config.PublicKey)
	if pkBytes == nil {
		return nil, fmt.Errorf("failed to marshal public key")
	}

	// Marshal secret share
	skBytes := bls.SecretKeyToBytes(config.SecretShare)
	if skBytes == nil {
		return nil, fmt.Errorf("failed to marshal secret share")
	}

	// Marshal verification keys
	vks := make([]blsVerificationKeyMarshal, 0, len(config.VerificationKeys))
	for id, pk := range config.VerificationKeys {
		vkBytes := bls.PublicKeyToCompressedBytes(pk)
		if vkBytes == nil {
			return nil, fmt.Errorf("failed to marshal verification key for %s", id)
		}
		vks = append(vks, blsVerificationKeyMarshal{
			ID:  id,
			Key: vkBytes,
		})
	}

	cm := &blsConfigMarshal{
		ID:               config.ID,
		Threshold:        config.Threshold,
		TotalParties:     config.TotalParties,
		PublicKey:        pkBytes,
		SecretShare:      skBytes,
		VerificationKeys: vks,
	}

	return cbor.Marshal(cm)
}

// UnmarshalBLSConfig deserializes CBOR bytes to a BLS threshold Config.
func UnmarshalBLSConfig(data []byte) (*blsThreshold.Config, error) {
	cm := &blsConfigMarshal{}
	if err := cbor.Unmarshal(data, cm); err != nil {
		return nil, fmt.Errorf("failed to unmarshal BLS config: %w", err)
	}

	// Unmarshal public key
	pk, err := bls.PublicKeyFromCompressedBytes(cm.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal public key: %w", err)
	}

	// Unmarshal secret share
	sk, err := bls.SecretKeyFromBytes(cm.SecretShare)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal secret share: %w", err)
	}

	// Unmarshal verification keys
	vks := make(map[party.ID]*bls.PublicKey, len(cm.VerificationKeys))
	for _, vk := range cm.VerificationKeys {
		key, err := bls.PublicKeyFromCompressedBytes(vk.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal verification key for %s: %w", vk.ID, err)
		}
		vks[vk.ID] = key
	}

	return &blsThreshold.Config{
		ID:               cm.ID,
		Threshold:        cm.Threshold,
		TotalParties:     cm.TotalParties,
		PublicKey:        pk,
		SecretShare:      sk,
		VerificationKeys: vks,
	}, nil
}
