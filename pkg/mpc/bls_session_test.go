package mpc

import (
	"context"
	"testing"

	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/threshold/pkg/party"
	blsThreshold "github.com/luxfi/threshold/protocols/bls"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyTypeBLSConstant(t *testing.T) {
	assert.Equal(t, KeyType("bls"), KeyTypeBLS)
}

func TestSessionTypeBLSConstant(t *testing.T) {
	assert.Equal(t, SessionType("bls"), SessionTypeBLS)
}

func TestBLSConfigMarshalRoundtrip(t *testing.T) {
	ctx := context.Background()

	partyA := party.ID("node-a")
	partyB := party.ID("node-b")
	partyC := party.ID("node-c")
	parties := []party.ID{partyA, partyB, partyC}

	// Generate real BLS threshold shares
	dealer := &blsThreshold.TrustedDealer{
		Threshold:    2,
		TotalParties: 3,
	}

	shares, groupPK, err := dealer.GenerateShares(ctx, parties)
	require.NoError(t, err)
	require.NotNil(t, groupPK)

	vks := blsThreshold.GetVerificationKeys(shares)

	// Create config for party A
	config := blsThreshold.NewConfig(partyA, 2, 3, shares[partyA], groupPK, vks)
	require.NotNil(t, config)

	// Marshal
	data, err := MarshalBLSConfig(config)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Unmarshal
	config2, err := UnmarshalBLSConfig(data)
	require.NoError(t, err)
	require.NotNil(t, config2)

	// Verify roundtrip
	assert.Equal(t, config.ID, config2.ID)
	assert.Equal(t, config.Threshold, config2.Threshold)
	assert.Equal(t, config.TotalParties, config2.TotalParties)

	// Verify public key roundtrip
	pkBytes1 := bls.PublicKeyToCompressedBytes(config.PublicKey)
	pkBytes2 := bls.PublicKeyToCompressedBytes(config2.PublicKey)
	assert.Equal(t, pkBytes1, pkBytes2)

	// Verify secret share roundtrip
	skBytes1 := bls.SecretKeyToBytes(config.SecretShare)
	skBytes2 := bls.SecretKeyToBytes(config2.SecretShare)
	assert.Equal(t, skBytes1, skBytes2)

	// Verify verification keys roundtrip
	for id, vk := range config.VerificationKeys {
		vk2, ok := config2.VerificationKeys[id]
		require.True(t, ok, "missing verification key for %s", id)
		vkBytes1 := bls.PublicKeyToCompressedBytes(vk)
		vkBytes2 := bls.PublicKeyToCompressedBytes(vk2)
		assert.Equal(t, vkBytes1, vkBytes2, "verification key mismatch for %s", id)
	}
}

func TestBLSConfigMarshalNilConfig(t *testing.T) {
	_, err := MarshalBLSConfig(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "config is nil")
}

func TestBLSConfigUnmarshalInvalidData(t *testing.T) {
	_, err := UnmarshalBLSConfig([]byte("invalid cbor data"))
	assert.Error(t, err)
}

func TestBLSSignAndVerifyWithMarshaledConfig(t *testing.T) {
	ctx := context.Background()

	parties := []party.ID{
		party.ID("party1"),
		party.ID("party2"),
		party.ID("party3"),
	}

	// Generate threshold shares
	dealer := &blsThreshold.TrustedDealer{
		Threshold:    2,
		TotalParties: 3,
	}

	shares, groupPK, err := dealer.GenerateShares(ctx, parties)
	require.NoError(t, err)

	vks := blsThreshold.GetVerificationKeys(shares)

	// Create configs, marshal/unmarshal each one (simulating storage roundtrip)
	configs := make(map[party.ID]*blsThreshold.Config, 3)
	for _, id := range parties {
		original := blsThreshold.NewConfig(id, 2, 3, shares[id], groupPK, vks)

		// Marshal and unmarshal to simulate BadgerDB storage
		data, err := MarshalBLSConfig(original)
		require.NoError(t, err)

		restored, err := UnmarshalBLSConfig(data)
		require.NoError(t, err)

		configs[id] = restored
	}

	// Sign with each party
	message := []byte("threshold BLS signing test via CBOR roundtrip")
	sigShares := make([]*blsThreshold.SignatureShare, 0, 3)
	for _, id := range parties {
		share, err := configs[id].Sign(message)
		require.NoError(t, err, "party %s signing failed", id)
		require.NotNil(t, share.Signature)
		sigShares = append(sigShares, share)
	}

	// Verify partial signatures
	for _, share := range sigShares {
		valid := configs[parties[0]].VerifyPartialSignature(share, message)
		require.True(t, valid, "partial signature from %s should be valid", share.PartyID)
	}

	// Aggregate with threshold (2 of 3)
	aggSig, err := blsThreshold.AggregateSignatures(sigShares[:2], 2)
	require.NoError(t, err)
	require.NotNil(t, aggSig)

	// Verify aggregate signature
	valid := configs[parties[0]].VerifyAggregateSignature(message, aggSig)
	require.True(t, valid, "aggregate signature should verify against group key")

	// Wrong message should fail
	require.False(t, configs[parties[0]].VerifyAggregateSignature([]byte("wrong message"), aggSig))
}

func TestBLSKeygenSessionCreation(t *testing.T) {
	walletID := "test-wallet-bls"
	partyIDs := []party.ID{"node-a", "node-b", "node-c"}
	selfPartyID := party.ID("node-a")

	session := newBLSKeygenSession(
		walletID,
		nil, // pubSub - nil for unit test
		selfPartyID,
		partyIDs,
		2,   // threshold
		nil, // kvstore
		nil, // keyinfoStore
		nil, // resultQueue
		nil, // identityStore
	)

	require.NotNil(t, session)
	assert.Equal(t, walletID, session.walletID)
	assert.Equal(t, selfPartyID, session.selfPartyID)
	assert.Equal(t, 2, session.threshold)
	assert.Equal(t, 1, session.rounds) // BLS keygen is single-round
	assert.False(t, session.done)
	assert.Nil(t, session.config)
	assert.Nil(t, session.resultErr)
}

func TestBLSKeygenSessionIsDealer(t *testing.T) {
	partyIDs := []party.ID{"node-c", "node-a", "node-b"}

	// node-a is the smallest sorted, so it should be the dealer
	sessionA := newBLSKeygenSession(
		"wallet1",
		nil,
		party.ID("node-a"),
		partyIDs,
		2,
		nil, nil, nil, nil,
	)
	assert.True(t, sessionA.isDealer())

	// node-b is not the smallest
	sessionB := newBLSKeygenSession(
		"wallet1",
		nil,
		party.ID("node-b"),
		partyIDs,
		2,
		nil, nil, nil, nil,
	)
	assert.False(t, sessionB.isDealer())

	// node-c is not the smallest
	sessionC := newBLSKeygenSession(
		"wallet1",
		nil,
		party.ID("node-c"),
		partyIDs,
		2,
		nil, nil, nil, nil,
	)
	assert.False(t, sessionC.isDealer())
}
