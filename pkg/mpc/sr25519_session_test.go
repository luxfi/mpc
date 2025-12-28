package mpc

import (
	"testing"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/frost"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRistretto255CurveInterface(t *testing.T) {
	group := Ristretto255{}

	// Verify interface satisfaction
	var _ curve.Curve = group
	var _ curve.Scalar = group.NewScalar()
	var _ curve.Point = group.NewPoint()

	assert.Equal(t, "ristretto255", group.Name())
	assert.Equal(t, 253, group.ScalarBits())
	assert.Equal(t, 32, group.SafeScalarBytes())
	assert.NotNil(t, group.Order())
}

func TestRistretto255ScalarRoundtrip(t *testing.T) {
	group := Ristretto255{}

	// Create a non-zero scalar: base point scalar mult then extract
	s := group.NewScalar()
	require.NotNil(t, s)

	// Marshal zero scalar
	data, err := s.MarshalBinary()
	require.NoError(t, err)
	assert.Len(t, data, 32)

	// Unmarshal should roundtrip
	s2 := group.NewScalar()
	err = s2.UnmarshalBinary(data)
	require.NoError(t, err)
	assert.True(t, s.Equal(s2))
}

func TestRistretto255PointRoundtrip(t *testing.T) {
	group := Ristretto255{}

	// Test identity point
	identity := group.NewPoint()
	data, err := identity.MarshalBinary()
	require.NoError(t, err)
	assert.Len(t, data, 32)

	identity2 := group.NewPoint()
	err = identity2.UnmarshalBinary(data)
	require.NoError(t, err)
	assert.True(t, identity.Equal(identity2))

	// Test base point
	base := group.NewBasePoint()
	data, err = base.MarshalBinary()
	require.NoError(t, err)
	assert.Len(t, data, 32)

	base2 := group.NewPoint()
	err = base2.UnmarshalBinary(data)
	require.NoError(t, err)
	assert.True(t, base.Equal(base2))

	// Base point should not be identity
	assert.False(t, base.Equal(identity))
}

func TestRistretto255ScalarArithmetic(t *testing.T) {
	group := Ristretto255{}

	// Test non-zero base point
	base := group.NewBasePoint()
	assert.False(t, base.IsIdentity())

	// Test that identity is identity
	identity := group.NewPoint()
	assert.True(t, identity.IsIdentity())

	// Test scalar operations don't panic
	s1 := group.NewScalar()
	s2 := group.NewScalar()
	s1.Add(s2)
	assert.True(t, s1.IsZero())
}

func TestRistretto255PointArithmetic(t *testing.T) {
	group := Ristretto255{}

	base := group.NewBasePoint()
	negBase := base.Negate()

	// base + (-base) = identity
	sum := base.Add(negBase)
	assert.True(t, sum.IsIdentity())

	// base - base = identity
	diff := group.NewBasePoint().Sub(group.NewBasePoint())
	assert.True(t, diff.IsIdentity())
}

func TestRistretto255XScalarReturnsNil(t *testing.T) {
	group := Ristretto255{}
	base := group.NewBasePoint()
	// ristretto255 is not an ECDSA curve, so XScalar should return nil
	assert.Nil(t, base.XScalar())
}

func TestSR25519ConfigMarshalRoundtrip(t *testing.T) {
	group := Ristretto255{}

	// Create a minimal FROST Config with Ristretto255 types
	privateShare := group.NewScalar()
	publicKey := group.NewBasePoint()

	partyA := party.ID("node-a")
	partyB := party.ID("node-b")
	partyC := party.ID("node-c")

	verificationShares := map[party.ID]curve.Point{
		partyA: group.NewBasePoint(),
		partyB: group.NewBasePoint(),
		partyC: group.NewBasePoint(),
	}

	config := &frost.Config{
		ID:                 partyA,
		Threshold:          1,
		PrivateShare:       privateShare,
		PublicKey:          publicKey,
		ChainKey:           make([]byte, 32),
		VerificationShares: party.NewPointMap(verificationShares),
	}

	// Marshal
	data, err := MarshalSR25519Config(config)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Unmarshal
	config2, err := UnmarshalSR25519Config(data)
	require.NoError(t, err)
	require.NotNil(t, config2)

	// Verify roundtrip
	assert.Equal(t, config.ID, config2.ID)
	assert.Equal(t, config.Threshold, config2.Threshold)
	assert.True(t, config.PrivateShare.Equal(config2.PrivateShare))
	assert.True(t, config.PublicKey.Equal(config2.PublicKey))
	assert.Equal(t, config.ChainKey, config2.ChainKey)

	// Verify verification shares
	for id, point := range config.VerificationShares.Points {
		point2, ok := config2.VerificationShares.Points[id]
		require.True(t, ok, "missing verification share for %s", id)
		assert.True(t, point.Equal(point2), "verification share mismatch for %s", id)
	}
}

func TestSR25519ConfigMarshalNilConfig(t *testing.T) {
	_, err := MarshalSR25519Config(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "config is nil")
}

func TestSR25519ConfigUnmarshalInvalidData(t *testing.T) {
	_, err := UnmarshalSR25519Config([]byte("invalid cbor data"))
	assert.Error(t, err)
}

func TestSR25519SessionCreation(t *testing.T) {
	// Test that the session constructor creates a valid session struct
	walletID := "test-wallet-sr25519"
	partyIDs := []party.ID{"node-a", "node-b", "node-c"}
	selfPartyID := party.ID("node-a")

	session := newSR25519KeygenSession(
		walletID,
		nil, // pubSub - nil for unit test
		selfPartyID,
		partyIDs,
		1, // threshold
		nil, // kvstore
		nil, // keyinfoStore
		nil, // resultQueue
		nil, // identityStore
	)

	require.NotNil(t, session)
	assert.Equal(t, walletID, session.walletID)
	assert.Equal(t, selfPartyID, session.selfPartyID)
	assert.Equal(t, 1, session.threshold)
	assert.Equal(t, 3, session.rounds)
	assert.False(t, session.done)
	assert.Nil(t, session.config)
	assert.Nil(t, session.resultErr)
}

func TestPrepareSigningMessage(t *testing.T) {
	msg := []byte("hello world")

	// Default substrate context
	result := prepareSigningMessage("substrate", msg)
	assert.Equal(t, append([]byte("substrate"), msg...), result)

	// Empty context
	result = prepareSigningMessage("", msg)
	assert.Equal(t, msg, result)

	// Custom context
	result = prepareSigningMessage("polkadot", msg)
	assert.Equal(t, append([]byte("polkadot"), msg...), result)
}

func TestDefaultSigningContext(t *testing.T) {
	assert.Equal(t, "substrate", DefaultSigningContext)
}

func TestKeyTypeSR25519Constant(t *testing.T) {
	assert.Equal(t, KeyType("sr25519"), KeyTypeSR25519)
}

func TestSessionTypeSR25519Constant(t *testing.T) {
	assert.Equal(t, SessionType("sr25519"), SessionTypeSR25519)
}
