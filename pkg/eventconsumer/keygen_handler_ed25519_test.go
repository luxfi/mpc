package eventconsumer

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/stretchr/testify/require"

	"github.com/luxfi/mpc/pkg/event"
)

// assertKeygenResultConsistent is the last gate before a wallet is announced.
// These tests pin the two states it must allow and the one it must not.

// TestKeygenResultAllowsAbsentEd25519Key is the fail-closed case. A wallet whose
// Ed25519 leg failed is a good wallet with no Solana address, and publishing it
// must not be blocked — otherwise a Solana outage would stop EVM wallets from
// being minted.
func TestKeygenResultAllowsAbsentEd25519Key(t *testing.T) {
	for name, result := range map[string]*event.KeygenResultEvent{
		"nil_eddsa_key":   {WalletID: "w1", EDDSAPubKey: nil},
		"empty_eddsa_key": {WalletID: "w2", EDDSAPubKey: []byte{}},
	} {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, assertKeygenResultConsistent(result))
		})
	}
}

// TestKeygenResultAllowsRealEd25519Key checks the gate does not reject the keys
// it exists to protect.
func TestKeygenResultAllowsRealEd25519Key(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	require.NoError(t, assertKeygenResultConsistent(&event.KeygenResultEvent{
		WalletID:    "w3",
		EDDSAPubKey: pub,
	}))
}

// TestKeygenResultRejectsWrongCurveKey is the guard: if an EdDSA key is present
// at all, it must be a real Ed25519 key. A secp256k1 x-only key is 32 bytes and
// would otherwise sail through to become a Solana address.
func TestKeygenResultRejectsWrongCurveKey(t *testing.T) {
	tested := 0
	for attempt := 0; attempt < 512 && tested < 16; attempt++ {
		candidate := make([]byte, 32)
		_, err := rand.Read(candidate)
		require.NoError(t, err)

		if _, err := (curve.Secp256k1{}).LiftX(candidate); err != nil {
			continue
		}
		if err := (curve.Ed25519{}).NewPoint().UnmarshalBinary(candidate); err == nil {
			continue
		}
		tested++

		require.Error(t, assertKeygenResultConsistent(&event.KeygenResultEvent{
			WalletID:    "w4",
			EDDSAPubKey: candidate,
		}), "a secp256k1 key must never be publishable as an EdDSA key: %x", candidate)
	}
	require.GreaterOrEqual(t, tested, 16, "did not find enough secp256k1-only keys to test")
}

// TestKeygenResultRejectsTruncatedKey covers corruption in transit or storage:
// anything that is not exactly a valid key must stop here rather than become an
// address.
func TestKeygenResultRejectsTruncatedKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	require.Error(t, assertKeygenResultConsistent(&event.KeygenResultEvent{
		WalletID:    "w5",
		EDDSAPubKey: pub[:31],
	}))
}
