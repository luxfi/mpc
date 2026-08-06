package mpc

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/frost"
	"github.com/stretchr/testify/require"
)

// These tests construct the production signing session itself, rather than a
// mirror of it.
//
// That distinction is the whole point. A test that calls frost.SignEd25519
// directly proves the library is correct; it proves nothing about what the
// daemon hands the library. The original bug survived its tests precisely
// because the tests and the code agreed on the word "EdDSA" and disagreed about
// everything underneath it.

// newTestEd25519Session runs a real ceremony, stores a real share, and builds
// the real session over it. pubSub, keyinfo, resultQueue and identity are nil:
// newFROSTSigningSession only reads the kvstore and prepares state, so nil is
// enough to exercise everything that happens before the protocol starts — which
// is where message handling is decided.
func newTestEd25519Session(t *testing.T, message []byte) (*frostSigningSession, *frost.Config) {
	t.Helper()

	const (
		orgID    = "org1"
		walletID = "wallet1"
	)
	ids := ceremonyParties()

	raw := runCeremony(t, ids, []byte("signing-session"), func(id party.ID) protocol.StartFunc {
		return ed25519KeygenStart(id, ids, 1)
	})
	cfg, ok := raw[ids[0]].(*frost.Config)
	require.True(t, ok, "keygen must produce *frost.Config, got %T", raw[ids[0]])

	store := mapKVStore{}
	shareBytes, err := MarshalEd25519Config(cfg)
	require.NoError(t, err)
	require.NoError(t, store.Put(OrgScopedKey(orgID, Ed25519ShareKey(walletID)), shareBytes))

	session, err := newFROSTSigningSession(
		"session1", walletID, message,
		nil, // pubSub
		ids[0], ids[:2],
		store,
		nil,   // keyinfoStore
		nil,   // resultQueue
		nil,   // identityStore
		false, // useBroadcast
		orgID,
	)
	require.NoError(t, err, "the session must load the share keygen wrote")
	return session, cfg
}

// TestSigningSessionDoesNotHashTheMessage is the regression guard for the
// pre-hash bug.
//
// The session used to SHA-256 any message that was not already 32 bytes, because
// BIP-340 requires a 32-byte digest. PureEdDSA does not: it hashes the message
// inside the challenge, so hashing here signs a digest of a digest and every
// chain rejects the result. The session must carry the caller's bytes through
// untouched, whatever their length.
func TestSigningSessionDoesNotHashTheMessage(t *testing.T) {
	for name, message := range map[string][]byte{
		"solana_sized_512_bytes": bytes.Repeat([]byte{0xAB}, 512),
		"short_11_bytes":         []byte("hello world"),
		"ton_cell_hash_32_bytes": func() []byte { h := sha256.Sum256([]byte("cell")); return h[:] }(),
		"one_byte":               {0x01},
		"empty":                  {},
	} {
		t.Run(name, func(t *testing.T) {
			session, _ := newTestEd25519Session(t, message)

			require.Equal(t, message, session.message,
				"the session must sign the caller's bytes, not a digest of them")

			// Explicitly rule out the exact transformation that used to happen,
			// so this fails loudly rather than subtly if it comes back.
			if len(message) != 32 {
				digest := sha256.Sum256(message)
				require.NotEqual(t, digest[:], session.message,
					"the session re-introduced the SHA-256 pre-hash")
			}
		})
	}
}

// TestSigningSessionLoadsTheEd25519Share pins the seam between the two halves:
// the session must read the share at the key keygen wrote, and must reconstruct
// the same wallet key. A mismatch here is an address that can receive and never
// spend.
func TestSigningSessionLoadsTheEd25519Share(t *testing.T) {
	message := []byte("a message of no particular length")
	session, original := newTestEd25519Session(t, message)

	require.NotNil(t, session.config, "the session must have loaded a config")

	loaded, err := session.config.PublicKey.MarshalBinary()
	require.NoError(t, err)
	expected, err := original.PublicKey.MarshalBinary()
	require.NoError(t, err)

	require.Equal(t, expected, loaded,
		"the signing session must reconstruct the wallet key keygen published")
	require.Equal(t, original.Threshold, session.config.Threshold)
}

// TestSigningSessionRefusesAMissingShare confirms the session fails closed when
// no Ed25519 share exists — the normal case for a wallet whose Ed25519 keygen
// leg failed. It must error rather than construct a session that would later
// sign with something else.
func TestSigningSessionRefusesAMissingShare(t *testing.T) {
	ids := ceremonyParties()

	_, err := newFROSTSigningSession(
		"session1", "no-such-wallet", []byte("msg"),
		nil, ids[0], ids[:2],
		mapKVStore{},
		nil, nil, nil, false, "org1",
	)
	require.Error(t, err, "a wallet with no Ed25519 share must not yield a signing session")
}

// TestSigningSessionRefusesAForeignShare confirms the curve boundary holds at
// load time: a share written by another curve's ceremony must not load, so it
// can never reach frost.SignEd25519.
func TestSigningSessionRefusesAForeignShare(t *testing.T) {
	const (
		orgID    = "org1"
		walletID = "wallet1"
	)
	ids := ceremonyParties()

	raw := runCeremony(t, ids, []byte("foreign-signing"), func(id party.ID) protocol.StartFunc {
		return frost.KeygenSR25519(id, ids, 1)
	})
	sr, ok := raw[ids[0]].(*frost.Config)
	require.True(t, ok)

	blob, err := MarshalSR25519Config(sr)
	require.NoError(t, err)

	store := mapKVStore{}
	require.NoError(t, store.Put(OrgScopedKey(orgID, Ed25519ShareKey(walletID)), blob))

	_, err = newFROSTSigningSession(
		"session1", walletID, []byte("msg"),
		nil, ids[0], ids[:2],
		store,
		nil, nil, nil, false, orgID,
	)
	require.Error(t, err, "a Ristretto255 share must not load into the Ed25519 signer")
}
