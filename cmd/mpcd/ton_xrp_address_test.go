package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/stretchr/testify/require"

	"github.com/luxfi/mpc/pkg/types"
)

// These tests sit at the daemon's own boundary, like sol_address_test.go:
// eddsaPubKeyToTonAddress and ecdsaPubKeyToXrpAddress are the functions whose
// return values become the ton_address and xrp_address fields of a /keygen
// response — the strings a customer is told to deposit into.
//
// The vectors are the published ones pinned in pkg/address: a live TON mainnet
// v4R2 account, and XRPLF/xrpl.js's own secp256k1 fixture. They are repeated
// here rather than imported so this layer is checked end to end against
// published truth, not against the layer below it.

const (
	// TON mainnet account 0:e7045e09…38cf, code_hash feb5ff68… (wallet v4R2),
	// get_public_key → 0x5754865e…c522. Same account @ton/ton asserts in
	// src/wallets/v4/WalletContractV4.spec.ts.
	tonVectorPubKey = "5754865e86d0ade1199301bbb0319a25ed6b129c4b0a57f28f62449b3df9c522"
	// Non-bounceable rendering, which is what a deposit address must be.
	tonVectorAddress = "UQDnBF4JTFKHTYjulEJyNd4dstLGH1m51UrLdu01_tw4zz3r"

	// XRPLF/xrpl.js packages/ripple-keypairs/test/fixtures/api.json → .secp256k1
	xrpVectorPubKey  = "030D58EB48B4420B1F7B9DF55087E0E29FEF0E8468F9A6825B01CA2C361042D435"
	xrpVectorAddress = "rU6K7V3Po4snVhBBaU29sesqs2qTQJWDw1"
)

func TestTonAddressMatchesPublishedMainnetVector(t *testing.T) {
	pub, err := hex.DecodeString(tonVectorPubKey)
	require.NoError(t, err)
	require.Equal(t, tonVectorAddress, eddsaPubKeyToTonAddress(pub))
}

func TestXrpAddressMatchesPublishedVector(t *testing.T) {
	pub, err := hex.DecodeString(xrpVectorPubKey)
	require.NoError(t, err)
	require.Equal(t, xrpVectorAddress, ecdsaPubKeyToXrpAddress(pub))
}

// TestTonAddressRefusesSecp256k1Keys is the same regression guard
// sol_address_test.go applies, for the same reason: TON spends with an Ed25519
// signature, so an x-only secp256k1 key rendered as a TON address would be
// fundable and permanently unspendable.
func TestTonAddressRefusesSecp256k1Keys(t *testing.T) {
	tested := 0
	for attempt := 0; attempt < 512 && tested < 32; attempt++ {
		candidate := make([]byte, 32)
		_, err := rand.Read(candidate)
		require.NoError(t, err)

		if _, err := (curve.Secp256k1{}).LiftX(candidate); err != nil {
			continue
		}
		// Skip the ~1-in-16 that are also valid Ed25519 keys; those are
		// indistinguishable by inspection, which is why provenance and not
		// validation is the primary defence upstream.
		if err := (curve.Ed25519{}).NewPoint().UnmarshalBinary(candidate); err == nil {
			continue
		}
		tested++
		require.Empty(t, eddsaPubKeyToTonAddress(candidate),
			"a secp256k1 x-only key must never produce a TON address")
	}
	require.Positive(t, tested, "no secp256k1 x-only candidates were generated")
}

// TestXrpAddressRefusesWrongCurveAndAmbiguousKeys covers the inputs that must
// produce no field at all. The 32-byte case matters most: it is a real
// secp256k1 x-coordinate with the y parity missing, and completing it by
// assuming even-y — which pubKeyToBtcAddress does — names the sibling point's
// address for half of all keys.
func TestXrpAddressRefusesWrongCurveAndAmbiguousKeys(t *testing.T) {
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	priv, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	compressed := priv.PubKey().SerializeCompressed()

	for name, key := range map[string][]byte{
		"empty":                    {},
		"ed25519_key":              edPub,
		"x_only_missing_parity":    compressed[1:],
		"truncated":                compressed[:32],
		"trailing_byte":            append(append([]byte{}, compressed...), 0x00),
		"ed25519_with_0xED_prefix": append([]byte{0xED}, edPub...),
	} {
		t.Run(name, func(t *testing.T) {
			require.Empty(t, ecdsaPubKeyToXrpAddress(key),
				"a key this function cannot verify must yield no xrp_address")
		})
	}
}

// TestAddressCurveMatchesSigningCurve binds the two halves that have to agree.
// pkg/types.networkKeyType decides which curve a network's signatures come
// from; the keygen response decides which key an address is derived from. If
// those ever disagree the daemon publishes an address it cannot sign for, so
// the agreement is asserted rather than assumed.
func TestAddressCurveMatchesSigningCurve(t *testing.T) {
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	priv, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	secpPub := priv.PubKey().SerializeCompressed()

	// "ton" and "xrp" are the names a /sign caller actually sends, so resolve
	// them the way that path does rather than assuming the canonical code.
	tonNet, err := types.ParseNetwork("ton")
	require.NoError(t, err, "a network we publish an address for must be signable")
	tonKeyType, err := types.KeyTypeForNetwork(tonNet)
	require.NoError(t, err)
	require.Equal(t, types.KeyTypeEd25519, tonKeyType,
		"TON signs with Ed25519, so ton_address must come from the Ed25519 key")
	require.NotEmpty(t, eddsaPubKeyToTonAddress(edPub))
	require.Empty(t, eddsaPubKeyToTonAddress(secpPub))

	xrpNet, err := types.ParseNetwork("xrp")
	require.NoError(t, err, "a network we publish an address for must be signable")
	xrpKeyType, err := types.KeyTypeForNetwork(xrpNet)
	require.NoError(t, err)
	require.Equal(t, types.KeyTypeSecp256k1, xrpKeyType,
		"XRPL signs with secp256k1, so xrp_address must come from the secp256k1 key")
	require.NotEmpty(t, ecdsaPubKeyToXrpAddress(secpPub))
	require.Empty(t, ecdsaPubKeyToXrpAddress(edPub))
}
