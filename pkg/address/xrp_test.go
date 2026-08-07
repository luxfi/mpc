package address

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/require"
)

// Published XRPL vectors.
//
// Source 1 — XRPLF/xrpl.js, packages/ripple-keypairs/test/fixtures/api.json.
// These are the reference implementation's own fixtures, one per signing
// algorithm, each pairing a public key with the address it must produce.
//
// Source 2 — XRPLF/xrpl-dev-portal, docs/concepts/accounts/addresses.md,
// section "Address Encoding". The docs walk the encoding step by step and
// print the resulting address at the end; that worked example is reproduced
// here verbatim.
//
// The two sources are independent (a library's tests and the protocol's
// documentation), and between them they cover both key types XRPL accepts, so
// agreement is evidence about the encoding rather than about us.
const (
	// ripple-keypairs api.json → .secp256k1.keypair.publicKey / .secp256k1.address
	xrplVectorSecpPubKey  = "030D58EB48B4420B1F7B9DF55087E0E29FEF0E8468F9A6825B01CA2C361042D435"
	xrplVectorSecpAddress = "rU6K7V3Po4snVhBBaU29sesqs2qTQJWDw1"

	// ripple-keypairs api.json → .ed25519.keypair.publicKey / .ed25519.address
	xrplVectorEd25519PubKey  = "ED01FA53FA5A7E77798F882ECE20B1ABC00BB358A9E55A202D0D0676BD0CE37A63"
	xrplVectorEd25519Address = "rLUEXYuLiQptky37CqLcm9USQpPiz5rkpD"

	// addresses.md "Address Encoding" worked example.
	xrplDocsPubKey  = "ED9434799226374926EDA3B54B1B461B4ABF7237962EAE18528FEA67595397FA32"
	xrplDocsAddress = "rDTXLQ7ZKZVKz33zJbHjgVShjsBnqMBhmN"
)

// TestXRPMatchesPublishedSecp256k1Vector is the one that matters for us: the
// full exported path, from a secp256k1 key of the kind mpcd actually holds to
// the address XRPL's reference implementation says that key owns.
func TestXRPMatchesPublishedSecp256k1Vector(t *testing.T) {
	pub, err := hex.DecodeString(xrplVectorSecpPubKey)
	require.NoError(t, err)

	addr, err := XRP(pub)
	require.NoError(t, err)
	require.Equal(t, xrplVectorSecpAddress, addr,
		"XRP address must equal the one XRPLF/xrpl.js publishes for this key")
}

// TestXRPLEncoderMatchesPublishedEd25519Vectors exercises the encoder against
// the two published Ed25519 vectors.
//
// XRP itself refuses these keys — an Ed25519 XRPL address is one this wallet
// cannot sign for — so the test reaches the unexported encoder directly. That
// is the point: the encoding is curve-blind and these vectors pin it, which
// doubles the published evidence behind the base58 alphabet, the 0x00 prefix
// and the double-SHA256 checksum without weakening the curve gate.
func TestXRPLEncoderMatchesPublishedEd25519Vectors(t *testing.T) {
	for name, tc := range map[string]struct{ pubHex, want string }{
		"ripple_keypairs_fixture": {xrplVectorEd25519PubKey, xrplVectorEd25519Address},
		"docs_worked_example":     {xrplDocsPubKey, xrplDocsAddress},
	} {
		t.Run(name, func(t *testing.T) {
			pub, err := hex.DecodeString(tc.pubHex)
			require.NoError(t, err)
			require.Equal(t, tc.want, xrplClassicAddress(pub))

			// And the exported entry point must still refuse it, because the
			// signing path for XRPL is ECDSA-only.
			addr, err := XRP(pub)
			require.ErrorIs(t, err, ErrNotSecp256k1)
			require.Empty(t, addr)
		})
	}
}

// TestXRPRoundTripsToTheAccountID decodes the address back to its parts and
// checks each one, so a change that happened to keep the string well-formed
// while corrupting the payload cannot pass.
func TestXRPRoundTripsToTheAccountID(t *testing.T) {
	for i := 0; i < 64; i++ {
		priv, err := secp256k1.GeneratePrivateKey()
		require.NoError(t, err)
		compressed := priv.PubKey().SerializeCompressed()

		addr, err := XRP(compressed)
		require.NoError(t, err)

		decoded, err := base58.DecodeAlphabet(addr, xrplAlphabet)
		require.NoError(t, err)
		require.Len(t, decoded, 25, "1 prefix + 20 account id + 4 checksum")
		require.Equal(t, byte(xrplAccountIDPrefix), decoded[0])
		require.Equal(t, "r", addr[:1], "the 0x00 prefix is what makes it render as r…")

		require.Equal(t, xrplClassicAddress(compressed), addr)

		// The uncompressed encoding of the same point must land on the same
		// address; canonicalisation happening inside RequireSecp256k1 is what
		// guarantees that, and it is the property that stops a caller's choice
		// of encoding from moving the address.
		fromUncompressed, err := XRP(priv.PubKey().SerializeUncompressed())
		require.NoError(t, err)
		require.Equal(t, addr, fromUncompressed)
	}
}

// TestXRPRefusesCorruptedChecksum proves the checksum is load-bearing: flipping
// any single bit of a valid address must break it. Verified against XRPL's own
// rule rather than ours by checking the decoded checksum no longer matches.
func TestXRPRefusesCorruptedChecksum(t *testing.T) {
	pub, err := hex.DecodeString(xrplVectorSecpPubKey)
	require.NoError(t, err)
	addr, err := XRP(pub)
	require.NoError(t, err)

	decoded, err := base58.DecodeAlphabet(addr, xrplAlphabet)
	require.NoError(t, err)

	alphabet := "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
	for i := 0; i < len(addr); i++ {
		corrupted := []byte(addr)
		// Swap this character for a different one from the same alphabet, so
		// the string stays decodable and only the value changes.
		if corrupted[i] == alphabet[0] {
			corrupted[i] = alphabet[1]
		} else {
			corrupted[i] = alphabet[0]
		}
		require.NotEqual(t, addr, string(corrupted))

		got, err := base58.DecodeAlphabet(string(corrupted), xrplAlphabet)
		if err != nil || len(got) != 25 {
			continue // malformed length is rejection enough
		}
		valid := checksumValid(got)
		require.False(t, valid,
			"corrupting position %d produced an address with a valid checksum", i)
	}
	require.True(t, checksumValid(decoded), "the untouched address must verify")
}

// TestXRPRefusesWrongCurveAndWrongLength covers the inputs that must never
// yield a string: wrong curve, wrong length, and the 32-byte x-only form whose
// missing parity cannot be guessed.
func TestXRPRefusesWrongCurveAndWrongLength(t *testing.T) {
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	priv, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	compressed := priv.PubKey().SerializeCompressed()

	// 33 bytes led by 0x02 but not a point: passes every shape check and must
	// still be refused, which only on-curve parsing can do.
	notOnCurve := make([]byte, 33)
	notOnCurve[0] = 0x02
	for i := 1; i < 33; i++ {
		notOnCurve[i] = 0xFF
	}

	for name, key := range map[string][]byte{
		"nil":                       nil,
		"empty":                     {},
		"ed25519_32_bytes":          edPub,
		"ed25519_with_0xED_prefix":  append([]byte{0xED}, edPub...),
		"x_only_32_bytes":           compressed[1:],
		"truncated_compressed":      compressed[:32],
		"compressed_plus_one_byte":  append(append([]byte{}, compressed...), 0x00),
		"bad_leading_byte":          append([]byte{0x05}, compressed[1:]...),
		"uncompressed_wrong_leader": append([]byte{0x02}, make([]byte, 64)...),
		"on_shape_off_curve":        notOnCurve,
	} {
		t.Run(name, func(t *testing.T) {
			addr, err := XRP(key)
			require.ErrorIs(t, err, ErrNotSecp256k1)
			require.Empty(t, addr, "an error must never be accompanied by an address")
		})
	}
}

// TestRequireSecp256k1CanonicalisesEncoding pins the contract the address
// derivation leans on: whatever encoding comes in, the compressed form comes
// out, so the hash input cannot vary with the caller.
func TestRequireSecp256k1CanonicalisesEncoding(t *testing.T) {
	for i := 0; i < 64; i++ {
		priv, err := secp256k1.GeneratePrivateKey()
		require.NoError(t, err)
		want := priv.PubKey().SerializeCompressed()

		fromCompressed, err := RequireSecp256k1(want)
		require.NoError(t, err)
		require.Equal(t, want, fromCompressed)

		fromUncompressed, err := RequireSecp256k1(priv.PubKey().SerializeUncompressed())
		require.NoError(t, err)
		require.Equal(t, want, fromUncompressed)
		require.Len(t, fromUncompressed, 33)
		require.Contains(t, []byte{0x02, 0x03}, fromUncompressed[0])
	}
}

// checksumValid recomputes XRPL's checksum over an already-prefixed payload,
// independently of the encoder, so a bug in the encoder cannot make the
// corruption test pass by agreeing with itself.
func checksumValid(decoded []byte) bool {
	if len(decoded) != 25 {
		return false
	}
	first := sha256.Sum256(decoded[:21])
	second := sha256.Sum256(first[:])
	return bytes.Equal(second[:4], decoded[21:])
}
