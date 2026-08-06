package address

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/require"
)

// TestSolanaRoundTripsARealEd25519Key pins the encoding itself: a Solana address
// is the base58 of the raw 32-byte key, nothing added and nothing hashed.
func TestSolanaRoundTripsARealEd25519Key(t *testing.T) {
	for i := 0; i < 64; i++ {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		addr, err := Solana(pub)
		require.NoError(t, err, "a stdlib Ed25519 key must always yield an address")

		decoded, err := base58.Decode(addr)
		require.NoError(t, err)
		require.Equal(t, []byte(pub), decoded, "the address must decode back to the key exactly")
	}
}

// TestSolanaRefusesWrongLength covers truncation and padding, the failure modes
// that come from a mis-sized buffer rather than a wrong curve.
func TestSolanaRefusesWrongLength(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	for name, key := range map[string][]byte{
		"nil":                           nil,
		"empty":                         {},
		"truncated":                     pub[:31],
		"too_long":                      append([]byte(pub), 0x00),
		"secp256k1_compressed_33_bytes": append([]byte{0x02}, pub...),
	} {
		t.Run(name, func(t *testing.T) {
			addr, err := Solana(key)
			require.ErrorIs(t, err, ErrNotEd25519)
			require.Empty(t, addr, "an error must never be accompanied by an address")
		})
	}
}

// TestSolanaRefusesTorsionPoints is the subtle one. These decode as perfectly
// good curve points, so nothing short of a subgroup check rejects them — and a
// torsion-tainted key makes the Schnorr verification equation unsatisfiable, so
// the address would take deposits and never spend.
func TestSolanaRefusesTorsionPoints(t *testing.T) {
	// Canonical small-order points of edwards25519 (RFC 8032 §5.1.7 / the
	// standard small-order set): identity, the order-2 point, and the two
	// order-4 points.
	smallOrder := map[string]string{
		"identity":     "0100000000000000000000000000000000000000000000000000000000000000",
		"order_2":      "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"order_4_a":    "0000000000000000000000000000000000000000000000000000000000000080",
		"order_4_b":    "0000000000000000000000000000000000000000000000000000000000000000",
		"order_8_mix1": "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"order_8_mix2": "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
	}

	for name, hexKey := range smallOrder {
		t.Run(name, func(t *testing.T) {
			key := mustHex(t, hexKey)

			// Every one of these must be refused. The identity is included
			// deliberately: it passes the prime-order test ([L]O = O) and is the
			// worst case of the set, because a wallet keyed to it is spendable
			// by anybody rather than by nobody.
			addr, err := Solana(key)
			require.Error(t, err, "small-order point %s must never yield an address", name)
			require.ErrorIs(t, err, ErrNotEd25519)
			require.Empty(t, addr, "an error must never be accompanied by an address")
		})
	}
}

// TestRequireEd25519AgreesWithTheDKGDecoder makes the address gate and the
// ceremony gate the same gate. If they ever diverge, a key could be good enough
// to mint an address but not good enough to sign with, or the reverse.
func TestRequireEd25519AgreesWithTheDKGDecoder(t *testing.T) {
	for i := 0; i < 256; i++ {
		candidate := make([]byte, 32)
		_, err := rand.Read(candidate)
		require.NoError(t, err)

		addrErr := RequireEd25519(candidate)

		point := (curve.Ed25519{}).NewPoint()
		dkgErr := point.UnmarshalBinary(candidate)

		if dkgErr == nil && point.IsIdentity() {
			// The one intended divergence: the DKG decoder accepts the identity,
			// the address gate does not. Asserted rather than tolerated so the
			// difference stays deliberate.
			require.Error(t, addrErr, "identity must be refused by the address gate")
			continue
		}
		require.Equal(t, dkgErr == nil, addrErr == nil,
			"address gate and DKG decoder disagree on %x", candidate)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		var b int
		for j := 0; j < 2; j++ {
			c := s[i*2+j]
			var v int
			switch {
			case c >= '0' && c <= '9':
				v = int(c - '0')
			case c >= 'a' && c <= 'f':
				v = int(c-'a') + 10
			default:
				t.Fatalf("bad hex %q", s)
			}
			b = b<<4 | v
		}
		out[i] = byte(b)
	}
	return out
}
