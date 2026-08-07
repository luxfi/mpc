package address

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	tonwallet "github.com/xssnick/tonutils-go/ton/wallet"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

// Published TON vectors, taken from TON mainnet itself.
//
// A library's fixture proves only that the library still agrees with the
// library. What has to be true here is that the address we hand a customer is
// the address of a v4R2 wallet contract holding our key, and the authority on
// that is the chain. Each vector below is a live mainnet account, recorded by
// asking a public node three questions:
//
//	GET  /api/v3/accountStates?address=<addr>   → code_hash, data_boc
//	POST /api/v2/runGetMethod  get_public_key   → the key the contract holds
//
// keeping only accounts whose code_hash is the v4R2 wallet code hash
// feb5ff6820e2ff0d9483e7e0d62c817d846789fb4ae580c878866d959dabd5c0. So for
// every pair below the chain asserts: this address runs wallet v4R2, and that
// contract's public key is this one. Our derivation has to map the key back to
// the address, and any drift in the code cell, the sub-wallet id, the data
// layout or the cell hashing moves the result off all four at once.
//
// Reproduce any row with:
//
//	curl -s https://toncenter.com/api/v3/accountStates?address=<raw>
//	curl -s https://toncenter.com/api/v2/runGetMethod -H 'Content-Type: application/json' \
//	     -d '{"address":"<raw>","method":"get_public_key","stack":[]}'
//
// The first row is additionally the address that @ton/ton (the independent
// TypeScript implementation) asserts in src/wallets/v4/WalletContractV4.spec.ts
// — "should has balance and correct address" — so that row is corroborated by
// a second implementation as well as by the chain.
var tonMainnetV4R2Vectors = []struct {
	name       string
	pubKey     string // hex, from get_public_key
	rawAddress string // "<workchain>:<account_id hex>", from accountStates
	bounceable string // EQ… form, "" when not separately published
}{
	{
		name:       "ton_org_WalletContractV4_spec",
		pubKey:     "5754865e86d0ade1199301bbb0319a25ed6b129c4b0a57f28f62449b3df9c522",
		rawAddress: "0:e7045e094c52874d88ee94427235de1db2d2c61f59b9d54acb76ed35fedc38cf",
		bounceable: "EQDnBF4JTFKHTYjulEJyNd4dstLGH1m51UrLdu01_tw4z2Au",
	},
	{
		name:       "mainnet_v4r2_a",
		pubKey:     "25bf0159c7aefdde0a21522fbd3c4b0a29d45a56322596301abfff77907f710d",
		rawAddress: "0:46635cbdd634c45992509a7be7f1341e8744a01b4bfa5336ee7d62ebd342d6cc",
	},
	{
		name:       "mainnet_v4r2_b",
		pubKey:     "9943a1ccd841ce8c37cfd5ee5f1bc699a7f1aa7e77c4bee99fd3923d333f40e6",
		rawAddress: "0:3b105f243cd0e8fe8caadc4984411a7d713bbc1b71830783f03e24aea844176d",
	},
	{
		name:       "mainnet_v4r2_c",
		pubKey:     "26fb32300f35979e12627ac42846dadc92a4d00db551d76d7c2710f5ec0569bc",
		rawAddress: "0:f750b1869136f8c2c003675bf0fce90335185d2faab3bb89e913995e68729aaf",
	},
}

// tonV4R2CodeHash is the representation hash of the wallet v4R2 code cell, as
// reported by mainnet for every account above (accountStates.code_hash, base64
// "/rX/aCDi/w2Ug+fg1iyBfYRniftK5YDIeIZtlZ2r1cA=").
const tonV4R2CodeHash = "feb5ff6820e2ff0d9483e7e0d62c817d846789fb4ae580c878866d959dabd5c0"

// TestTONMatchesMainnetV4R2Accounts is the vector test. It goes through the
// exported TON function, so the curve gate is exercised on real keys too: a
// gate that rejected genuine wallet keys would fail here rather than in
// production.
func TestTONMatchesMainnetV4R2Accounts(t *testing.T) {
	for _, v := range tonMainnetV4R2Vectors {
		t.Run(v.name, func(t *testing.T) {
			pub, err := hex.DecodeString(v.pubKey)
			require.NoError(t, err)

			addr, err := TON(pub)
			require.NoError(t, err, "a real mainnet wallet key must yield an address")

			// TON returns the non-bounceable rendering; compare on the
			// account_id, which is what actually identifies the account and is
			// identical across renderings.
			parsed, err := parseTONFriendly(addr)
			require.NoError(t, err)
			require.Equal(t, v.rawAddress, parsed,
				"derived account differs from the v4R2 contract mainnet reports for this key")

			if v.bounceable != "" {
				alt, err := parseTONFriendly(v.bounceable)
				require.NoError(t, err)
				require.Equal(t, v.rawAddress, alt)
			}
		})
	}
}

// TestTONCodeCellIsTheMainnetV4R2Code checks the input we cannot see in the
// address: the contract code hashed into it. If tonutils-go ever re-tags a
// different cell as V4R2, every address this package produces silently moves,
// and every already-issued deposit address becomes undeployable. This pins the
// code cell to the hash mainnet reports for the accounts above.
func TestTONCodeCellIsTheMainnetV4R2Code(t *testing.T) {
	stateInit, err := tonwallet.GetStateInit(make(ed25519.PublicKey, 32), TONWalletVersion, TONSubwalletID)
	require.NoError(t, err)
	require.NotNil(t, stateInit.Code)
	require.Equal(t, tonV4R2CodeHash, hex.EncodeToString(stateInit.Code.Hash()),
		"the wallet code being hashed is not mainnet's v4R2 code")
}

// TestTONStateInitDataLayoutMatchesMainnet checks the other hashed input: the
// data cell. Mainnet's data_boc for the first vector decodes to
// seqno ‖ subwallet_id ‖ pubkey, and the sub-wallet id in particular is a
// silent address-mover — nothing about a wrong one looks wrong.
func TestTONStateInitDataLayoutMatchesMainnet(t *testing.T) {
	// accountStates.data_boc for 0:e7045e09…38cf, truncated to the fields the
	// address depends on. seqno differs from 0 because the wallet has sent
	// transactions; the address was fixed at seqno 0, which is what
	// GetStateInit builds.
	const mainnetDataBOC = "te6ccgEBAgEAUQABUQAAAFQpqaMXV1SGXobQreEZkwG7sDGaJe1rEpxLClfyj2JEmz35xSLAAQBFoQAI+lAOsPuAY5Dfuu2no15Sv+OhWcwEHuHJ2z2e09ajB1A="

	raw, err := base64.StdEncoding.DecodeString(mainnetDataBOC)
	require.NoError(t, err)
	c, err := cell.FromBOC(raw)
	require.NoError(t, err)

	s, err := c.BeginParse()
	require.NoError(t, err)
	_, err = s.LoadUInt(32) // seqno, now non-zero on chain
	require.NoError(t, err)
	subwallet, err := s.LoadUInt(32)
	require.NoError(t, err)
	pub, err := s.LoadSlice(256)
	require.NoError(t, err)

	require.Equal(t, uint64(TONSubwalletID), subwallet,
		"mainnet's v4R2 wallet uses a different sub-wallet id than we hash")
	require.Equal(t, tonMainnetV4R2Vectors[0].pubKey, hex.EncodeToString(pub),
		"data cell layout is not seqno‖subwallet‖pubkey")

	// And the parameters we pin are the ones the constants claim.
	require.Equal(t, uint32(698983191), TONSubwalletID)
	require.Equal(t, int8(0), TONWorkchain)
	require.Equal(t, tonwallet.V4R2, TONWalletVersion)
}

// TestTONEmitsNonBounceableMainnetForm pins the rendering. UQ vs EQ decides
// whether a deposit to a not-yet-deployed wallet lands or is returned to the
// sender, and the flag byte is the only difference between the two strings.
func TestTONEmitsNonBounceableMainnetForm(t *testing.T) {
	for i := 0; i < 32; i++ {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		addr, err := TON(pub)
		require.NoError(t, err)

		require.True(t, strings.HasPrefix(addr, "UQ"),
			"deposit addresses must be non-bounceable mainnet (UQ…), got %q", addr)

		decoded, err := base64.RawURLEncoding.DecodeString(addr)
		require.NoError(t, err)
		require.Len(t, decoded, 36, "1 flag + 1 workchain + 32 account id + 2 crc")
		require.Equal(t, byte(0x51), decoded[0], "0x51 = non-bounceable, mainnet")
		require.Equal(t, byte(0x00), decoded[1], "basechain")
	}
}

// TestTONRefusesTheSameKeysSolanaRefuses keeps the two chains on one gate. Both
// spend with an Ed25519 signature, so a key too weak to be a Solana address is
// exactly as unspendable as a TON wallet.
func TestTONRefusesTheSameKeysSolanaRefuses(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	bad := map[string][]byte{
		"nil":                           nil,
		"empty":                         {},
		"truncated":                     pub[:31],
		"too_long":                      append([]byte(pub), 0x00),
		"secp256k1_compressed_33_bytes": append([]byte{0x02}, pub...),
		"identity":                      mustHex(t, "0100000000000000000000000000000000000000000000000000000000000000"),
		"order_2":                       mustHex(t, "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
		"order_4_a":                     mustHex(t, "0000000000000000000000000000000000000000000000000000000000000080"),
		"order_4_b":                     mustHex(t, "0000000000000000000000000000000000000000000000000000000000000000"),
		"order_8_mix1":                  mustHex(t, "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
		"order_8_mix2":                  mustHex(t, "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
	}

	for name, key := range bad {
		t.Run(name, func(t *testing.T) {
			addr, err := TON(key)
			require.ErrorIs(t, err, ErrNotEd25519)
			require.Empty(t, addr, "an error must never be accompanied by an address")

			// Same verdict as Solana, since it is the same key and the same
			// signature scheme behind both.
			_, solErr := Solana(key)
			require.Error(t, solErr)
		})
	}
}

// TestTONIsDistinctFromSolana guards the bug this work replaced: a base58
// Solana string was once served as a TON address. The two encodings of one key
// must never be confusable.
func TestTONIsDistinctFromSolana(t *testing.T) {
	for i := 0; i < 32; i++ {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		ton, err := TON(pub)
		require.NoError(t, err)
		sol, err := Solana(pub)
		require.NoError(t, err)

		require.NotEqual(t, sol, ton)
		require.False(t, strings.HasPrefix(ton, sol[:8]))

		// A TON address is a contract hash, so it must not contain the key.
		decoded, err := base64.RawURLEncoding.DecodeString(ton)
		require.NoError(t, err)
		require.NotEqual(t, []byte(pub), decoded[2:34],
			"the account id must be the StateInit hash, never the raw key")
	}
}

// parseTONFriendly turns a user-friendly TON address back into its canonical
// "<workchain>:<account_id>" form and verifies the CRC16 while doing it.
func parseTONFriendly(s string) (string, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	if len(decoded) != 36 {
		return "", errBadTONLength
	}
	got := binary.BigEndian.Uint16(decoded[34:])
	if got != crc16XMODEM(decoded[:34]) {
		return "", errBadTONChecksum
	}
	return strings.ToLower(
		itoa(int8(decoded[1])) + ":" + hex.EncodeToString(decoded[2:34]),
	), nil
}

var (
	errBadTONLength   = errTON("ton: address must decode to 36 bytes")
	errBadTONChecksum = errTON("ton: crc16 mismatch")
)

type errTON string

func (e errTON) Error() string { return string(e) }

func itoa(v int8) string {
	if v < 0 {
		return "-" + itoa(-v)
	}
	if v < 10 {
		return string(rune('0' + v))
	}
	return itoa(v/10) + string(rune('0'+v%10))
}

// crc16XMODEM is the checksum TON puts on user-friendly addresses. Written out
// here rather than imported so the test verifies the address independently of
// the library that produced it.
func crc16XMODEM(data []byte) uint16 {
	var crc uint16
	for _, b := range data {
		crc ^= uint16(b) << 8
		for i := 0; i < 8; i++ {
			if crc&0x8000 != 0 {
				crc = crc<<1 ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}
