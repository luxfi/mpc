package address

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/mr-tron/base58"
	"golang.org/x/crypto/ripemd160" //nolint:staticcheck // XRPL and Bitcoin both specify RIPEMD160; there is no substitute.
)

// ErrNotSecp256k1 reports that bytes offered as a secp256k1 public key are not
// one. As with ErrNotEd25519, the only correct response is to emit no address.
var ErrNotSecp256k1 = errors.New("not a secp256k1 public key")

// xrplAlphabet is the XRPL base58 dictionary. It is NOT the Bitcoin dictionary:
// the two alphabets contain the same 58 characters in a different order, so
// encoding an XRPL payload with the Bitcoin alphabet yields a string that is
// still 34 characters, still starts with 'r' about as often, and still passes a
// regex — but names a different account. Nothing about the shape of the output
// reveals the mistake, which is why the encoder is pinned to published test
// vectors rather than eyeballed.
var xrplAlphabet = base58.NewAlphabet("rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz")

// xrplAccountIDPrefix is the type prefix XRPL puts in front of an AccountID
// before base58 encoding. XRPL base58-encodes several different kinds of key
// with the same alphabet and distinguishes them by this byte; 0x00 is what
// makes an address render as "r…".
const xrplAccountIDPrefix = 0x00

// XRP derives the XRP Ledger classic address ("r…") for a secp256k1 public key.
//
// Deposit model, which this function does NOT implement and must not be read as
// implementing: XRPL charges a base reserve (10 XRP at time of writing) per
// funded account, and that reserve is not refundable. Handing every payer their
// own r-address therefore strands 10 XRP per payer, forever. The production
// model is a single pooled r-address plus a per-deposit DestinationTag, and the
// tag allocation belongs to whoever is taking the payments, not here. This
// function exists so the pooled address is one we provably control and can
// sign for — not so a fresh address can be minted per payer.
//
// Only secp256k1 is accepted. XRPL also supports Ed25519 account keys (wire
// prefix 0xED), and this wallet does hold an Ed25519 key, but the XRPL signing
// path in luxfi/bridge emits ECDSA signatures only. An Ed25519 XRPL address
// would be an address we can fund and cannot spend from.
func XRP(pub []byte) (string, error) {
	compressed, err := RequireSecp256k1(pub)
	if err != nil {
		return "", err
	}
	return xrplClassicAddress(compressed), nil
}

// RequireSecp256k1 checks that pub is a usable secp256k1 public key and returns
// it in the 33-byte compressed encoding XRPL hashes.
//
// It returns the canonical bytes rather than only an error because the caller
// must hash the compressed form specifically: the same point has a 65-byte
// uncompressed encoding that hashes to a completely different, wrong address.
// Having one function both validate and canonicalise leaves no way to hash a
// non-canonical encoding by accident.
//
// A bare 32-byte x-coordinate is refused rather than completed. Recovering the
// point from x alone requires choosing a sign for y, and both choices are valid
// points, so the choice is a coin flip that silently produces the sibling
// point's address half the time. That is not a hypothetical: pubKeyToBtcAddress
// in cmd/mpcd guesses 0x02 for a 32-byte input for exactly this reason and is
// wrong for every odd-y key. Refusing is the only safe answer, and the MPC
// keygen serialises the full compressed point anyway (see
// pkg/mpc/keygen_session.go), so a 32-byte ECDSA key means something upstream
// has already lost the parity.
func RequireSecp256k1(pub []byte) ([]byte, error) {
	switch {
	case len(pub) == 33 && (pub[0] == 0x02 || pub[0] == 0x03):
	case len(pub) == 65 && pub[0] == 0x04:
	case len(pub) == 32:
		return nil, fmt.Errorf("%w: 32 bytes is a bare x-coordinate with no y parity, and guessing the parity picks the wrong point for half of all keys", ErrNotSecp256k1)
	default:
		lead := "none"
		if len(pub) > 0 {
			lead = fmt.Sprintf("0x%02x", pub[0])
		}
		return nil, fmt.Errorf("%w: want 33 bytes led by 0x02/0x03 or 65 bytes led by 0x04, got %d bytes led by %s", ErrNotSecp256k1, len(pub), lead)
	}

	// Parsing is what proves the bytes are a point on secp256k1 at all. Without
	// it the encoding checks above would pass any 33 bytes beginning 0x02,
	// including an Ed25519 key with a byte stuck on the front.
	key, err := secp256k1.ParsePubKey(pub)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotSecp256k1, err)
	}
	return key.SerializeCompressed(), nil
}

// xrplClassicAddress performs the XRPL address encoding on a 33-byte account
// public key, per XRPL "Address Encoding":
//
//	account_id = RIPEMD160(SHA-256(pubkey))
//	payload    = 0x00 ‖ account_id
//	checksum   = SHA-256(SHA-256(payload))[:4]
//	address    = base58_xrpl(payload ‖ checksum)
//
// It is unexported and takes no view on the curve, because the encoding does
// not: XRPL feeds a 33-byte secp256k1 key or an 0xED-prefixed Ed25519 key
// through the identical steps. Keeping the encoder curve-blind is what lets it
// be tested against the Ed25519 vectors XRPL publishes while the exported XRP
// entry point still refuses everything but secp256k1.
func xrplClassicAddress(accountPubKey []byte) string {
	inner := sha256.Sum256(accountPubKey)
	outer := ripemd160.New()
	outer.Write(inner[:])
	accountID := outer.Sum(nil)

	payload := make([]byte, 0, 1+len(accountID)+4)
	payload = append(payload, xrplAccountIDPrefix)
	payload = append(payload, accountID...)

	first := sha256.Sum256(payload)
	second := sha256.Sum256(first[:])

	return base58.EncodeAlphabet(append(payload, second[:4]...), xrplAlphabet)
}
