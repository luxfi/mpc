package address

import (
	"crypto/ed25519"
	"fmt"

	tonwallet "github.com/xssnick/tonutils-go/ton/wallet"
)

// The TON address of an Ed25519 key is not an encoding of that key. It is the
// address of a wallet *contract* that happens to hold the key:
//
//	account_id = SHA-256(StateInit{code, data})   where data embeds the pubkey
//	address    = workchain ‖ account_id
//
// Because the code cell is part of the hash, the same key lands on a different
// address under every wallet version. v3R2, v4R2 and W5 are three different
// addresses for one key. "The TON address of this key" is therefore not a
// well-formed question; "the v4R2 address of this key" is.
//
// The three parameters below are that answer, and they are constants rather
// than arguments on purpose: a per-call wallet version would let one caller
// hand out a deposit address that a different caller cannot spend from.
const (
	// TONWalletVersion is wallet v4R2.
	//
	// Chosen because it is what the rest of the estate already signs with:
	// luxfi/bridge's TON assembler builds its state_init with
	// tonwallet.GetStateInit(pub, tonwallet.V4R2, DefaultSubwallet) and derives
	// the source address with the identical call this file makes. If keygen
	// published a v3R2 or W5 address instead, the deposit would land at an
	// address whose contract the only code we have that can spend TON does not
	// know how to deploy — fundable, unspendable, which is the exact failure
	// this package exists to prevent. v4R2 is also the flavour the overwhelming
	// majority of TON wallets and exchanges deploy, so it is the well-trodden
	// path for the sender as well.
	//
	// The contract is NOT deployed when the address is handed out. That is
	// normal and safe on TON: an incoming transfer credits an uninitialised
	// account, and the wallet contract is deployed later by attaching this same
	// StateInit to the first outgoing message. It only works because the
	// StateInit we would deploy is byte-identical to the one hashed here, which
	// is why the version is pinned rather than chosen per call.
	TONWalletVersion = tonwallet.V4R2

	// TONSubwalletID is the v4R2 sub-wallet id, which is hashed into the data
	// cell and so is as address-determining as the public key itself. 698983191
	// is the ecosystem default (tonutils-go's DefaultSubwallet, @ton/ton's
	// 698983191 + workchain) and is what luxfi/bridge signs with.
	TONSubwalletID uint32 = tonwallet.DefaultSubwallet

	// TONWorkchain is 0, the basechain, where ordinary wallets live.
	// Workchain -1 is the masterchain and is for validators, not deposits.
	TONWorkchain int8 = 0
)

// TON derives the v4R2 TON wallet address for an Ed25519 public key.
//
// The key is checked against its curve first, by the same RequireEd25519 gate
// Solana uses, for the same reason: a 32-byte string that is not an
// edwards25519 prime-order point still hashes into a perfectly well-formed
// address, and that address would accept deposits no signature can ever move.
//
// The returned string is the user-friendly base64url form in its
// NON-bounceable rendering ("UQ…"). That choice is deliberate. A bounceable
// ("EQ…") message sent to an account whose contract is not yet deployed is
// returned to the sender, and a deposit address is by definition undeployed
// until we first spend from it — so publishing the bounceable form would make
// a customer's first deposit bounce. The non-bounceable form credits the
// uninitialised account and waits, which is what a deposit address must do.
// Both forms carry the identical account_id; only the sender-facing hint
// differs. luxfi/bridge makes the same choice for the same reason.
func TON(pub []byte) (string, error) {
	if err := RequireEd25519(pub); err != nil {
		return "", err
	}
	addr, err := tonwallet.AddressFromPubKey(ed25519.PublicKey(pub), TONWalletVersion, TONSubwalletID, TONWorkchain)
	if err != nil {
		return "", fmt.Errorf("derive TON v4R2 address: %w", err)
	}
	return addr.Bounce(false).String(), nil
}
