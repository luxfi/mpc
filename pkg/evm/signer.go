// Package evm turns a threshold secp256k1 signer into an Ethereum-account
// signer: it derives the 20-byte account an MPC wallet controls, signs a
// 32-byte transaction digest, and recovers the account a signature binds to.
//
// The point of this package is that a Lux mainnet deploy never needs a plaintext
// private key or a mnemonic. The signing key exists only as shares across the
// MPC quorum; a caller holds the wallet's public account and a way to ask the
// quorum for a signature over a digest. Everything an EVM chain needs — the
// account, the (r, s, v) triple, the assembled transaction — is built from
// those two things and nothing more.
//
// An account is derived from a curve, never a byte length: the address is the
// last 20 bytes of Keccak256 over the 64-byte uncompressed secp256k1 public key,
// which is exactly what luxfi/geth's own sender recovery computes, so an account
// derived here and a sender recovered from an assembled transaction are the same
// value by construction.
package evm

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
)

// digestLen is the width of an EVM signing digest: Keccak256 is 32 bytes, and
// secp256k1 signs a digest of exactly that width. A shorter or longer input is
// not a digest and is refused rather than padded.
const digestLen = 32

// Signature is a secp256k1 signature over an EVM digest: the two scalars r and s
// and the recovery id v (0 or 1). It is the whole output of a threshold signing
// round and the whole input to recovery and to transaction assembly.
type Signature struct {
	R [32]byte
	S [32]byte
	V byte
}

// Bytes returns the 65-byte r‖s‖v encoding luxfi/geth and every EVM tool
// consume. v is 0 or 1, the low form; callers that need the EIP-155 or typed
// form get it from transaction assembly, not from here.
func (sig Signature) Bytes() []byte {
	out := make([]byte, 65)
	copy(out[0:32], sig.R[:])
	copy(out[32:64], sig.S[:])
	out[64] = sig.V
	return out
}

// ParseSignature reads the 65-byte r‖s‖v encoding. A v of 27 or 28 is accepted
// and normalised to 0 or 1, so a signature that arrived in the legacy form is
// not silently mis-recovered.
func ParseSignature(b []byte) (Signature, error) {
	if len(b) != 65 {
		return Signature{}, fmt.Errorf("evm: signature must be 65 bytes, got %d", len(b))
	}
	var sig Signature
	copy(sig.R[:], b[0:32])
	copy(sig.S[:], b[32:64])
	sig.V = normalizeV(b[64])
	return sig, nil
}

// SignatureFromRSV builds a Signature from the parts an MPC signing result
// carries: r and s as big-endian byte slices (left-padded to 32 bytes if short)
// and the recovery id. This is the one place the quorum's output becomes a
// value this package operates on.
func SignatureFromRSV(r, s []byte, v byte) (Signature, error) {
	if len(r) == 0 || len(r) > 32 || len(s) == 0 || len(s) > 32 {
		return Signature{}, fmt.Errorf("evm: r and s must each be 1..32 bytes, got %d and %d", len(r), len(s))
	}
	var sig Signature
	copy(sig.R[32-len(r):], r)
	copy(sig.S[32-len(s):], s)
	sig.V = normalizeV(v)
	return sig, nil
}

func normalizeV(v byte) byte {
	if v >= 27 {
		return v - 27
	}
	return v
}

// Account derives the EVM account a secp256k1 public key controls. The key may
// be 65-byte uncompressed, 64-byte uncompressed without the 0x04 tag, or
// 33-byte compressed — the forms an MPC keygen result reports across chains —
// and any other length is refused rather than guessed at.
func Account(pub []byte) (common.Address, error) {
	uncompressed, err := uncompress(pub)
	if err != nil {
		return common.Address{}, err
	}
	// address = Keccak256(X‖Y)[12:], i.e. the uncompressed key without its 0x04
	// tag. This is byte-for-byte what luxfi/geth's recoverPlain computes for a
	// transaction sender.
	return common.BytesToAddress(crypto.Keccak256(uncompressed[1:])[12:]), nil
}

// uncompress returns the 65-byte 0x04‖X‖Y form of a secp256k1 public key,
// validating that the bytes are a point on the curve.
func uncompress(pub []byte) ([]byte, error) {
	switch len(pub) {
	case 65:
		if _, err := crypto.UnmarshalPubkey(pub); err != nil {
			return nil, fmt.Errorf("evm: %w", err)
		}
		return pub, nil
	case 64:
		full := make([]byte, 65)
		full[0] = 0x04
		copy(full[1:], pub)
		if _, err := crypto.UnmarshalPubkey(full); err != nil {
			return nil, fmt.Errorf("evm: %w", err)
		}
		return full, nil
	case 33:
		pk, err := crypto.DecompressPubkey(pub)
		if err != nil {
			return nil, fmt.Errorf("evm: %w", err)
		}
		return crypto.FromECDSAPub(pk), nil
	default:
		return nil, fmt.Errorf("evm: public key must be 33, 64, or 65 bytes, got %d", len(pub))
	}
}

// Recover returns the account that produced sig over digest. It is the inverse
// of signing and the check every assembled transaction is held to: a signature
// whose recovery id points at the wrong account is caught here rather than
// broadcast.
func Recover(digest []byte, sig Signature) (common.Address, error) {
	if len(digest) != digestLen {
		return common.Address{}, fmt.Errorf("evm: digest must be %d bytes, got %d", digestLen, len(digest))
	}
	pub, err := crypto.Ecrecover(digest, sig.Bytes())
	if err != nil {
		return common.Address{}, fmt.Errorf("evm: recover: %w", err)
	}
	return common.BytesToAddress(crypto.Keccak256(pub[1:])[12:]), nil
}

// Signer is an EVM account backed by a secp256k1 key. Account is the address it
// signs for; Sign returns a signature over a 32-byte digest. The key material
// lives wherever the implementation keeps it — in an MPC quorum for Remote, in
// memory for Local — and callers depend only on this seam.
type Signer interface {
	Account() common.Address
	Sign(ctx context.Context, digest []byte) (Signature, error)
}

// Local signs with an in-memory secp256k1 key. It exists for offline and
// air-gapped signing, for development, and for tests. It is NOT the custody
// path: a production key never leaves the MPC quorum, so a Lux mainnet deploy
// uses Remote. Local is here so the same assembly and recovery code can be
// exercised without a live quorum.
type Local struct {
	key  *ecdsa.PrivateKey
	addr common.Address
}

// NewLocal wraps an secp256k1 private key.
func NewLocal(key *ecdsa.PrivateKey) *Local {
	addr := common.BytesToAddress(crypto.Keccak256(crypto.FromECDSAPub(&key.PublicKey)[1:])[12:])
	return &Local{key: key, addr: addr}
}

// LocalFromHex wraps a hex-encoded secp256k1 private key.
func LocalFromHex(hexKey string) (*Local, error) {
	key, err := crypto.HexToECDSA(trim0x(hexKey))
	if err != nil {
		return nil, fmt.Errorf("evm: private key: %w", err)
	}
	return NewLocal(key), nil
}

func (l *Local) Account() common.Address { return l.addr }

func (l *Local) Sign(_ context.Context, digest []byte) (Signature, error) {
	if len(digest) != digestLen {
		return Signature{}, fmt.Errorf("evm: digest must be %d bytes, got %d", digestLen, len(digest))
	}
	raw, err := crypto.Sign(digest, l.key)
	if err != nil {
		return Signature{}, fmt.Errorf("evm: sign: %w", err)
	}
	return ParseSignature(raw)
}

// SignDigest is the one call a custody backend provides: given a 32-byte digest,
// return the threshold signature over it. The MPC daemon's TriggerSign with an
// EVM network — which resolves to secp256k1/CGGMP21 — is exactly this shape once
// its (r, s, v) result is read into a Signature.
type SignDigest func(ctx context.Context, digest []byte) (Signature, error)

// Remote signs through an MPC quorum. The private key is never assembled: it
// exists only as shares across the signer set, and each signature is a fresh
// threshold round. addr is the wallet's account, known from keygen; sign
// carries the digest to the quorum and returns its answer.
type Remote struct {
	addr common.Address
	sign SignDigest
}

// NewRemote binds a wallet's known account to the call that reaches its quorum.
func NewRemote(addr common.Address, sign SignDigest) (*Remote, error) {
	if sign == nil {
		return nil, errors.New("evm: remote signer needs a sign function")
	}
	return &Remote{addr: addr, sign: sign}, nil
}

func (r *Remote) Account() common.Address { return r.addr }

func (r *Remote) Sign(ctx context.Context, digest []byte) (Signature, error) {
	if len(digest) != digestLen {
		return Signature{}, fmt.Errorf("evm: digest must be %d bytes, got %d", digestLen, len(digest))
	}
	return r.sign(ctx, digest)
}

func trim0x(s string) string {
	if len(s) >= 2 && (s[0:2] == "0x" || s[0:2] == "0X") {
		return s[2:]
	}
	return s
}
