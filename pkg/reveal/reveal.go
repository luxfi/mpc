// Package reveal opens a secret that was sealed to a wallet's share set.
//
// This daemon holds shares and answers with them. It does NOT hold the things
// those shares open: a caller that wants something opened brings the ciphertext.
// So there is no store of sealed material here to guard, back up or leak, and a
// sealed secret can sit anywhere its owner likes — a config map, a repository,
// a file — because the only thing that opens it is a quorum of these nodes.
//
// One round. A party's answer depends on its own share and the ciphertext and
// nothing else, so there is no session to build and no party that must wait to
// speak. Answer runs on each node; Combine runs wherever the request came from.
package reveal

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/protocols/frost"
	"github.com/luxfi/threshold/protocols/reveal"

	"github.com/luxfi/mpc/pkg/kvstore"
	"github.com/luxfi/mpc/pkg/mpc"
)

// ErrNoShare means this node holds no share for the key named. It is an answer,
// not a silence: a node that cannot take part says so, because "no share here"
// and "this node is gone" call for different responses from the caller — the
// first will never succeed, the second is worth waiting out.
var ErrNoShare = errors.New("reveal: this node holds no share for that key")

// Answer computes this node's contribution to opening ciphertext under the
// share set recorded for keyID.
//
// The share is loaded, used, and left behind: what leaves this function is a
// point and a proof, never the share and never anything the share could be
// recovered from.
func Answer(store kvstore.KVStore, orgID, keyID string, ciphertext []byte) ([]byte, error) {
	cfg, err := config(store, orgID, keyID)
	if err != nil {
		return nil, err
	}
	ct, err := reveal.UnmarshalCiphertext(cfg.PublicKey.Curve(), ciphertext)
	if err != nil {
		return nil, err
	}
	answer, err := ct.Answer(rand.Reader, cfg.ID, cfg.PrivateShare)
	if err != nil {
		return nil, fmt.Errorf("reveal: answer for %s: %w", keyID, err)
	}
	return answer.MarshalBinary()
}

// Combine turns enough answers into the secret.
//
// The threshold and the verification shares come from the share set, read here
// from the same record every party read — not from the request and not from the
// answers. An opening whose quorum size arrived with the request would be an
// opening whose quorum size the requester chose.
func Combine(store kvstore.KVStore, orgID, keyID string, ciphertext []byte, answers [][]byte) ([]byte, error) {
	cfg, err := config(store, orgID, keyID)
	if err != nil {
		return nil, err
	}
	group := cfg.PublicKey.Curve()

	ct, err := reveal.UnmarshalCiphertext(group, ciphertext)
	if err != nil {
		return nil, err
	}

	decoded := make([]*reveal.Answer, 0, len(answers))
	for _, raw := range answers {
		a, err := reveal.UnmarshalAnswer(group, raw)
		if err != nil {
			// One unreadable answer does not end the attempt: the rest may
			// still be a quorum, and a party sending nonsense should cost the
			// request nothing beyond its own seat.
			continue
		}
		decoded = append(decoded, a)
	}

	secret, err := reveal.Open(ct, cfg.Threshold, cfg.VerificationShares, decoded)
	if err != nil {
		return nil, fmt.Errorf("reveal: open %s: %w", keyID, err)
	}
	return secret, nil
}

// PublicKey returns the group key a caller seals to. It is public in the strict
// sense — handing it out lets anyone seal a secret to this committee and lets
// nobody open one.
func PublicKey(store kvstore.KVStore, orgID, keyID string) (curve.Point, error) {
	cfg, err := config(store, orgID, keyID)
	if err != nil {
		return nil, err
	}
	return cfg.PublicKey, nil
}

// config loads the share set recorded for a key.
//
// The Ed25519 share, deliberately and by name. One keygen writes TWO shares for
// a wallet — the CGGMP21 secp256k1 one under the bare id, the FROST Ed25519 one
// under `ed25519:<id>` — and the bare id is the one a reader reaches by default.
// Reading it here would load a share from another curve entirely, whose scalar
// acts on no point this ciphertext contains.
func config(store kvstore.KVStore, orgID, keyID string) (*frost.Config, error) {
	raw, err := mpc.GetKeyShareWithFallback(store, orgID, mpc.Ed25519ShareKey(keyID))
	if err != nil || len(raw) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNoShare, keyID)
	}
	cfg, err := mpc.UnmarshalEd25519Config(raw)
	if err != nil {
		return nil, fmt.Errorf("reveal: read the share set for %s: %w", keyID, err)
	}
	if cfg.PublicKey == nil || cfg.PrivateShare == nil || cfg.VerificationShares == nil {
		return nil, fmt.Errorf("reveal: the share set for %s is incomplete", keyID)
	}
	return cfg, nil
}
