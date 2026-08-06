// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package main, file sign_idempotency.go.
//
// Idempotency cache for the internal HTTP POST /sign endpoint — the
// anti-signing-oracle guard backing the wallet-backend custody adapter
// (lux/wallet apps/backend/internal/custody/mpc.go) and the MPC client
// Threshold.Sign contract.
//
// Contract enforced here:
//
//	idempotency_key REQUIRED            → empty rejected, no signing.
//	org_id          REQUIRED            → empty rejected (tenant isolation).
//	same key + same canonical content   → return the CACHED result, never re-sign.
//	same key + different content        → CONFLICT, never sign (oracle defense).
//	concurrent duplicates               → single-flight; signer runs exactly once.
//	signer FAILURE                       → not cached; a later retry may re-attempt.
//
// In-process by design: each mpcd node owns its cache. The custody adapter
// retries against one endpoint, so a per-node cache is the correct scope — no
// shared store, no persistence. Keep it simple.
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	mpcapi "github.com/luxfi/mpc/pkg/api"
	"github.com/luxfi/mpc/pkg/types"
)

// Boundary errors surfaced by the cache / request validation. The HTTP handler
// maps these to status codes; keeping them as sentinels lets callers (and
// tests) branch with errors.Is rather than string matching.
var (
	errIdempotencyKeyRequired = errors.New("idempotency_key required")
	errOrgIDRequired          = errors.New("org_id is required")
	errIdempotencyConflict    = errors.New("idempotency conflict")
)

// signFields is the canonical CONTENT of a /sign request — every field that
// binds the signature, EXCLUDING idempotency_key (which keys the cache, not the
// content). The canonical hash over these fields is what a reused idempotency
// key is checked against to detect a conflicting replay.
//
// Network is part of the content because it selects the curve: the same bytes
// under the same key, requested for SOL and then for ETH, are two different
// signatures from two different keys. Reusing one idempotency key across them
// must conflict, not return the first one's result.
type signFields struct {
	OrgID       string
	WalletID    string
	Network     string
	ChainID     int
	PayloadHash string // hex, as received on the wire
}

// canonicalHash returns a stable, field-order-independent sha256 over the
// request content. Each field is length-prefixed (8-byte big-endian) before
// its bytes so no character can migrate across a field boundary and forge a
// collision — e.g. {OrgID:"ab",WalletID:"c"} and {OrgID:"a",WalletID:"bc"}
// hash differently. Returned as lowercase hex.
func (f signFields) canonicalHash() string {
	h := sha256.New()
	write := func(s string) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	write(f.OrgID)
	write(f.WalletID)
	write(f.Network)
	write(strconv.Itoa(f.ChainID))
	write(f.PayloadHash)
	return hex.EncodeToString(h.Sum(nil))
}

// decodeSignPayload decodes the hex bytes to sign and enforces the length rule
// for the network's curve.
//
// The rule belongs to the scheme, not to the endpoint:
//
//   - secp256k1 signs a 32-byte DIGEST. Anything else is a caller bug, caught
//     here rather than inside the signer.
//   - Ed25519 is PureEdDSA: the message is hashed inside the challenge, so what
//     gets signed is the message itself, at whatever length the chain uses — a
//     serialized Solana transaction message is hundreds of bytes; a TON cell
//     hash is 32. Demanding 32 bytes here is what made every Solana signing
//     request impossible to express, and pre-hashing to satisfy it would sign a
//     digest of a digest, which the chain rejects.
//
// An empty payload is refused for both: signing nothing is never intended, and
// for Ed25519 it is otherwise a legal length.
func decodeSignPayload(network types.NetworkCode, hexPayload string) ([]byte, error) {
	keyType, err := types.KeyTypeForNetwork(network)
	if err != nil {
		return nil, err
	}
	payload, err := hex.DecodeString(strings.TrimPrefix(hexPayload, "0x"))
	if err != nil {
		return nil, errors.New("payload_hash must be hex")
	}
	if len(payload) == 0 {
		return nil, errors.New("payload_hash must not be empty")
	}
	if keyType == types.KeyTypeSecp256k1 && len(payload) != 32 {
		return nil, fmt.Errorf("payload_hash must be a 32-byte digest for %s (got %d bytes)", keyType, len(payload))
	}
	return payload, nil
}

// validateSignRequest enforces the boundary preconditions before any signing
// machinery is touched. Returns a sentinel error the handler maps to 400.
func validateSignRequest(idempotencyKey string, f signFields) error {
	if idempotencyKey == "" {
		return errIdempotencyKeyRequired
	}
	if f.OrgID == "" {
		return errOrgIDRequired
	}
	return nil
}

// cachedSign is the committed result for an idempotency key — the body the
// handler returns. SessionID is derived from the canonical hash so it is stable
// across idempotent retries.
type cachedSign struct {
	SessionID string
	Signature string
	Status    string
}

// signFunc is the injectable signer the cache drives. The HTTP handler wires
// ConsensusMPCBackend.TriggerSign here; tests inject a counting mock. It
// receives the org/wallet, the network that selects the curve, and the decoded
// bytes to sign.
type signFunc func(orgID, walletID string, network types.NetworkCode, payload []byte) (*mpcapi.SignResult, error)

// signEntry is one in-flight-or-completed idempotency slot. done is closed when
// the single in-flight signer call returns; until then, duplicate callers block
// on it (single-flight). result/err hold the committed outcome.
type signEntry struct {
	canonicalHash string
	done          chan struct{}
	result        *cachedSign
	err           error
}

// signIdempotencyCache is a per-node, mutex-guarded idempotency map. It is the
// only place /sign deduplication lives.
type signIdempotencyCache struct {
	mu      sync.Mutex
	entries map[string]*signEntry // keyed by idempotency_key
}

func newSignIdempotencyCache() *signIdempotencyCache {
	return &signIdempotencyCache{entries: make(map[string]*signEntry)}
}

// Do executes the signer exactly once per (idempotency_key, content) pair.
//
//   - First call for a key: registers an in-flight entry, releases the lock,
//     runs signer, records the result, and wakes any waiters.
//   - Duplicate call, same key + same canonical content, completed: returns the
//     cached result (signer NOT called).
//   - Duplicate call, same key + same canonical content, still in flight:
//     blocks on the entry's done channel, then returns the shared result
//     (signer NOT called — single-flight).
//   - Same key + DIFFERENT canonical content: returns errIdempotencyConflict
//     WITHOUT signing — the signing-oracle defense.
//   - Signer error: the entry is removed so a future retry may re-attempt; the
//     failure is never cached and never wakes a "successful" waiter.
//
// payload is the decoded bytes to sign; it is passed through to signer
// untouched and is NOT part of the cache key (the canonical hash of
// f.PayloadHash already binds it). network is likewise already bound, via
// f.Network.
func (c *signIdempotencyCache) Do(idempotencyKey string, f signFields, network types.NetworkCode, payload []byte, signer signFunc) (*cachedSign, error) {
	canon := f.canonicalHash()

	c.mu.Lock()
	if e, ok := c.entries[idempotencyKey]; ok {
		// Key already seen. Reject a content mismatch before doing anything
		// else — never sign under a reused key with new content.
		if e.canonicalHash != canon {
			c.mu.Unlock()
			return nil, errIdempotencyConflict
		}
		// Same content: join the in-flight call / take the cached result.
		c.mu.Unlock()
		<-e.done
		return e.result, e.err
	}

	// First caller for this key: register in-flight and run the signer with the
	// lock released so concurrent distinct keys don't serialize.
	e := &signEntry{canonicalHash: canon, done: make(chan struct{})}
	c.entries[idempotencyKey] = e
	c.mu.Unlock()

	res, err := signer(f.OrgID, f.WalletID, network, payload)
	if err != nil {
		// Do not cache failures: drop the entry so a retry can re-attempt.
		c.mu.Lock()
		// Only delete if it is still our entry (defensive; same key isn't
		// re-registered while in flight because duplicates block on done).
		if cur, ok := c.entries[idempotencyKey]; ok && cur == e {
			delete(c.entries, idempotencyKey)
		}
		c.mu.Unlock()
		e.err = err
		close(e.done)
		return nil, err
	}

	e.result = &cachedSign{
		// SessionID derived from the canonical hash → stable across retries.
		SessionID: "sign-" + canon[:32],
		Signature: assembleSignature(res),
		Status:    "signed",
	}
	close(e.done)
	return e.result, nil
}

// assembleSignature renders the wire `signature` (hex, no 0x prefix) from a
// SignResult. Prefer the combined Signature if the protocol returned one; else
// fall back to R||S (the 64-byte secp256k1 r||s), appending the recovery-bearing
// remainder only if it is already folded into Signature. R/S are already hex
// (TriggerSign hex-encodes them), so concatenating the hex strings yields the
// hex of r||s.
func assembleSignature(res *mpcapi.SignResult) string {
	if res == nil {
		return ""
	}
	if res.Signature != "" {
		return res.Signature
	}
	return res.R + res.S
}
