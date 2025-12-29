// Package audit provides an append-only audit log with a Merkle hash chain.
//
// Every Event carries: a sequence number, the SHA-256 of the previous event,
// and the SHA-256 of the canonical bytes of (PrevHash || SerializedPayload).
// Tampering with any historical event invalidates every subsequent hash, so
// verification reduces to recomputing the chain.
//
// The Dispatcher interface lets the same chain be persisted to different
// targets — the local WORM file, the Lux M-Chain anchor RPC, S3 Glacier
// Vault Lock, Azure Immutable Blob Storage, or GCS Object Lock. Mode
// selection happens once at startup via NewDispatcher; the rest of the
// daemon only sees the interface.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// EventKind enumerates the audit event types emitted by mpcd.
//
// Keep this list closed: adding a kind is a wire-protocol change and must
// be coordinated with verifiers. New kinds go at the end of the constant
// block to preserve any external numeric ordering.
type EventKind string

const (
	KindKeygen      EventKind = "keygen"
	KindSign        EventKind = "sign"
	KindReshare     EventKind = "reshare"
	KindBackup      EventKind = "backup"
	KindBootstrap   EventKind = "bootstrap"
	KindPeerJoin    EventKind = "peer_join"
	KindPeerLeave   EventKind = "peer_leave"
	KindPolicyApply EventKind = "policy_apply"
)

// Event is one entry in the audit log.
//
// The Hash field is the SHA-256 of canonical(PrevHash || Seq || NodeID ||
// Kind || OrgID || WalletID || Timestamp || Payload). It is computed by
// Seal and never set by callers; ComputeHash will reject an Event with a
// pre-populated Hash to prevent forgery.
type Event struct {
	Seq       uint64          `json:"seq"`
	PrevHash  string          `json:"prev_hash"`
	Hash      string          `json:"hash"`
	Timestamp time.Time       `json:"ts"`
	NodeID    string          `json:"node_id"`
	Kind      EventKind       `json:"kind"`
	OrgID     string          `json:"org_id,omitempty"`
	WalletID  string          `json:"wallet_id,omitempty"`
	Payload   json.RawMessage `json:"payload,omitempty"`
}

// canonicalBytes returns the bytes that go into the SHA-256 for Hash.
// Order is fixed: prev || seq(8 BE) || node || kind || org || wallet ||
// unix-nano(8 BE) || payload. We intentionally do NOT use json.Marshal
// here because Go's map iteration ordering would defeat reproducibility.
func (e *Event) canonicalBytes() []byte {
	prev, _ := hex.DecodeString(e.PrevHash)
	buf := make([]byte, 0, 256+len(e.Payload))
	buf = append(buf, prev...)
	buf = appendUint64BE(buf, e.Seq)
	buf = append(buf, []byte(e.NodeID)...)
	buf = append(buf, byte(0)) // separator — NodeID may be empty
	buf = append(buf, []byte(e.Kind)...)
	buf = append(buf, byte(0))
	buf = append(buf, []byte(e.OrgID)...)
	buf = append(buf, byte(0))
	buf = append(buf, []byte(e.WalletID)...)
	buf = append(buf, byte(0))
	buf = appendUint64BE(buf, uint64(e.Timestamp.UnixNano()))
	buf = append(buf, e.Payload...)
	return buf
}

// ComputeHash returns the canonical SHA-256 hex of e. e.Hash must be empty.
func (e *Event) ComputeHash() (string, error) {
	if e.Hash != "" {
		return "", fmt.Errorf("audit: event already sealed (Hash=%q)", e.Hash)
	}
	sum := sha256.Sum256(e.canonicalBytes())
	return hex.EncodeToString(sum[:]), nil
}

// Seal sets Seq, PrevHash, Timestamp (if zero) and Hash on e.
// Mutates e and returns it.
func (e *Event) Seal(seq uint64, prevHash string) (*Event, error) {
	e.Seq = seq
	e.PrevHash = prevHash
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	h, err := e.ComputeHash()
	if err != nil {
		return nil, err
	}
	e.Hash = h
	return e, nil
}

// VerifyChain walks events in order and confirms each Hash chains to its
// PrevHash. Returns the index of the first inconsistent event, or -1 if
// the whole slice is intact.
func VerifyChain(events []*Event) (int, error) {
	prev := ""
	for i, ev := range events {
		if ev.PrevHash != prev {
			return i, fmt.Errorf("audit: event %d prev=%q expected %q", i, ev.PrevHash, prev)
		}
		want := ev.Hash
		ev.Hash = "" // recompute requires empty
		got, err := ev.ComputeHash()
		ev.Hash = want
		if err != nil {
			return i, err
		}
		if got != want {
			return i, fmt.Errorf("audit: event %d hash=%q recomputed %q", i, want, got)
		}
		prev = want
	}
	return -1, nil
}

func appendUint64BE(b []byte, v uint64) []byte {
	return append(b,
		byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
		byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}
