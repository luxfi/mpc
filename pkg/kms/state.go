// state.go — durable nonce + epoch state for ReleaseGate.
//
// The release gate must defend against:
//
//  1. Nonce confusion — a worker presenting a nonce never issued by this
//     gate, or one issued for a different (jobID, epoch) tuple.
//  2. Replay across restart — a KMS process restart must NOT reset the
//     replay window. State persists; nonces survive.
//  3. Cross-job collision — two Issue() calls with the same jobID +
//     epoch must be impossible (jobID dedup) and the AAD must bind the
//     issued nonce so a stale sealed key cannot be reinterpreted.
//
// NonceStore is the persistence seam. Two implementations:
//
//   - MemoryNonceStore — in-process map, suitable for tests and single-
//     process dev. Resets on restart (does NOT survive crashes).
//   - DatabaseNonceStore — backed by a luxfi/database.Database (Hanzo
//     Base / ZapDB / encdb). Survives restart, GC reclaims expired
//     entries.
//
// Both satisfy the same interface; LocalReleaseGate composes either.
package kms

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/luxfi/database"
)

// Errors surfaced by the store + gate. Callers MUST distinguish — a
// mismatch is a hard refusal, expiry is a soft refusal (re-issue).
var (
	ErrNonceUnknown    = errors.New("kms/release: nonce unknown for jobID")
	ErrNonceMismatch   = errors.New("kms/release: nonce mismatch for jobID")
	ErrAlreadyConsumed = errors.New("kms/release: jobID already consumed")
	ErrExpired         = errors.New("kms/release: nonce expired")
)

// NonceRecord is the full row stored per pending Issue. JobID is the
// primary key; nonce + epoch + expiry travel together so Lookup is
// single-shot.
type NonceRecord struct {
	JobID   [32]byte  `json:"job_id"`
	Nonce   [32]byte  `json:"nonce"`
	Epoch   uint64    `json:"epoch"`
	Expires time.Time `json:"expires"`
}

// NonceStore persists pending nonces (Issue → unconsumed) and tracks
// consumed jobIDs for the replay window.
//
// Semantics:
//   - Issue stores (jobID, nonce, epoch, expires). Two Issues with the
//     same jobID at the same epoch MUST collide (the gate dedupes
//     before calling, but the store enforces too).
//   - Lookup returns the issued record or ErrNonceUnknown.
//   - Consume atomically removes a pending record AND marks the jobID
//     consumed for the replay window. A subsequent Lookup or Consume
//     with the same jobID returns ErrAlreadyConsumed.
//   - GC drops both pending and consumed records older than `now`.
//   - Epoch{Get,Set} persist the gate's current epoch across restarts.
type NonceStore interface {
	Issue(rec NonceRecord) error
	Lookup(jobID [32]byte) (NonceRecord, error)
	Consume(jobID [32]byte, replayUntil time.Time) error
	GC(now time.Time) error

	EpochGet() (uint64, error)
	EpochSet(epoch uint64) error

	Close() error
}

// MemoryNonceStore is a simple in-memory implementation. Resets on
// process restart — useful for unit tests and single-shot dev.
type MemoryNonceStore struct {
	mu       sync.Mutex
	pending  map[[32]byte]NonceRecord
	consumed map[[32]byte]time.Time // jobID -> replayUntil
	epoch    uint64
}

// NewMemoryNonceStore returns a zero-state in-memory store at epoch 1.
func NewMemoryNonceStore() *MemoryNonceStore {
	return &MemoryNonceStore{
		pending:  make(map[[32]byte]NonceRecord),
		consumed: make(map[[32]byte]time.Time),
		epoch:    1,
	}
}

func (m *MemoryNonceStore) Issue(rec NonceRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t, ok := m.consumed[rec.JobID]; ok && time.Now().Before(t) {
		return fmt.Errorf("%w: jobID in consumed-set", ErrAlreadyConsumed)
	}
	if _, ok := m.pending[rec.JobID]; ok {
		return fmt.Errorf("%w: jobID already pending", ErrAlreadyConsumed)
	}
	m.pending[rec.JobID] = rec
	return nil
}

func (m *MemoryNonceStore) Lookup(jobID [32]byte) (NonceRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t, ok := m.consumed[jobID]; ok && time.Now().Before(t) {
		return NonceRecord{}, ErrAlreadyConsumed
	}
	rec, ok := m.pending[jobID]
	if !ok {
		return NonceRecord{}, ErrNonceUnknown
	}
	if time.Now().After(rec.Expires) {
		return NonceRecord{}, ErrExpired
	}
	return rec, nil
}

func (m *MemoryNonceStore) Consume(jobID [32]byte, replayUntil time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.pending[jobID]; !ok {
		return ErrNonceUnknown
	}
	delete(m.pending, jobID)
	m.consumed[jobID] = replayUntil
	return nil
}

func (m *MemoryNonceStore) GC(now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, rec := range m.pending {
		if now.After(rec.Expires) {
			delete(m.pending, k)
		}
	}
	for k, until := range m.consumed {
		if now.After(until) {
			delete(m.consumed, k)
		}
	}
	return nil
}

func (m *MemoryNonceStore) EpochGet() (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.epoch, nil
}

func (m *MemoryNonceStore) EpochSet(epoch uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.epoch = epoch
	return nil
}

func (m *MemoryNonceStore) Close() error { return nil }

// DatabaseNonceStore is a luxfi/database-backed implementation. Use
// with encdb-wrapped ZapDB for at-rest encryption (Hanzo Base in prod).
//
// Layout:
//
//	"kms/release/pending/<jobID>"   → JSON NonceRecord
//	"kms/release/consumed/<jobID>"  → 8-byte big-endian unix-nano replayUntil
//	"kms/release/epoch"             → 8-byte big-endian uint64
//
// All access goes through the underlying database's locking; no
// per-store mutex needed.
type DatabaseNonceStore struct {
	db database.Database
}

const (
	keyPrefixPending  = "kms/release/pending/"
	keyPrefixConsumed = "kms/release/consumed/"
	keyEpoch          = "kms/release/epoch"
)

// NewDatabaseNonceStore wraps a database.Database. The caller owns the
// lifecycle of db; Close() does NOT close the underlying database.
func NewDatabaseNonceStore(db database.Database) *DatabaseNonceStore {
	return &DatabaseNonceStore{db: db}
}

func pendingKey(jobID [32]byte) []byte {
	return append([]byte(keyPrefixPending), jobID[:]...)
}

func consumedKey(jobID [32]byte) []byte {
	return append([]byte(keyPrefixConsumed), jobID[:]...)
}

func (d *DatabaseNonceStore) Issue(rec NonceRecord) error {
	// Reject if already consumed within replay window.
	if v, err := d.db.Get(consumedKey(rec.JobID)); err == nil && len(v) == 8 {
		until := time.Unix(0, int64(binary.BigEndian.Uint64(v)))
		if time.Now().Before(until) {
			return fmt.Errorf("%w: jobID in consumed-set", ErrAlreadyConsumed)
		}
	} else if err != nil && !errors.Is(err, database.ErrNotFound) {
		return fmt.Errorf("kms/release: consumed lookup: %w", err)
	}
	// Reject if already pending.
	if _, err := d.db.Get(pendingKey(rec.JobID)); err == nil {
		return fmt.Errorf("%w: jobID already pending", ErrAlreadyConsumed)
	} else if !errors.Is(err, database.ErrNotFound) {
		return fmt.Errorf("kms/release: pending lookup: %w", err)
	}
	buf, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("kms/release: marshal: %w", err)
	}
	if err := d.db.Put(pendingKey(rec.JobID), buf); err != nil {
		return fmt.Errorf("kms/release: put pending: %w", err)
	}
	return nil
}

func (d *DatabaseNonceStore) Lookup(jobID [32]byte) (NonceRecord, error) {
	if v, err := d.db.Get(consumedKey(jobID)); err == nil && len(v) == 8 {
		until := time.Unix(0, int64(binary.BigEndian.Uint64(v)))
		if time.Now().Before(until) {
			return NonceRecord{}, ErrAlreadyConsumed
		}
	} else if err != nil && !errors.Is(err, database.ErrNotFound) {
		return NonceRecord{}, fmt.Errorf("kms/release: consumed lookup: %w", err)
	}
	buf, err := d.db.Get(pendingKey(jobID))
	if errors.Is(err, database.ErrNotFound) {
		return NonceRecord{}, ErrNonceUnknown
	}
	if err != nil {
		return NonceRecord{}, fmt.Errorf("kms/release: pending lookup: %w", err)
	}
	var rec NonceRecord
	if err := json.Unmarshal(buf, &rec); err != nil {
		return NonceRecord{}, fmt.Errorf("kms/release: unmarshal: %w", err)
	}
	if time.Now().After(rec.Expires) {
		return NonceRecord{}, ErrExpired
	}
	return rec, nil
}

func (d *DatabaseNonceStore) Consume(jobID [32]byte, replayUntil time.Time) error {
	if _, err := d.db.Get(pendingKey(jobID)); err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return ErrNonceUnknown
		}
		return fmt.Errorf("kms/release: pending lookup: %w", err)
	}
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(replayUntil.UnixNano()))
	if err := d.db.Put(consumedKey(jobID), ts[:]); err != nil {
		return fmt.Errorf("kms/release: put consumed: %w", err)
	}
	if err := d.db.Delete(pendingKey(jobID)); err != nil {
		return fmt.Errorf("kms/release: delete pending: %w", err)
	}
	return nil
}

func (d *DatabaseNonceStore) GC(now time.Time) error {
	it := d.db.NewIterator()
	defer it.Release()
	pendingPfx := []byte(keyPrefixPending)
	consumedPfx := []byte(keyPrefixConsumed)
	var toDelete [][]byte
	for it.Next() {
		k := it.Key()
		v := it.Value()
		switch {
		case bytes.HasPrefix(k, pendingPfx):
			var rec NonceRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				continue
			}
			if now.After(rec.Expires) {
				kk := make([]byte, len(k))
				copy(kk, k)
				toDelete = append(toDelete, kk)
			}
		case bytes.HasPrefix(k, consumedPfx):
			if len(v) != 8 {
				continue
			}
			until := time.Unix(0, int64(binary.BigEndian.Uint64(v)))
			if now.After(until) {
				kk := make([]byte, len(k))
				copy(kk, k)
				toDelete = append(toDelete, kk)
			}
		}
	}
	if err := it.Error(); err != nil {
		return fmt.Errorf("kms/release: gc iterator: %w", err)
	}
	for _, k := range toDelete {
		if err := d.db.Delete(k); err != nil {
			return fmt.Errorf("kms/release: gc delete: %w", err)
		}
	}
	return nil
}

func (d *DatabaseNonceStore) EpochGet() (uint64, error) {
	v, err := d.db.Get([]byte(keyEpoch))
	if errors.Is(err, database.ErrNotFound) {
		return 1, nil
	}
	if err != nil {
		return 0, fmt.Errorf("kms/release: epoch get: %w", err)
	}
	if len(v) != 8 {
		return 0, fmt.Errorf("kms/release: epoch corrupt (len=%d)", len(v))
	}
	return binary.BigEndian.Uint64(v), nil
}

func (d *DatabaseNonceStore) EpochSet(epoch uint64) error {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], epoch)
	if err := d.db.Put([]byte(keyEpoch), b[:]); err != nil {
		return fmt.Errorf("kms/release: epoch set: %w", err)
	}
	return nil
}

func (d *DatabaseNonceStore) Close() error { return nil }
