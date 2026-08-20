package main

// The fan-out and the fan-in, over a bus a test controls.
//
// pkg/reveal proves the cryptography. This proves the wiring around it: that a
// request reaches every node, that each answers from its own store, that the
// asking node waits for a real quorum, and that it stops waiting once it has
// one. Those are the parts a live ring would otherwise be the only place to
// find a mistake in.

import (
	"bytes"
	"context"
	"crypto/rand"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/frost"
	tr "github.com/luxfi/threshold/protocols/reveal"
	"github.com/nats-io/nats.go"

	"github.com/luxfi/mpc/internal/ceremony"
	"github.com/luxfi/mpc/pkg/messaging"
	"github.com/luxfi/mpc/pkg/mpc"
)

const (
	revealOrg = "hanzo"
	revealKey = "rek-v1"
)

// bus delivers to every subscriber whose topic matches, wildcard included. It
// is the whole of what these two halves need from a message bus.
type bus struct {
	mu   sync.Mutex
	subs []*sub
}

type sub struct {
	topic  string
	handle func(*nats.Msg)
	b      *bus
	off    bool
}

func (s *sub) Unsubscribe() error { s.b.mu.Lock(); s.off = true; s.b.mu.Unlock(); return nil }

func (b *bus) Subscribe(topic string, h func(*nats.Msg)) (messaging.Subscription, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := &sub{topic: topic, handle: h, b: b}
	b.subs = append(b.subs, s)
	return s, nil
}

func (b *bus) Publish(topic string, data []byte) error {
	b.mu.Lock()
	targets := make([]*sub, 0, len(b.subs))
	for _, s := range b.subs {
		if !s.off && matches(s.topic, topic) {
			targets = append(targets, s)
		}
	}
	b.mu.Unlock()
	for _, s := range targets {
		s.handle(&nats.Msg{Subject: topic, Data: append([]byte(nil), data...)})
	}
	return nil
}

func (b *bus) PublishWithReply(topic, _ string, data []byte, _ map[string]string) error {
	return b.Publish(topic, data)
}

// matches is NATS subject matching, only as far as the one wildcard these
// topics use: a trailing "*" standing for exactly one segment.
func matches(pattern, topic string) bool {
	if pattern == topic {
		return true
	}
	if !strings.HasSuffix(pattern, ".*") {
		return false
	}
	head := strings.TrimSuffix(pattern, "*")
	return strings.HasPrefix(topic, head) && !strings.Contains(topic[len(head):], ".")
}

// shelf is one node's store.
type shelf struct {
	mu   sync.Mutex
	held map[string][]byte
}

func newShelf() *shelf { return &shelf{held: map[string][]byte{}} }

func (s *shelf) Put(k string, v []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.held[k] = append([]byte(nil), v...)
	return nil
}

func (s *shelf) Get(k string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.held[k], nil
}

func (s *shelf) Delete(k string) error { delete(s.held, k); return nil }
func (s *shelf) Close() error          { return nil }
func (s *shelf) Backup() error         { return nil }

// ring runs the real Ed25519 keygen, gives each party its own store, and starts
// each one answering on the shared bus.
func committee(t *testing.T, threshold int) (*bus, []*shelf, *frost.Config) {
	t.Helper()
	ids := ceremony.Parties()

	results, err := ceremony.Run(ids, []byte("mpcd-reveal"), func(id party.ID) protocol.StartFunc {
		return frost.KeygenEd25519(id, ids, threshold)
	})
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	b := &bus{}
	var stores []*shelf
	var any *frost.Config
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	for id, r := range results {
		cfg := r.(*frost.Config)
		raw, err := mpc.MarshalEd25519Config(cfg)
		if err != nil {
			t.Fatal(err)
		}
		s := newShelf()
		if err := s.Put(mpc.OrgScopedKey(revealOrg, mpc.Ed25519ShareKey(revealKey)), raw); err != nil {
			t.Fatal(err)
		}
		if err := serveReveal(ctx, b, s, string(id)); err != nil {
			t.Fatal(err)
		}
		stores = append(stores, s)
		any = cfg
	}
	return b, stores, any
}

func sealed(t *testing.T, cfg *frost.Config, secret []byte) []byte {
	t.Helper()
	ct, err := tr.Encrypt(rand.Reader, cfg.PublicKey, secret)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ct.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The whole path: one node asks, every node answers from its own share, and the
// asking node reassembles a root none of them could have produced alone.
func TestARootTravelsTheRingAndComesBack(t *testing.T) {
	b, stores, cfg := committee(t, 2)

	root := make([]byte, 32)
	if _, err := rand.Read(root); err != nil {
		t.Fatal(err)
	}
	ct := sealed(t, cfg, root)

	got, err := openReveal(b, stores[0], "asker", revealOrg, revealKey, ct)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, root) {
		t.Fatal("the root did not come back")
	}
}

// It returns as soon as a quorum answers, rather than waiting out the deadline.
// A boot that blocks twenty seconds on a key it already has is a boot that will
// be given a shorter deadline by whoever is waiting, and then it will fail.
func TestItStopsWaitingOnceItHasEnough(t *testing.T) {
	b, stores, cfg := committee(t, 2)
	ct := sealed(t, cfg, []byte("a root"))

	start := time.Now()
	if _, err := openReveal(b, stores[0], "asker", revealOrg, revealKey, ct); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > revealDeadline/2 {
		t.Fatalf("waited %s of a %s deadline after a quorum had answered", elapsed, revealDeadline)
	}
}

// A ring that cannot muster a quorum says how many answered and why, rather
// than failing as an opaque timeout.
func TestNotEnoughNodesSaysSoAndWhy(t *testing.T) {
	_, stores, cfg := committee(t, 2)
	ct := sealed(t, cfg, []byte("a root"))

	// A bus nobody answers on, except one node that holds no share at all.
	quiet := &bus{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := serveReveal(ctx, quiet, newShelf(), "empty-node"); err != nil {
		t.Fatal(err)
	}

	_, err := openReveal(quiet, stores[0], "asker", revealOrg, revealKey, ct)
	if err == nil {
		t.Fatal("an opening succeeded with no quorum")
	}
	if !strings.Contains(err.Error(), "of 3 answered") {
		t.Fatalf("the failure does not say how many answered: %v", err)
	}
	if !strings.Contains(err.Error(), "empty-node") {
		t.Fatalf("the failure does not name the node that refused: %v", err)
	}
}

// An opening with nothing to open, or no key to open it under, is refused
// before it reaches the ring.
func TestAnEmptyRequestNeverReachesTheRing(t *testing.T) {
	b, stores, _ := committee(t, 2)

	for _, bad := range []struct {
		what     string
		org, key string
		ct       []byte
	}{
		{"no ciphertext", revealOrg, revealKey, nil},
		{"no key", revealOrg, "", []byte("x")},
		{"no org", "", revealKey, []byte("x")},
	} {
		if _, err := openReveal(b, stores[0], "asker", bad.org, bad.key, bad.ct); err == nil {
			t.Fatalf("%s was accepted", bad.what)
		}
	}
}
