package reveal

import (
	"bytes"
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/frost"
	tr "github.com/luxfi/threshold/protocols/reveal"

	"github.com/luxfi/mpc/internal/ceremony"
	"github.com/luxfi/mpc/pkg/mpc"
)

const (
	testOrg    = "hanzo"
	testWallet = "rek-v1"
)

// shelf is one node's local store. Each node in a test gets its own, because
// the point of the exercise is that no single one of them holds enough.
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

// committee runs the real Ed25519 keygen and gives each party its own store,
// written through the production codec at the production key. Anything less
// would test this package against shares it dealt itself.
func committee(t *testing.T, threshold int) (map[party.ID]*shelf, *frost.Config) {
	t.Helper()
	ids := ceremony.Parties()

	results, err := ceremony.Run(ids, []byte("reveal-committee"), func(id party.ID) protocol.StartFunc {
		return frost.KeygenEd25519(id, ids, threshold)
	})
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	stores := make(map[party.ID]*shelf, len(ids))
	var any *frost.Config
	for id, r := range results {
		cfg, ok := r.(*frost.Config)
		if !ok {
			t.Fatalf("party %s produced %T", id, r)
		}
		raw, err := mpc.MarshalEd25519Config(cfg)
		if err != nil {
			t.Fatal(err)
		}
		s := newShelf()
		if err := s.Put(mpc.OrgScopedKey(testOrg, mpc.Ed25519ShareKey(testWallet)), raw); err != nil {
			t.Fatal(err)
		}
		stores[id] = s
		any = cfg
	}
	return stores, any
}

func sealTo(t *testing.T, cfg *frost.Config, secret []byte) []byte {
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

// A root sealed to the committee comes back when enough of them answer, and the
// answers come from separate stores holding separate shares.
func TestTheCommitteeOpensARootNoNodeCouldOpen(t *testing.T) {
	stores, cfg := committee(t, 2)

	root := make([]byte, 32)
	if _, err := rand.Read(root); err != nil {
		t.Fatal(err)
	}
	ct := sealTo(t, cfg, root)

	var answers [][]byte
	var combiner *shelf
	for _, s := range stores {
		a, err := Answer(s, testOrg, testWallet, ct)
		if err != nil {
			t.Fatalf("answer: %v", err)
		}
		answers = append(answers, a)
		combiner = s
	}

	got, err := Combine(combiner, testOrg, testWallet, ct, answers)
	if err != nil {
		t.Fatalf("combine: %v", err)
	}
	if !bytes.Equal(got, root) {
		t.Fatal("the root did not come back")
	}
}

// THE PROPERTY. Fewer answers than the share set requires opens nothing, so a
// node — or an attacker holding one — learns nothing from its own share.
func TestTooFewNodesOpenNothing(t *testing.T) {
	stores, cfg := committee(t, 2)
	ct := sealTo(t, cfg, []byte("a root nobody gets"))

	var answers [][]byte
	var combiner *shelf
	for _, s := range stores {
		if len(answers) == 2 {
			break
		}
		a, err := Answer(s, testOrg, testWallet, ct)
		if err != nil {
			t.Fatal(err)
		}
		answers = append(answers, a)
		combiner = s
	}

	if _, err := Combine(combiner, testOrg, testWallet, ct, answers[:1]); err == nil {
		t.Fatal("one answer opened it")
	}
	if _, err := Combine(combiner, testOrg, testWallet, ct, answers); err == nil {
		t.Fatal("two answers opened a set needing three")
	}
}

// A node with no share for the key says so, rather than staying silent or
// answering with something that would fail three frames later.
func TestANodeWithoutTheShareSaysSo(t *testing.T) {
	stores, cfg := committee(t, 2)
	ct := sealTo(t, cfg, []byte("x"))

	empty := newShelf()
	_, err := Answer(empty, testOrg, testWallet, ct)
	if !errors.Is(err, ErrNoShare) {
		t.Fatalf("want ErrNoShare, got %v", err)
	}

	// And a node that holds the share for one org does not hold it for another.
	for _, s := range stores {
		if _, err := Answer(s, "someone-else", testWallet, ct); !errors.Is(err, ErrNoShare) {
			t.Fatalf("a share answered for another org: %v", err)
		}
		break
	}
}

// Nonsense from one party costs that party its seat and nothing more, so a
// single bad actor cannot deny the whole opening.
func TestOneBadAnswerDoesNotStopTheRest(t *testing.T) {
	stores, cfg := committee(t, 2)
	root := []byte("the root")
	ct := sealTo(t, cfg, root)

	answers := [][]byte{[]byte("not an answer at all")}
	var combiner *shelf
	for _, s := range stores {
		a, err := Answer(s, testOrg, testWallet, ct)
		if err != nil {
			t.Fatal(err)
		}
		answers = append(answers, a)
		combiner = s
	}

	got, err := Combine(combiner, testOrg, testWallet, ct, answers)
	if err != nil {
		t.Fatalf("a malformed answer stopped a quorum: %v", err)
	}
	if !bytes.Equal(got, root) {
		t.Fatal("the root did not come back")
	}
}

// The share set's own threshold decides the quorum. A request cannot ask for a
// smaller one, because it never carries one.
func TestTheQuorumComesFromTheShareSet(t *testing.T) {
	stores, cfg := committee(t, 2)
	if cfg.Threshold != 2 {
		t.Fatalf("keygen recorded threshold %d, want 2", cfg.Threshold)
	}
	ct := sealTo(t, cfg, []byte("x"))

	for _, s := range stores {
		// One answer, from the node that also combines: the most favourable
		// case an attacker holding a single node could construct.
		a, err := Answer(s, testOrg, testWallet, ct)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Combine(s, testOrg, testWallet, ct, [][]byte{a})
		if err == nil {
			t.Fatal("a single node opened the secret")
		}
		if !strings.Contains(err.Error(), "not enough") {
			t.Fatalf("want a quorum refusal, got %v", err)
		}
		break
	}
}

// The group key is public: handing it out lets anyone seal and nobody open.
func TestThePublicKeyIsTheOneSealedTo(t *testing.T) {
	stores, cfg := committee(t, 2)
	for _, s := range stores {
		got, err := PublicKey(s, testOrg, testWallet)
		if err != nil {
			t.Fatal(err)
		}
		if !got.Equal(cfg.PublicKey) {
			t.Fatal("a node reports a different group key than the keygen produced")
		}
	}
}
