// Copyright © 2026 Lux Industries Inc. All rights reserved.

package main

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/frost"

	"github.com/luxfi/mpc/internal/ceremony"
	"github.com/luxfi/mpc/pkg/mpc"
	revealpkg "github.com/luxfi/mpc/pkg/reveal"
)

// desk is one node's local store, held in memory for the length of a test.
type desk struct {
	mu   sync.Mutex
	held map[string][]byte
}

func newDesk() *desk { return &desk{held: map[string][]byte{}} }

func (d *desk) Put(k string, v []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.held[k] = append([]byte(nil), v...)
	return nil
}

func (d *desk) Get(k string) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.held[k], nil
}

func (d *desk) Delete(k string) error { delete(d.held, k); return nil }
func (d *desk) Close() error          { return nil }
func (d *desk) Backup() error         { return nil }

const (
	deskOrg    = "hanzo"
	deskWallet = "root"
)

// keyed runs a real Ed25519 keygen and files one party's share where a node
// keeps it, so the handler reads what production would read.
func keyed(t *testing.T) (*desk, *frost.Config) {
	t.Helper()
	ids := ceremony.Parties()
	results, err := ceremony.Run(ids, []byte("group-handler"), func(id party.ID) protocol.StartFunc {
		return frost.KeygenEd25519(id, ids, 1)
	})
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	d := newDesk()
	var cfg *frost.Config
	for _, r := range results {
		c, ok := r.(*frost.Config)
		if !ok {
			t.Fatalf("party produced %T", r)
		}
		raw, err := mpc.MarshalEd25519Config(c)
		if err != nil {
			t.Fatal(err)
		}
		if err := d.Put(mpc.OrgScopedKey(deskOrg, mpc.Ed25519ShareKey(deskWallet)), raw); err != nil {
			t.Fatal(err)
		}
		cfg = c
		break
	}
	return d, cfg
}

func ask(h http.HandlerFunc, query string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h(w, httptest.NewRequest(http.MethodGet, "/group?"+query, nil))
	return w
}

// The whole point: a caller who holds no share can still learn what to seal to.
func TestTheGroupKeyIsReadableWithoutHoldingAShare(t *testing.T) {
	d, cfg := keyed(t)
	w := ask(groupHandler(d), "org="+deskOrg+"&key="+deskWallet)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d, body %s", w.Code, w.Body.String())
	}
	var got struct {
		GroupKey string `json:"group_key"`
		Quorum   int    `json:"quorum"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	want, err := cfg.PublicKey.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if got.GroupKey != hex.EncodeToString(want) {
		t.Fatalf("group key = %s, want %s", got.GroupKey, hex.EncodeToString(want))
	}
	// A key that seals but cannot be opened is worse than none, so the answer
	// says how many nodes it takes to open it.
	if got.Quorum != cfg.Threshold+1 {
		t.Fatalf("quorum = %d, want %d", got.Quorum, cfg.Threshold+1)
	}
}

// The key must be usable as-is: sealing to what this returns is the only reason
// to ask for it, so the bytes have to decode as a point on the curve.
func TestWhatItReturnsCanBeSealedTo(t *testing.T) {
	d, _ := keyed(t)
	w := ask(groupHandler(d), "org="+deskOrg+"&key="+deskWallet)
	var got struct {
		GroupKey string `json:"group_key"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString(got.GroupKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := revealpkg.Seal(raw, []byte("a root that no one node may hold")); err != nil {
		t.Fatalf("seal to the returned key: %v", err)
	}
}

func TestAKeyWithNoShareIsNotFound(t *testing.T) {
	d, _ := keyed(t)
	w := ask(groupHandler(d), "org="+deskOrg+"&key=absent")
	if w.Code != http.StatusNotFound {
		t.Fatalf("code = %d, want 404", w.Code)
	}
}

func TestOrgAndKeyAreBothRequired(t *testing.T) {
	d, _ := keyed(t)
	// %20 is a key of pure whitespace: the handler trims before it decides,
	// so a blank that arrived encoded is still a blank.
	for _, q := range []string{"", "org=" + deskOrg, "key=" + deskWallet, "org=&key=%20"} {
		if w := ask(groupHandler(d), q); w.Code != http.StatusBadRequest {
			t.Fatalf("%q → %d, want 400", q, w.Code)
		}
	}
}
