package transport

import (
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/luxfi/mpc/pkg/types"
)

// mapKV is the smallest thing satisfying kvstore.KVStore, so the real state
// store and key-info store run against it unchanged.
type mapKV struct {
	mu sync.Mutex
	m  map[string][]byte
}

func newMapKV() *mapKV { return &mapKV{m: map[string][]byte{}} }

func (k *mapKV) Put(key string, value []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.m[key] = value
	return nil
}

func (k *mapKV) Get(key string) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	v, ok := k.m[key]
	if !ok {
		return nil, errors.New("key not found: " + key)
	}
	return v, nil
}

func (k *mapKV) Delete(key string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.m, key)
	return nil
}

func (k *mapKV) Close() error  { return nil }
func (k *mapKV) Backup() error { return nil }

func newTestKeyInfoStore() (*KeyInfoStore, *mapKV) {
	kv := newMapKV()
	return NewKeyInfoStore(NewStateStore(kv, nil, "node-a"), "node-a"), kv
}

// TestRegisterKeyCarriesBothCurves is the point of the record's shape: one
// keygen mints a key on each curve, and both survive on one wallet.
func TestRegisterKeyCarriesBothCurves(t *testing.T) {
	store, _ := newTestKeyInfoStore()

	if err := store.RegisterKey("w1", 2, "ecdsa-pub", "eddsa-pub", nil); err != nil {
		t.Fatalf("RegisterKey: %v", err)
	}
	info, err := store.Get("w1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	for keyType, want := range map[types.KeyType]string{
		types.KeyTypeSecp256k1: "ecdsa-pub",
		types.KeyTypeEd25519:   "eddsa-pub",
	} {
		got, ok := info.PublicKeyFor(keyType)
		if !ok || got != want {
			t.Errorf("PublicKeyFor(%s) = %q,%v; want %q,true", keyType, got, ok, want)
		}
	}
	// sr25519 has no keygen leg, so the honest answer is "absent".
	if _, ok := info.PublicKeyFor(types.KeyTypeSR25519); ok {
		t.Error("PublicKeyFor(sr25519) claimed a key exists; no leg mints one")
	}
	if info.Threshold != 2 {
		t.Errorf("threshold = %d, want 2", info.Threshold)
	}
}

// TestRegisterKeyMergesAcrossTheTwoWrites pins the reason RegisterKey merges.
// A wallet's record is written twice during one keygen — by the ceremony, which
// knows the threshold and no keys, and by the keygen result, which knows the
// keys and arrives later. Whichever runs last must not erase the other.
func TestRegisterKeyMergesAcrossTheTwoWrites(t *testing.T) {
	t.Run("ceremony then result", func(t *testing.T) {
		store, _ := newTestKeyInfoStore()
		if err := store.RegisterKey("w1", 3, "", "", nil); err != nil { // ConsensusKeyInfoStore.Save
			t.Fatal(err)
		}
		if err := store.RegisterKey("w1", 3, "ecdsa-pub", "eddsa-pub", nil); err != nil { // TriggerKeygen
			t.Fatal(err)
		}
		info, err := store.Get("w1")
		if err != nil {
			t.Fatal(err)
		}
		if info.ECDSAPubKey != "ecdsa-pub" || info.EdDSAPubKey != "eddsa-pub" || info.Threshold != 3 {
			t.Fatalf("record lost a field: %+v", info)
		}
	})

	t.Run("result then a later ceremony write", func(t *testing.T) {
		store, _ := newTestKeyInfoStore()
		if err := store.RegisterKey("w1", 3, "ecdsa-pub", "eddsa-pub", nil); err != nil {
			t.Fatal(err)
		}
		// A reshare re-saves the threshold and knows no public keys. The keys
		// must survive: a wallet that "loses" its Ed25519 key here is a wallet
		// that silently stops being able to sign for Solana.
		if err := store.RegisterKey("w1", 4, "", "", nil); err != nil {
			t.Fatal(err)
		}
		info, err := store.Get("w1")
		if err != nil {
			t.Fatal(err)
		}
		if info.ECDSAPubKey != "ecdsa-pub" || info.EdDSAPubKey != "eddsa-pub" {
			t.Fatalf("a threshold-only write erased the key set: %+v", info)
		}
		if info.Threshold != 4 {
			t.Fatalf("threshold = %d, want the updated 4", info.Threshold)
		}
	})
}

// TestRecordWithoutKeysDeniesNothing is the guard against the regression that
// would have been invisible until production: every wallet minted before key
// sets were recorded has a record with no public keys. Reading that silence as
// "this wallet has no keys" would refuse all of them.
func TestRecordWithoutKeysDeniesNothing(t *testing.T) {
	store, kv := newTestKeyInfoStore()

	// A record exactly as the previous code wrote it: a scalar key type, a
	// threshold, and no public keys.
	legacy := []byte(`{"wallet_id":"w-old","key_type":"secp256k1","threshold":2,` +
		`"public_key":"","eddsa_key":"","node_id":"node-a"}`)
	if err := kv.Put("mpc/keys/w-old", legacy); err != nil {
		t.Fatal(err)
	}

	info, err := store.Get("w-old")
	if err != nil {
		t.Fatalf("a record written by the previous code must still read: %v", err)
	}
	if info.Threshold != 2 {
		t.Errorf("threshold = %d, want 2 — the record must still carry it", info.Threshold)
	}
	if info.RecordsCurves() {
		t.Error("a record with no public keys must not claim to name curves")
	}
	// And the now-absent scalar key type must not resurface through any field.
	var raw map[string]any
	if err := json.Unmarshal(legacy, &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["key_type"]; !ok {
		t.Fatal("test fixture is wrong: it should carry the old scalar key_type")
	}
	blob, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	var rewritten map[string]any
	if err := json.Unmarshal(blob, &rewritten); err != nil {
		t.Fatal(err)
	}
	if _, ok := rewritten["key_type"]; ok {
		t.Error("KeyInfo still serializes a scalar key_type; a wallet has one key per curve")
	}
}
