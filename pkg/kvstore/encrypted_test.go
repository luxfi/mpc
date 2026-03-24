package kvstore

import (
	"bytes"
	"testing"
)

type memKV struct {
	data map[string][]byte
}

func newMemKV() *memKV                        { return &memKV{data: make(map[string][]byte)} }
func (m *memKV) Put(k string, v []byte) error { m.data[k] = v; return nil }
func (m *memKV) Get(k string) ([]byte, error) { return m.data[k], nil }
func (m *memKV) Delete(k string) error        { delete(m.data, k); return nil }
func (m *memKV) Close() error                 { return nil }
func (m *memKV) Backup() error                { return nil }

func TestEncryptedKVStoreRoundtrip(t *testing.T) {
	inner := newMemKV()
	key := DeriveUserKey([]byte("master-secret-key-for-testing!!"), "acme", "user001")

	store, err := NewEncryptedKVStore(inner, key)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("this is a secret MPC key share shard data")
	if err := store.Put("org:acme:wallet_001", plaintext); err != nil {
		t.Fatal(err)
	}

	// Verify the underlying store has encrypted (different) data
	raw := inner.data["org:acme:wallet_001"]
	if bytes.Equal(raw, plaintext) {
		t.Error("underlying store has plaintext — encryption not working")
	}
	if len(raw) == 0 {
		t.Error("underlying store is empty")
	}

	// Decrypt via the encrypted store
	decrypted, err := store.Get("org:acme:wallet_001")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestDifferentUsersGetDifferentKeys(t *testing.T) {
	master := []byte("master-secret-key-for-testing!!")
	key1 := DeriveUserKey(master, "acme", "user001")
	key2 := DeriveUserKey(master, "acme", "user002")
	key3 := DeriveUserKey(master, "beta", "user001")

	if bytes.Equal(key1, key2) {
		t.Error("same org, different users should get different keys")
	}
	if bytes.Equal(key1, key3) {
		t.Error("different orgs, same user ID should get different keys")
	}
	if bytes.Equal(key2, key3) {
		t.Error("different org+user combos should get different keys")
	}
}

func TestWrongKeyCannotDecrypt(t *testing.T) {
	inner := newMemKV()
	master := []byte("master-secret-key-for-testing!!")

	store1, _ := NewEncryptedKVStore(inner, DeriveUserKey(master, "acme", "user001"))
	store2, _ := NewEncryptedKVStore(inner, DeriveUserKey(master, "acme", "user002"))

	plaintext := []byte("user001's secret shard")
	store1.Put("shard_001", plaintext)

	// user002's key cannot decrypt user001's data
	_, err := store2.Get("shard_001")
	if err == nil {
		t.Error("expected decryption error with wrong key")
	}
}

func TestEmptyValueRoundtrip(t *testing.T) {
	inner := newMemKV()
	key := DeriveUserKey([]byte("master-secret-key-for-testing!!"), "acme", "user001")
	store, _ := NewEncryptedKVStore(inner, key)

	store.Put("empty", []byte{})
	got, err := store.Get("empty")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty, got %d bytes", len(got))
	}
}

func TestOrgKeyDiffersFromUserKey(t *testing.T) {
	master := []byte("master-secret-key-for-testing!!")
	orgKey := DeriveOrgKey(master, "acme")
	userKey := DeriveUserKey(master, "acme", "user001")

	if bytes.Equal(orgKey, userKey) {
		t.Error("org key and user key should differ")
	}
}
