package kms

import (
	"bytes"
	"context"
	"testing"
)

func newTestClient(t *testing.T) *KMSClient {
	t.Helper()
	c, err := NewKMSClient(KMSConfig{
		ClientID:     "test-client",
		ClientSecret: "test-secret-32-chars-long-enough",
		ProjectID:    "test-project",
		Environment:  "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	c := newTestClient(t)
	plaintext := []byte("this is a secret key share")

	encrypted, err := c.encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}

	// Encrypted must differ from plaintext
	if bytes.Equal(encrypted, plaintext) {
		t.Fatal("encrypted data must differ from plaintext")
	}

	decrypted, err := c.decrypt(encrypted)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("round-trip failed: got %q, want %q", decrypted, plaintext)
	}
}

func TestStoreRetrieveKeyShare(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	walletID := "wallet-abc123"
	keyShare := []byte("ecdsa-key-share-bytes-here")

	if err := c.StoreKeyShare(ctx, walletID, keyShare); err != nil {
		t.Fatal(err)
	}

	retrieved, err := c.RetrieveKeyShare(ctx, walletID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(retrieved, keyShare) {
		t.Fatalf("got %q, want %q", retrieved, keyShare)
	}
}

func TestStoreMPCKeyShareEncrypted(t *testing.T) {
	c := newTestClient(t)
	nodeID := "node0"
	walletID := "wallet-xyz"
	keyType := "ecdsa"
	keyData := []byte("mpc-share-data-42")

	if err := c.StoreMPCKeyShare(nodeID, walletID, keyType, keyData); err != nil {
		t.Fatal(err)
	}

	// Verify internal storage is encrypted (not plaintext)
	secretName := "/mpc/nodes/node0/wallets/wallet-xyz/ecdsa"
	c.mu.RLock()
	raw := c.secrets[secretName]
	c.mu.RUnlock()
	if bytes.Equal(raw, keyData) {
		t.Fatal("internal storage must be encrypted, not plaintext")
	}

	// Retrieve should return original plaintext
	retrieved, err := c.RetrieveMPCKeyShare(nodeID, walletID, keyType)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(retrieved, keyData) {
		t.Fatalf("got %q, want %q", retrieved, keyData)
	}
}

func TestHealthcheck(t *testing.T) {
	c := newTestClient(t)
	if err := c.Healthcheck(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestBatchStoreRetrieve(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()

	secrets := map[string][]byte{
		"key1": []byte("value1"),
		"key2": []byte("value2"),
	}
	if err := c.BatchStore(ctx, secrets); err != nil {
		t.Fatal(err)
	}

	retrieved, err := c.BatchRetrieve(ctx, []string{"key1", "key2", "missing"})
	if err != nil {
		t.Fatal(err)
	}
	if len(retrieved) != 2 {
		t.Fatalf("expected 2 results, got %d", len(retrieved))
	}
	if !bytes.Equal(retrieved["key1"], []byte("value1")) {
		t.Fatalf("key1: got %q, want %q", retrieved["key1"], "value1")
	}
}

func TestStoreConfig(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()

	type cfg struct {
		Threshold int    `json:"threshold"`
		NodeID    string `json:"node_id"`
	}
	original := cfg{Threshold: 2, NodeID: "node0"}

	if err := c.StoreConfig(ctx, "node0", original); err != nil {
		t.Fatal(err)
	}

	var retrieved cfg
	if err := c.RetrieveConfig(ctx, "node0", &retrieved); err != nil {
		t.Fatal(err)
	}
	if retrieved.Threshold != 2 || retrieved.NodeID != "node0" {
		t.Fatalf("config mismatch: got %+v", retrieved)
	}
}

func TestClose(t *testing.T) {
	c := newTestClient(t)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	// Master key should be zeroed
	for _, b := range c.masterKey {
		if b != 0 {
			t.Fatal("master key not zeroed after Close")
		}
	}
	if c.secrets != nil {
		t.Fatal("secrets map not cleared after Close")
	}
}

func TestGenerateEncryptionKey(t *testing.T) {
	key, err := GenerateEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Fatalf("expected 32-byte key, got %d bytes", len(key))
	}
	// Should not be all zeros
	allZero := true
	for _, b := range key {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("generated key is all zeros")
	}
}

func TestDeleteKey(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()

	if err := c.StoreKeyShare(ctx, "w1", []byte("data")); err != nil {
		t.Fatal(err)
	}

	keys, _ := c.ListKeys()
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}

	if err := c.DeleteKey(keys[0]); err != nil {
		t.Fatal(err)
	}

	keys, _ = c.ListKeys()
	if len(keys) != 0 {
		t.Fatalf("expected 0 keys after delete, got %d", len(keys))
	}
}
