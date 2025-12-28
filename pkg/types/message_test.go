package types

import (
	"crypto/ed25519"
	"testing"
)

func TestMessage_SignAndVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	msg := &Message{
		SessionID:    "session-1",
		SenderID:     "node0:keygen:1",
		SenderNodeID: "node0",
		RecipientIDs: []string{"node1", "node2"},
		Body:         []byte("hello protocol"),
		IsBroadcast:  true,
	}

	msg.Sign(priv)
	if len(msg.Signature) == 0 {
		t.Fatal("signature should not be empty after signing")
	}

	if err := msg.Verify(pub); err != nil {
		t.Fatalf("valid signature should verify: %v", err)
	}
}

func TestMessage_VerifyRejectsWrongKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	otherPub, _, _ := ed25519.GenerateKey(nil)

	msg := &Message{
		SessionID:    "session-2",
		SenderID:     "node0",
		SenderNodeID: "node0",
		Body:         []byte("data"),
		IsBroadcast:  false,
	}

	msg.Sign(priv)

	if err := msg.Verify(otherPub); err == nil {
		t.Fatal("verify with wrong key should fail")
	}
}

func TestMessage_VerifyRejectsNoSignature(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)

	msg := &Message{
		SessionID: "session-3",
		Body:      []byte("unsigned"),
	}

	if err := msg.Verify(pub); err == nil {
		t.Fatal("verify with no signature should fail")
	}
}

func TestMessage_VerifyRejectsTamperedBody(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)

	msg := &Message{
		SessionID: "session-4",
		Body:      []byte("original"),
	}

	msg.Sign(priv)

	// Tamper with the body
	msg.Body = []byte("tampered")

	if err := msg.Verify(pub); err == nil {
		t.Fatal("verify should fail after body tampering")
	}
}
