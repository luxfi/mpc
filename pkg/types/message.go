package types

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
)

// Message represents a protocol message
type Message struct {
	SessionID    string   `json:"session_id"`
	SenderID     string   `json:"sender_id"`
	SenderNodeID string   `json:"sender_node_id,omitempty"` // Raw node ID for key lookup
	RecipientIDs []string `json:"recipient_ids"`
	Body         []byte   `json:"body"`
	IsBroadcast  bool     `json:"is_broadcast"`
	Signature    []byte   `json:"signature,omitempty"` // Ed25519 signature over signable fields
}

// SignableBytes returns a deterministic byte representation of the message
// fields that are covered by the signature. The signature field itself is
// excluded.
func (m *Message) SignableBytes() []byte {
	h := sha256.New()
	h.Write([]byte(m.SessionID))
	h.Write([]byte(m.SenderID))
	h.Write([]byte(m.SenderNodeID))
	for _, r := range m.RecipientIDs {
		h.Write([]byte(r))
	}
	h.Write(m.Body)
	if m.IsBroadcast {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}
	return h.Sum(nil)
}

// Sign signs the message with the given Ed25519 private key.
func (m *Message) Sign(privateKey ed25519.PrivateKey) {
	m.Signature = ed25519.Sign(privateKey, m.SignableBytes())
}

// Verify checks the message signature against the given Ed25519 public key.
func (m *Message) Verify(publicKey ed25519.PublicKey) error {
	if len(m.Signature) == 0 {
		return fmt.Errorf("message has no signature")
	}
	if !ed25519.Verify(publicKey, m.SignableBytes(), m.Signature) {
		return fmt.Errorf("invalid message signature from %s", m.SenderNodeID)
	}
	return nil
}
