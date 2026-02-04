// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package transport provides a consensus-embedded transport layer for MPC
// that uses ZAP wire protocol instead of NATS/Consul.
package transport

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

// MPC Message Types (60-79 range in ZAP protocol)
// These extend the base ZAP message types defined in api/zap/wire.go
const (
	// MsgMPCBroadcast is used for pub/sub broadcasts to all nodes
	MsgMPCBroadcast uint8 = 60

	// MsgMPCDirect is used for point-to-point messaging
	MsgMPCDirect uint8 = 61

	// MsgMPCReady is used for peer registry readiness signaling
	MsgMPCReady uint8 = 62

	// MsgMPCSubscribe is used for subscription management
	MsgMPCSubscribe uint8 = 63

	// MsgMPCKeygen is used for DKG protocol messages
	MsgMPCKeygen uint8 = 64

	// MsgMPCSign is used for signing protocol messages
	MsgMPCSign uint8 = 65

	// MsgMPCReshare is used for key resharing protocol messages
	MsgMPCReshare uint8 = 66

	// MsgMPCResult is used for session result messages
	MsgMPCResult uint8 = 67

	// MsgMPCPing is used for health checks
	MsgMPCPing uint8 = 68

	// MsgMPCPong is the response to ping
	MsgMPCPong uint8 = 69

	// HeaderSize is 4 bytes length + 1 byte type
	HeaderSize = 5

	// MaxMessageSize is 16MB
	MaxMessageSize = 16 * 1024 * 1024
)

// Message represents an MPC protocol message
type Message struct {
	Type    uint8             `json:"type"`
	Topic   string            `json:"topic,omitempty"`
	From    string            `json:"from"`
	To      string            `json:"to,omitempty"` // Empty for broadcasts
	ReplyTo string            `json:"reply_to,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Data    []byte            `json:"data"`
}

// Envelope wraps a message with correlation ID for request/response
type Envelope struct {
	ID      uint32  `json:"id"`
	Message Message `json:"message"`
}

// ReadySignal is sent when a node becomes ready
type ReadySignal struct {
	NodeID    string `json:"node_id"`
	PublicKey []byte `json:"public_key"` // Ed25519 public key
	Ready     bool   `json:"ready"`
	Timestamp int64  `json:"timestamp"`
}

// SubscribeRequest is sent to subscribe to a topic
type SubscribeRequest struct {
	Topic  string `json:"topic"`
	NodeID string `json:"node_id"`
}

// Marshal serializes a message to bytes
func (m *Message) Marshal() ([]byte, error) {
	return json.Marshal(m)
}

// Unmarshal deserializes bytes to a message
func (m *Message) Unmarshal(data []byte) error {
	return json.Unmarshal(data, m)
}

// WriteMessage writes a complete ZAP message with header to the writer
func WriteMessage(w io.Writer, msgType uint8, payload []byte) error {
	if len(payload) > MaxMessageSize {
		return fmt.Errorf("message too large: %d > %d", len(payload), MaxMessageSize)
	}

	header := make([]byte, HeaderSize)
	binary.BigEndian.PutUint32(header[0:4], uint32(len(payload)))
	header[4] = msgType

	if _, err := w.Write(header); err != nil {
		return err
	}
	if _, err := w.Write(payload); err != nil {
		return err
	}
	return nil
}

// ReadMessage reads a complete ZAP message with header from the reader
func ReadMessage(r io.Reader) (uint8, []byte, error) {
	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, err
	}

	length := binary.BigEndian.Uint32(header[0:4])
	msgType := header[4]

	if length > MaxMessageSize {
		return 0, nil, fmt.Errorf("message too large: %d > %d", length, MaxMessageSize)
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}

	return msgType, payload, nil
}
