// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package transport

import (
	"sync"
	"sync/atomic"
)

// PubSub adapts Transport to the messaging.PubSub interface
// This provides a drop-in replacement for NATS pub/sub
type PubSub struct {
	transport *Transport
}

// NATSMsg mimics nats.Msg for compatibility with existing handlers
// This allows existing code to work without changes
type NATSMsg struct {
	Subject string
	Reply   string
	Data    []byte
	Header  map[string][]string

	// Internal
	transport *Transport
}

// Subscription represents an active subscription
type Subscription struct {
	topic       string
	handler     func(msg *NATSMsg)
	transport   *Transport
	unsubscribe func()
	closed      atomic.Bool
}

// NewPubSub creates a PubSub adapter for the transport
func NewPubSub(transport *Transport) *PubSub {
	return &PubSub{transport: transport}
}

// Publish sends a message to a topic
func (p *PubSub) Publish(topic string, message []byte) error {
	return p.transport.Publish(topic, message)
}

// PublishWithReply sends a message with reply information
func (p *PubSub) PublishWithReply(topic, reply string, data []byte, headers map[string]string) error {
	return p.transport.PublishWithReply(topic, reply, data, headers)
}

// Subscribe registers a handler for a topic
func (p *PubSub) Subscribe(topic string, handler func(msg *NATSMsg)) (*Subscription, error) {
	sub := &Subscription{
		topic:     topic,
		handler:   handler,
		transport: p.transport,
	}

	// Wrap the handler to convert Message -> NATSMsg
	unsubscribe, err := p.transport.Subscribe(topic, func(msg *Message) {
		if sub.closed.Load() {
			return
		}

		// Convert to NATS-compatible message
		natsMsg := &NATSMsg{
			Subject:   msg.Topic,
			Reply:     msg.ReplyTo,
			Data:      msg.Data,
			Header:    make(map[string][]string),
			transport: p.transport,
		}

		// Convert headers
		for k, v := range msg.Headers {
			natsMsg.Header[k] = []string{v}
		}

		handler(natsMsg)
	})

	if err != nil {
		return nil, err
	}

	sub.unsubscribe = unsubscribe
	return sub, nil
}

// Unsubscribe stops the subscription
func (s *Subscription) Unsubscribe() error {
	if s.closed.Swap(true) {
		return nil
	}
	if s.unsubscribe != nil {
		s.unsubscribe()
	}
	return nil
}

// Respond sends a reply to the message (if Reply is set)
func (m *NATSMsg) Respond(data []byte) error {
	if m.Reply == "" {
		return nil
	}
	return m.transport.Publish(m.Reply, data)
}

// MessageQueue provides a simple queue abstraction using the transport
// This replaces NATS JetStream for result queues
type MessageQueue struct {
	transport *Transport
	nodeID    string

	mu       sync.Mutex
	messages map[string][]*QueuedMessage // topic -> messages
	handlers map[string]func(*QueuedMessage)
}

// QueuedMessage represents a message in the queue
type QueuedMessage struct {
	Topic   string
	Data    []byte
	Headers map[string]string
	ID      string // Idempotent key

	// Acknowledgment
	ackCh chan struct{}
}

// EnqueueOptions for queue operations
type EnqueueOptions struct {
	IdempotentKey string
}

// NewMessageQueue creates a queue backed by the transport
func NewMessageQueue(transport *Transport, nodeID string) *MessageQueue {
	return &MessageQueue{
		transport: transport,
		nodeID:    nodeID,
		messages:  make(map[string][]*QueuedMessage),
		handlers:  make(map[string]func(*QueuedMessage)),
	}
}

// Enqueue adds a message to the queue and broadcasts it
func (q *MessageQueue) Enqueue(topic string, data []byte, options *EnqueueOptions) error {
	msg := &QueuedMessage{
		Topic: topic,
		Data:  data,
		ackCh: make(chan struct{}, 1),
	}

	if options != nil {
		msg.ID = options.IdempotentKey
	}

	// Broadcast to all nodes
	queueMsg := Message{
		Type:  MsgMPCResult,
		Topic: topic,
		From:  q.nodeID,
		Data:  data,
	}

	if options != nil && options.IdempotentKey != "" {
		queueMsg.Headers = map[string]string{
			"Idempotent-Key": options.IdempotentKey,
		}
	}

	return q.transport.Publish(topic, data)
}

// Dequeue registers a handler for queue messages
func (q *MessageQueue) Dequeue(topic string, handler func(msg *QueuedMessage) error) error {
	_, err := q.transport.Subscribe(topic, func(msg *Message) {
		qm := &QueuedMessage{
			Topic:   msg.Topic,
			Data:    msg.Data,
			Headers: msg.Headers,
			ackCh:   make(chan struct{}, 1),
		}

		if msg.Headers != nil {
			qm.ID = msg.Headers["Idempotent-Key"]
		}

		if err := handler(qm); err != nil {
			// Log error but don't crash
			// In NATS this would NAK the message
		}
	})

	return err
}

// Close closes the queue
func (q *MessageQueue) Close() error {
	return nil
}

// Ack acknowledges the message
func (m *QueuedMessage) Ack() error {
	select {
	case m.ackCh <- struct{}{}:
	default:
	}
	return nil
}

// Nak negative-acknowledges the message (for retry)
func (m *QueuedMessage) Nak() error {
	// In consensus-based transport, we don't have automatic retry
	// The sender should handle retries if needed
	return nil
}

// Term terminates the message (no retry)
func (m *QueuedMessage) Term() error {
	return m.Ack()
}
