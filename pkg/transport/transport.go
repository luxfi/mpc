// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package transport

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/luxfi/mpc/pkg/logger"
)

var (
	ErrClosed         = errors.New("transport: connection closed")
	ErrTimeout        = errors.New("transport: request timeout")
	ErrPeerNotFound   = errors.New("transport: peer not found")
	ErrInvalidMessage = errors.New("transport: invalid message")
)

// Config holds transport configuration
type Config struct {
	// NodeID is this node's identifier
	NodeID string

	// ListenAddr is the address to listen on (e.g., ":9651")
	ListenAddr string

	// Peers maps node IDs to their addresses
	Peers map[string]string

	// PrivateKey is this node's Ed25519 private key (for signing)
	PrivateKey ed25519.PrivateKey

	// PublicKey is this node's Ed25519 public key
	PublicKey ed25519.PublicKey

	// ReadTimeout for reading messages
	ReadTimeout time.Duration

	// WriteTimeout for writing messages
	WriteTimeout time.Duration

	// BufferSize for read/write buffers
	BufferSize int
}

// DefaultConfig returns sensible defaults
func DefaultConfig() *Config {
	return &Config{
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 10 * time.Second,
		BufferSize:   64 * 1024,
	}
}

// Transport provides ZAP-based messaging for MPC nodes
type Transport struct {
	config *Config

	listener net.Listener

	// Peer connections
	peersMu sync.RWMutex
	peers   map[string]*peerConn

	// Subscriptions: topic -> handlers
	subsMu sync.RWMutex
	subs   map[string][]MessageHandler

	// Request/response correlation
	reqMu    sync.Mutex
	requests map[uint32]chan *Message
	nextID   uint32

	closed atomic.Bool
	done   chan struct{}
	wg     sync.WaitGroup
}

// MessageHandler processes incoming messages
type MessageHandler func(msg *Message)

// peerConn represents a connection to a peer
type peerConn struct {
	nodeID string
	addr   string
	conn   net.Conn
	reader *bufio.Reader
	writer *bufio.Writer

	writeMu sync.Mutex
	closed  atomic.Bool
}

// New creates a new ZAP transport
func New(config *Config) (*Transport, error) {
	if config == nil {
		config = DefaultConfig()
	}

	t := &Transport{
		config:   config,
		peers:    make(map[string]*peerConn),
		subs:     make(map[string][]MessageHandler),
		requests: make(map[uint32]chan *Message),
		done:     make(chan struct{}),
	}

	return t, nil
}

// Start starts the transport (listener and peer connections)
func (t *Transport) Start(ctx context.Context) error {
	// Start listener
	listener, err := net.Listen("tcp", t.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	t.listener = listener

	logger.Info("Transport listening", "addr", listener.Addr().String())

	// Accept incoming connections
	t.wg.Add(1)
	go t.acceptLoop(ctx)

	// Connect to peers
	for nodeID, addr := range t.config.Peers {
		if nodeID == t.config.NodeID {
			continue // Skip self
		}
		t.wg.Add(1)
		go t.connectToPeer(ctx, nodeID, addr)
	}

	return nil
}

// Stop stops the transport
func (t *Transport) Stop() error {
	if t.closed.Swap(true) {
		return nil
	}
	close(t.done)

	if t.listener != nil {
		t.listener.Close()
	}

	t.peersMu.Lock()
	for _, peer := range t.peers {
		peer.close()
	}
	t.peers = nil
	t.peersMu.Unlock()

	t.wg.Wait()
	return nil
}

// acceptLoop accepts incoming connections
func (t *Transport) acceptLoop(ctx context.Context) {
	defer t.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.done:
			return
		default:
		}

		conn, err := t.listener.Accept()
		if err != nil {
			if t.closed.Load() {
				return
			}
			logger.Error("Accept error", err)
			continue
		}

		t.wg.Add(1)
		go t.handleIncoming(ctx, conn)
	}
}

// connectToPeer establishes connection to a peer
func (t *Transport) connectToPeer(ctx context.Context, nodeID, addr string) {
	defer t.wg.Done()

	backoff := time.Second
	maxBackoff := 30 * time.Second

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.done:
			return
		default:
		}

		conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
		if err != nil {
			logger.Warn("Failed to connect to peer", "nodeID", nodeID, "addr", addr, "err", err)
			time.Sleep(backoff)
			backoff = min(backoff*2, maxBackoff)
			continue
		}

		backoff = time.Second // Reset backoff on success

		peer := t.addPeer(nodeID, addr, conn)
		logger.Info("Connected to peer", "nodeID", nodeID, "addr", addr)

		// Send our identity
		t.sendIdentity(peer)

		// Handle messages from this peer
		t.handlePeer(ctx, peer)

		// Connection closed, remove peer
		t.removePeer(nodeID)
		logger.Warn("Disconnected from peer", "nodeID", nodeID)
	}
}

// handleIncoming handles an incoming connection
func (t *Transport) handleIncoming(ctx context.Context, conn net.Conn) {
	defer t.wg.Done()
	defer conn.Close()

	// Read identity message first
	msgType, payload, err := ReadMessage(conn)
	if err != nil {
		logger.Error("Failed to read identity", err)
		return
	}

	if msgType != MsgMPCReady {
		logger.Warn("Expected identity message, got", "type", msgType)
		return
	}

	var ready ReadySignal
	if err := json.Unmarshal(payload, &ready); err != nil {
		logger.Error("Failed to unmarshal identity", err)
		return
	}

	peer := t.addPeer(ready.NodeID, conn.RemoteAddr().String(), conn)
	logger.Info("Incoming connection from peer", "nodeID", ready.NodeID)

	// Handle messages from this peer
	t.handlePeer(ctx, peer)

	t.removePeer(ready.NodeID)
}

// handlePeer reads messages from a peer connection
func (t *Transport) handlePeer(ctx context.Context, peer *peerConn) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.done:
			return
		default:
		}

		if t.config.ReadTimeout > 0 {
			peer.conn.SetReadDeadline(time.Now().Add(t.config.ReadTimeout))
		}

		msgType, payload, err := ReadMessage(peer.reader)
		if err != nil {
			if err == io.EOF || errors.Is(err, net.ErrClosed) {
				return
			}
			if !t.closed.Load() {
				logger.Error("Read error", err, "peer", peer.nodeID)
			}
			return
		}

		t.handleMessage(peer.nodeID, msgType, payload)
	}
}

// handleMessage processes a received message
func (t *Transport) handleMessage(from string, msgType uint8, payload []byte) {
	switch msgType {
	case MsgMPCBroadcast:
		var msg Message
		if err := json.Unmarshal(payload, &msg); err != nil {
			logger.Error("Failed to unmarshal broadcast", err)
			return
		}
		msg.From = from
		t.deliverToSubscribers(msg.Topic, &msg)

	case MsgMPCDirect:
		var env Envelope
		if err := json.Unmarshal(payload, &env); err != nil {
			logger.Error("Failed to unmarshal direct", err)
			return
		}
		env.Message.From = from

		// Check if this is a response to a request
		t.reqMu.Lock()
		ch, ok := t.requests[env.ID]
		if ok {
			delete(t.requests, env.ID)
		}
		t.reqMu.Unlock()

		if ok {
			select {
			case ch <- &env.Message:
			default:
			}
		} else {
			// Deliver to topic subscribers
			t.deliverToSubscribers(env.Message.Topic, &env.Message)
		}

	case MsgMPCReady:
		var ready ReadySignal
		if err := json.Unmarshal(payload, &ready); err != nil {
			logger.Error("Failed to unmarshal ready", err)
			return
		}
		logger.Debug("Received ready signal", "from", ready.NodeID, "ready", ready.Ready)

	case MsgMPCPing:
		// Send pong back
		t.sendPong(from)

	case MsgMPCPong:
		logger.Debug("Received pong", "from", from)

	default:
		// Treat as protocol message, deliver to subscriptions
		var msg Message
		if err := json.Unmarshal(payload, &msg); err != nil {
			logger.Error("Failed to unmarshal message", err, "type", msgType)
			return
		}
		msg.From = from
		t.deliverToSubscribers(msg.Topic, &msg)
	}
}

// deliverToSubscribers delivers a message to all topic subscribers
func (t *Transport) deliverToSubscribers(topic string, msg *Message) {
	t.subsMu.RLock()
	handlers := t.subs[topic]
	t.subsMu.RUnlock()

	for _, handler := range handlers {
		go handler(msg)
	}
}

// Publish sends a message to all peers (broadcast)
func (t *Transport) Publish(topic string, data []byte) error {
	msg := Message{
		Type:  MsgMPCBroadcast,
		Topic: topic,
		From:  t.config.NodeID,
		Data:  data,
	}

	payload, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	return t.broadcast(MsgMPCBroadcast, payload)
}

// PublishWithReply sends a message with reply information
func (t *Transport) PublishWithReply(topic, reply string, data []byte, headers map[string]string) error {
	msg := Message{
		Type:    MsgMPCBroadcast,
		Topic:   topic,
		From:    t.config.NodeID,
		ReplyTo: reply,
		Headers: headers,
		Data:    data,
	}

	payload, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	return t.broadcast(MsgMPCBroadcast, payload)
}

// Subscribe registers a handler for a topic
func (t *Transport) Subscribe(topic string, handler MessageHandler) (func(), error) {
	t.subsMu.Lock()
	t.subs[topic] = append(t.subs[topic], handler)
	t.subsMu.Unlock()

	// Return unsubscribe function
	return func() {
		t.subsMu.Lock()
		defer t.subsMu.Unlock()
		handlers := t.subs[topic]
		for i, h := range handlers {
			// Compare function pointers (this is a simplification)
			if &h == &handler {
				t.subs[topic] = append(handlers[:i], handlers[i+1:]...)
				break
			}
		}
	}, nil
}

// Send sends a direct message to a specific peer
func (t *Transport) Send(ctx context.Context, nodeID string, data []byte) (*Message, error) {
	t.peersMu.RLock()
	peer, ok := t.peers[nodeID]
	t.peersMu.RUnlock()

	if !ok {
		return nil, ErrPeerNotFound
	}

	// Allocate request ID
	id := atomic.AddUint32(&t.nextID, 1)
	respCh := make(chan *Message, 1)

	t.reqMu.Lock()
	t.requests[id] = respCh
	t.reqMu.Unlock()

	defer func() {
		t.reqMu.Lock()
		delete(t.requests, id)
		t.reqMu.Unlock()
	}()

	// Send envelope
	env := Envelope{
		ID: id,
		Message: Message{
			Type: MsgMPCDirect,
			From: t.config.NodeID,
			To:   nodeID,
			Data: data,
		},
	}

	payload, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}

	if err := peer.send(MsgMPCDirect, payload); err != nil {
		return nil, err
	}

	// Wait for response
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.done:
		return nil, ErrClosed
	case resp := <-respCh:
		return resp, nil
	}
}

// broadcast sends a message to all connected peers
func (t *Transport) broadcast(msgType uint8, payload []byte) error {
	t.peersMu.RLock()
	peers := make([]*peerConn, 0, len(t.peers))
	for _, peer := range t.peers {
		peers = append(peers, peer)
	}
	t.peersMu.RUnlock()

	var errs []error
	for _, peer := range peers {
		if err := peer.send(msgType, payload); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", peer.nodeID, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("broadcast errors: %v", errs)
	}
	return nil
}

// sendIdentity sends our identity to a peer
func (t *Transport) sendIdentity(peer *peerConn) {
	ready := ReadySignal{
		NodeID:    t.config.NodeID,
		PublicKey: t.config.PublicKey,
		Ready:     true,
		Timestamp: time.Now().UnixMilli(),
	}

	payload, _ := json.Marshal(ready)
	peer.send(MsgMPCReady, payload)
}

// sendPong sends a pong response
func (t *Transport) sendPong(to string) {
	t.peersMu.RLock()
	peer, ok := t.peers[to]
	t.peersMu.RUnlock()

	if ok {
		msg := Message{
			Type: MsgMPCPong,
			From: t.config.NodeID,
		}
		payload, _ := json.Marshal(msg)
		peer.send(MsgMPCPong, payload)
	}
}

// addPeer adds a peer connection
func (t *Transport) addPeer(nodeID, addr string, conn net.Conn) *peerConn {
	peer := &peerConn{
		nodeID: nodeID,
		addr:   addr,
		conn:   conn,
		reader: bufio.NewReaderSize(conn, t.config.BufferSize),
		writer: bufio.NewWriterSize(conn, t.config.BufferSize),
	}

	t.peersMu.Lock()
	// Close existing connection if any
	if existing, ok := t.peers[nodeID]; ok {
		existing.close()
	}
	t.peers[nodeID] = peer
	t.peersMu.Unlock()

	return peer
}

// removePeer removes a peer connection
func (t *Transport) removePeer(nodeID string) {
	t.peersMu.Lock()
	if peer, ok := t.peers[nodeID]; ok {
		peer.close()
		delete(t.peers, nodeID)
	}
	t.peersMu.Unlock()
}

// GetPeers returns connected peer IDs
func (t *Transport) GetPeers() []string {
	t.peersMu.RLock()
	defer t.peersMu.RUnlock()

	peers := make([]string, 0, len(t.peers))
	for nodeID := range t.peers {
		peers = append(peers, nodeID)
	}
	return peers
}

// GetPeerCount returns number of connected peers
func (t *Transport) GetPeerCount() int {
	t.peersMu.RLock()
	defer t.peersMu.RUnlock()
	return len(t.peers)
}

// peerConn methods

func (p *peerConn) send(msgType uint8, payload []byte) error {
	if p.closed.Load() {
		return ErrClosed
	}

	p.writeMu.Lock()
	defer p.writeMu.Unlock()

	if err := WriteMessage(p.writer, msgType, payload); err != nil {
		return err
	}
	return p.writer.Flush()
}

func (p *peerConn) close() {
	if p.closed.Swap(true) {
		return
	}
	p.conn.Close()
}

func min(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
