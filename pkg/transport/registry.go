// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package transport

import (
	"context"
	"encoding/json"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/luxfi/mpc/pkg/logger"
)

// Registry implements mpc.PeerRegistry using consensus-based transport
// instead of Consul for peer discovery and readiness tracking
type Registry struct {
	nodeID      string
	peerNodeIDs []string
	transport   *Transport

	readyMu    sync.RWMutex
	readyMap   map[string]bool // nodeID -> ready
	readyCount int64

	ready atomic.Bool // all peers ready

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewRegistry creates a new consensus-based peer registry
func NewRegistry(nodeID string, peerNodeIDs []string, transport *Transport) *Registry {
	ctx, cancel := context.WithCancel(context.Background())

	r := &Registry{
		nodeID:      nodeID,
		peerNodeIDs: filterSelf(nodeID, peerNodeIDs),
		transport:   transport,
		readyMap:    make(map[string]bool),
		readyCount:  1, // self is always ready
		ctx:         ctx,
		cancel:      cancel,
	}

	return r
}

func filterSelf(nodeID string, peerNodeIDs []string) []string {
	filtered := make([]string, 0, len(peerNodeIDs))
	for _, id := range peerNodeIDs {
		if id != nodeID {
			filtered = append(filtered, id)
		}
	}
	return filtered
}

// Ready marks this node as ready and announces to peers
func (r *Registry) Ready() error {
	ready := ReadySignal{
		NodeID:    r.nodeID,
		Ready:     true,
		Timestamp: time.Now().UnixMilli(),
	}

	// Broadcast ready signal to all peers via the transport
	return r.transport.broadcastReady(ready)
}

// Resign marks this node as not ready
func (r *Registry) Resign() error {
	ready := ReadySignal{
		NodeID:    r.nodeID,
		Ready:     false,
		Timestamp: time.Now().UnixMilli(),
	}

	return r.transport.broadcastReady(ready)
}

// WatchPeersReady starts watching for peer readiness
func (r *Registry) WatchPeersReady() {
	// Subscribe to ready signals
	unsubscribe, _ := r.transport.Subscribe("mpc:ready", r.handleReadySignal)
	defer unsubscribe()

	r.wg.Add(1)
	go r.watchLoop()

	// Also start logging status
	r.wg.Add(1)
	go r.logReadyStatus()
}

// watchLoop checks peer connectivity periodically
func (r *Registry) watchLoop() {
	defer r.wg.Done()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			r.checkPeerConnections()
		}
	}
}

// checkPeerConnections updates ready status based on transport connections
func (r *Registry) checkPeerConnections() {
	connectedPeers := r.transport.GetPeers()
	connectedSet := make(map[string]bool, len(connectedPeers))
	for _, id := range connectedPeers {
		connectedSet[id] = true
	}

	r.readyMu.Lock()
	defer r.readyMu.Unlock()

	var changed bool

	// Check for new connections
	for _, peerID := range connectedPeers {
		if !r.readyMap[peerID] {
			r.readyMap[peerID] = true
			atomic.AddInt64(&r.readyCount, 1)
			logger.Info("Peer connected", "peerID", peerID)
			changed = true
		}
	}

	// Check for disconnections
	for peerID, ready := range r.readyMap {
		if ready && !connectedSet[peerID] {
			r.readyMap[peerID] = false
			atomic.AddInt64(&r.readyCount, -1)
			logger.Warn("Peer disconnected", "peerID", peerID)
			changed = true
		}
	}

	// Update overall ready status
	allReady := len(connectedPeers) == len(r.peerNodeIDs)
	wasReady := r.ready.Load()

	if allReady && !wasReady {
		r.ready.Store(true)
		logger.Info("ALL PEERS ARE READY! Starting to accept MPC requests")
	} else if !allReady && wasReady {
		r.ready.Store(false)
	}

	_ = changed // Suppress unused warning
}

// handleReadySignal processes ready signals from peers
func (r *Registry) handleReadySignal(msg *Message) {
	var ready ReadySignal
	if err := ready.Unmarshal(msg.Data); err != nil {
		logger.Error("Failed to unmarshal ready signal", err)
		return
	}

	if ready.NodeID == r.nodeID {
		return // Ignore our own signals
	}

	r.readyMu.Lock()
	defer r.readyMu.Unlock()

	wasReady := r.readyMap[ready.NodeID]

	if ready.Ready && !wasReady {
		r.readyMap[ready.NodeID] = true
		atomic.AddInt64(&r.readyCount, 1)
		logger.Info("Peer became ready", "peerID", ready.NodeID)
	} else if !ready.Ready && wasReady {
		r.readyMap[ready.NodeID] = false
		atomic.AddInt64(&r.readyCount, -1)
		logger.Warn("Peer resigned", "peerID", ready.NodeID)
	}

	// Update overall ready status
	allReady := atomic.LoadInt64(&r.readyCount) == int64(len(r.peerNodeIDs)+1)
	if allReady && !r.ready.Load() {
		r.ready.Store(true)
		logger.Info("ALL PEERS ARE READY! Starting to accept MPC requests")
	} else if !allReady && r.ready.Load() {
		r.ready.Store(false)
	}
}

func (rs *ReadySignal) Unmarshal(data []byte) error {
	return json.Unmarshal(data, rs)
}

// logReadyStatus periodically logs readiness status
func (r *Registry) logReadyStatus() {
	defer r.wg.Done()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			if !r.ArePeersReady() {
				logger.Info("Peers not ready",
					"ready", r.GetReadyPeersCount(),
					"expected", len(r.peerNodeIDs)+1,
				)
			}
		}
	}
}

// ArePeersReady returns true if all peers are ready
func (r *Registry) ArePeersReady() bool {
	return r.ready.Load()
}

// GetReadyPeersCount returns number of ready peers
func (r *Registry) GetReadyPeersCount() int64 {
	return atomic.LoadInt64(&r.readyCount)
}

// GetTotalPeersCount returns total expected peers including self
func (r *Registry) GetTotalPeersCount() int64 {
	return int64(len(r.peerNodeIDs) + 1)
}

// GetReadyPeersIncludeSelf returns all ready peer IDs including self, sorted
func (r *Registry) GetReadyPeersIncludeSelf() []string {
	r.readyMu.RLock()
	defer r.readyMu.RUnlock()

	peers := make([]string, 0, len(r.readyMap)+1)
	for peerID, ready := range r.readyMap {
		if ready {
			peers = append(peers, peerID)
		}
	}
	peers = append(peers, r.nodeID)

	// Sort for deterministic party ID ordering
	sort.Strings(peers)

	return peers
}

// Close stops the registry
func (r *Registry) Close() error {
	r.cancel()
	r.wg.Wait()
	return nil
}

// broadcastReady sends a ready signal to all peers
func (t *Transport) broadcastReady(ready ReadySignal) error {
	payload, err := json.Marshal(ready)
	if err != nil {
		return err
	}

	// Broadcast via transport
	return t.broadcast(MsgMPCReady, payload)
}
