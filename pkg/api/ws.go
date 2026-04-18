package api

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/luxfi/mpc/pkg/logger"
)

// Event is a server-side event published to WebSocket clients and ZAP subscribers.
type Event struct {
	Type      string          `json:"type"`                // e.g. "intent.status", "sign.progress", "wallet.created"
	OrgID     string          `json:"org_id,omitempty"`    // scope to org (empty = broadcast to all)
	WalletID  string          `json:"wallet_id,omitempty"` // optional wallet scope
	Data      json.RawMessage `json:"data"`
	Timestamp int64           `json:"ts"`
}

// EventBus is a simple fan-out pubsub for server events.
type EventBus struct {
	mu   sync.RWMutex
	subs map[*eventSub]struct{}
}

type eventSub struct {
	ch    chan Event
	orgID string // filter: only receive events for this org (empty = all)
}

// NewEventBus creates a new event bus.
func NewEventBus() *EventBus {
	return &EventBus{subs: make(map[*eventSub]struct{})}
}

// Publish sends an event to all matching subscribers.
func (eb *EventBus) Publish(evt Event) {
	if evt.Timestamp == 0 {
		evt.Timestamp = time.Now().UnixMilli()
	}
	eb.mu.RLock()
	defer eb.mu.RUnlock()
	for sub := range eb.subs {
		if sub.orgID != "" && evt.OrgID != "" && sub.orgID != evt.OrgID {
			continue
		}
		select {
		case sub.ch <- evt:
		default:
			// slow consumer, drop
		}
	}
}

// Subscribe returns a channel that receives events for the given org.
// Call the returned function to unsubscribe.
func (eb *EventBus) Subscribe(orgID string) (<-chan Event, func()) {
	sub := &eventSub{
		ch:    make(chan Event, 64),
		orgID: orgID,
	}
	eb.mu.Lock()
	eb.subs[sub] = struct{}{}
	eb.mu.Unlock()
	return sub.ch, func() {
		eb.mu.Lock()
		delete(eb.subs, sub)
		eb.mu.Unlock()
	}
}

// handleWebSocket upgrades an HTTP connection to a WebSocket and streams events.
// Auth is via ?token=<jwt> query parameter since browsers don't send custom
// headers on WebSocket upgrade requests.
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Authenticate via query param
	token := r.URL.Query().Get("token")
	if token == "" {
		writeError(w, http.StatusUnauthorized, "missing token query parameter")
		return
	}
	claims, err := s.validateJWT(token)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid token")
		return
	}

	// Require upgrade header
	if r.Header.Get("Upgrade") != "websocket" {
		writeError(w, http.StatusBadRequest, "expected websocket upgrade")
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		writeError(w, http.StatusInternalServerError, "websocket upgrade not supported")
		return
	}

	conn, bufrw, err := hj.Hijack()
	if err != nil {
		logger.Error("websocket hijack failed", err)
		return
	}
	defer conn.Close()

	// Complete the WebSocket handshake (RFC 6455 section 4.2.2)
	acceptKey := wsAcceptKey(r.Header.Get("Sec-WebSocket-Key"))
	bufrw.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	bufrw.WriteString("Upgrade: websocket\r\n")
	bufrw.WriteString("Connection: Upgrade\r\n")
	bufrw.WriteString("Sec-WebSocket-Accept: " + acceptKey + "\r\n")
	bufrw.WriteString("\r\n")
	if err := bufrw.Flush(); err != nil {
		logger.Error("websocket handshake flush failed", err)
		return
	}

	logger.Info("websocket client connected", "org", claims.OrgID, "user", claims.UserID)

	// Subscribe to events for this org
	ch, unsub := s.Events.Subscribe(claims.OrgID)
	defer unsub()

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Read goroutine — drain client frames to detect close/ping
	go wsReadDrain(ctx, cancel, conn)

	// Write loop — send events as text frames
	pingTicker := time.NewTicker(30 * time.Second)
	defer pingTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case evt := <-ch:
			data, merr := json.Marshal(evt)
			if merr != nil {
				continue
			}
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if werr := wsWriteText(conn, data); werr != nil {
				return
			}
		case <-pingTicker.C:
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			// WebSocket ping frame: opcode 0x9, no payload
			if _, err := conn.Write([]byte{0x89, 0x00}); err != nil {
				return
			}
		}
	}
}

// wsReadDrain reads and discards client frames until error or context cancel.
func wsReadDrain(ctx context.Context, cancel context.CancelFunc, conn net.Conn) {
	defer cancel()
	buf := make([]byte, 512)
	for {
		conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		if _, err := conn.Read(buf); err != nil {
			return
		}
		// Check context between reads
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

// wsWriteText writes a WebSocket text frame (opcode 0x1, FIN bit set).
// Server-to-client frames are never masked per RFC 6455.
func wsWriteText(conn net.Conn, payload []byte) error {
	length := len(payload)
	var header []byte
	switch {
	case length <= 125:
		header = []byte{0x81, byte(length)}
	case length <= 65535:
		header = []byte{0x81, 126, byte(length >> 8), byte(length)}
	default:
		header = []byte{0x81, 127,
			0, 0, 0, 0,
			byte(length >> 24), byte(length >> 16), byte(length >> 8), byte(length),
		}
	}
	if _, err := conn.Write(header); err != nil {
		return err
	}
	_, err := conn.Write(payload)
	return err
}

// wsAcceptKey computes Sec-WebSocket-Accept per RFC 6455 section 4.2.2.
func wsAcceptKey(clientKey string) string {
	const wsGUID = "258EAFA5-E914-47DA-95CA-5AB5DC76CB65"
	h := sha1.Sum([]byte(clientKey + wsGUID))
	return base64.StdEncoding.EncodeToString(h[:])
}
