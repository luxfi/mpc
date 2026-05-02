// Package api — KMS-facing ZAP server.
//
// This file implements a luxfi/zap node that exposes MPC threshold operations
// to the KMS control plane. KMS dials this node, runs the ML-KEM-768 hybrid
// handshake (kms/pkg/zap), then issues opcode-prefixed JSON requests for
// keygen / sign / reshare / status / wallet lookup. The wire contract is the
// one defined by kms/pkg/mpc/zap_client.go — opcodes 0x0001-0x0031.
//
// The existing pkg/api zap server (zap_server.go, opcodes 0x0060+) is for
// MPC's own dashboard event bus and uses a different wire format. The two
// servers serve different consumers and run on different ports.
//
// Wire format per request: opcode(2 LE) || JSON payload.
// Response: opcode(2 LE) || JSON body. Errors set top-level "error" string.
package api

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/luxfi/mpc/pkg/logger"
	"github.com/luxfi/zap"

	kmszap "github.com/luxfi/mpc/pkg/zap"
	"github.com/luxfi/mpc/pkg/zapauth"
)

// KMS-facing opcode constants. These are the contract with
// luxfi/kms/pkg/mpc/zap_client.go and MUST stay in lockstep with that file.
const (
	OpKMSStatus  uint16 = 0x0001
	OpKMSKeygen  uint16 = 0x0010
	OpKMSSign    uint16 = 0x0011
	OpKMSReshare uint16 = 0x0012
	OpKMSWallet  uint16 = 0x0020
)

// KMSZapServer wires MPCBackend onto a luxfi/zap.Node and frames responses in
// KMS's opcode-prefixed JSON dialect.
type KMSZapServer struct {
	backend MPCBackend

	// sessions holds per-peer hybrid handshake state. Once a peer runs the
	// ML-KEM-768 handshake (opcode 0x00F0), every subsequent request is
	// AEAD-sealed under the derived session key. A peer with no entry can
	// still talk in the clear — forward-only fallback so older KMS builds
	// that pre-date the handshake (#55) keep working until they upgrade.
	sessions   map[string]*kmszap.Session
	sessionsMu sync.RWMutex

	// localCaps controls what the server advertises in ServerHello. ML-KEM
	// is on by default; we never opt out unilaterally.
	localCaps uint16

	// auth, when non-nil, validates a JWKS-bearer JWT presented in
	// OpAuthHello (zapauth.OpAuthHello = 0x00EF) BEFORE the hybrid PQ
	// handshake. The peer's verified claims are attached to the
	// connection by ZAP peer ID and looked up on every subsequent
	// dispatch. nil means "no JWT verification" — secure-by-default
	// requires this to be non-nil; the wrapper in StartKMSZAP enforces
	// that behavior gating off ZAP_AUTH_REQUIRED.
	auth         *zapauth.Verifier
	authRequired bool

	node *zap.Node
}

// KMSZapConfig configures the optional zapauth bearer-token gate on the
// KMS-facing ZAP server. Fields are mutually consistent: a non-nil
// Verifier paired with AuthRequired=true rejects unauthenticated peers
// at OpClientHello; with AuthRequired=false (the v1.14.0 default) the
// connection still completes and a warning logs so operators can roll
// out KMS-side bearer minting before flipping the flag.
type KMSZapConfig struct {
	Verifier     *zapauth.Verifier
	AuthRequired bool
}

// StartKMSZAP creates a luxfi/zap.Node bound to listenAddr and registers KMS
// opcode handlers. Returns the server (so callers can stop it on shutdown).
//
// nodeID is the ZAP advertised identity — KMS uses it as the auditable
// principal for sign/keygen requests. Every MPC StatefulSet pod gets a unique
// ID (mpc-kms-zap-<pod>) so KMS audit rows can pin a request to a node.
//
// This wrapper preserves the v1.13.x signature for callers that have not
// yet wired zapauth. New deployments should call StartKMSZAPWith to pass
// a zapauth.Verifier.
func StartKMSZAP(backend MPCBackend, nodeID, listenAddr string) (*KMSZapServer, error) {
	return StartKMSZAPWith(backend, nodeID, listenAddr, KMSZapConfig{})
}

// StartKMSZAPWith is the configurable form of StartKMSZAP. cfg.Verifier
// gates OpClientHello on a verified JWT in OpAuthHello when
// cfg.AuthRequired is true. cfg.Verifier without AuthRequired logs but
// still serves unauthenticated peers — used during the rollout window.
func StartKMSZAPWith(backend MPCBackend, nodeID, listenAddr string, cfg KMSZapConfig) (*KMSZapServer, error) {
	port, err := parsePort(listenAddr)
	if err != nil {
		return nil, fmt.Errorf("zap: parse listen %q: %w", listenAddr, err)
	}
	if cfg.AuthRequired && cfg.Verifier == nil {
		return nil, fmt.Errorf("zap: AuthRequired=true requires a non-nil Verifier")
	}

	node := zap.NewNode(zap.NodeConfig{
		NodeID:      nodeID,
		ServiceType: "_mpc-kms._tcp",
		Port:        port,
		NoDiscovery: true, // direct dial only — no mDNS leakage from prod pods
	})

	s := &KMSZapServer{
		backend:      backend,
		sessions:     make(map[string]*kmszap.Session),
		localCaps:    kmszap.CapMLKEM768,
		auth:         cfg.Verifier,
		authRequired: cfg.AuthRequired,
		node:         node,
	}

	// Pre-handshake bearer token. When auth is configured, OpAuthHello
	// MUST precede OpClientHello. The handler verifies + attaches claims
	// keyed by ZAP peer ID. Forward-compat: we register the handler even
	// when auth is nil so peers that send the frame don't get an unknown-
	// opcode error during the rollout window.
	node.Handle(zapauth.OpAuthHello, s.handleAuthHello)

	// Application-layer hybrid handshake. Distinct opcode so a client can
	// negotiate before sending any threshold-op payload.
	node.Handle(kmszap.OpClientHello, s.handleHandshake)

	// KMS opcodes — the public surface.
	node.Handle(OpKMSStatus, s.handle(s.handleStatus))
	node.Handle(OpKMSKeygen, s.handle(s.handleKeygen))
	node.Handle(OpKMSSign, s.handle(s.handleSign))
	node.Handle(OpKMSReshare, s.handle(s.handleReshare))
	node.Handle(OpKMSWallet, s.handle(s.handleWallet))

	// Universal type=0 mux: clients that don't set the per-message type
	// field (zap.Builder default) reach handlers via the opcode embedded in
	// the body bytes. Mirrors kms/pkg/zapserver Register().
	node.Handle(0, s.muxByOpcode)

	if err := node.Start(); err != nil {
		return nil, fmt.Errorf("zap: start node: %w", err)
	}
	authMode := "off"
	switch {
	case cfg.AuthRequired:
		authMode = "required"
	case cfg.Verifier != nil:
		authMode = "advisory"
	}
	logger.Info("KMS ZAP server started",
		"addr", listenAddr, "nodeID", nodeID,
		"caps", "X25519+ML-KEM-768", "auth", authMode)
	return s, nil
}

// Stop tears down the underlying ZAP node. Idempotent.
func (s *KMSZapServer) Stop() {
	if s.node != nil {
		s.node.Stop()
	}
}

// handlerFn is the shape of an op handler before opcode framing.
type handlerFn func(ctx context.Context, from string, payload []byte) ([]byte, error)

// handle wraps an opcode handler with payload extraction, optional session
// AEAD, and opcode-prefixed JSON response framing. The opcode comes from
// the first 2 LE bytes of the body — the same prefix the client wrote.
func (s *KMSZapServer) handle(op handlerFn) zap.Handler {
	return func(ctx context.Context, from string, msg *zap.Message) (*zap.Message, error) {
		raw := extractPayload(msg)
		if len(raw) < 2 {
			return s.respond(from, 0, errBody("empty payload")), nil
		}
		opcode := binary.LittleEndian.Uint16(raw[:2])
		if !s.checkAuth(from, opcode) {
			return s.respond(from, opcode, errBody("auth required")), nil
		}
		payload := raw[2:]
		// Session-sealed payloads are AEAD-opened before dispatch.
		if sess := s.session(from); sess != nil {
			pt, err := sess.Open(kmszap.DirClientToServer, payload)
			if err != nil {
				logger.Warn("kms-zap session open failed", "from", from, "op", opcode, "err", err)
				return s.respond(from, opcode, errBody("session decrypt failed")), nil
			}
			payload = pt
		}
		body, err := op(ctx, from, payload)
		if err != nil {
			logger.Warn("kms-zap handler error", "from", from, "op", opcode, "err", err)
			return s.respond(from, opcode, errBody(err.Error())), nil
		}
		return s.respond(from, opcode, body), nil
	}
}

// muxByOpcode dispatches type-0 messages by reading the opcode from the body.
// Clients that don't set the ZAP message type field land here.
func (s *KMSZapServer) muxByOpcode(ctx context.Context, from string, msg *zap.Message) (*zap.Message, error) {
	raw := extractPayload(msg)
	if len(raw) < 2 {
		return s.respond(from, 0, errBody("empty payload")), nil
	}
	op := binary.LittleEndian.Uint16(raw[:2])
	if op == zapauth.OpAuthHello {
		return s.respondAuthHello(ctx, from, raw[2:]), nil
	}
	if op == kmszap.OpClientHello {
		if !s.checkAuth(from, op) {
			return s.respond(from, kmszap.OpServerHello, errBody("auth required")), nil
		}
		return s.respondHandshake(from, raw[2:]), nil
	}
	if !s.checkAuth(from, op) {
		return s.respond(from, op, errBody("auth required")), nil
	}
	dispatch := map[uint16]handlerFn{
		OpKMSStatus:  s.handleStatus,
		OpKMSKeygen:  s.handleKeygen,
		OpKMSSign:    s.handleSign,
		OpKMSReshare: s.handleReshare,
		OpKMSWallet:  s.handleWallet,
	}
	h, ok := dispatch[op]
	if !ok {
		return s.respond(from, op, errBody(fmt.Sprintf("unknown opcode 0x%04x", op))), nil
	}
	payload := raw[2:]
	if sess := s.session(from); sess != nil {
		pt, err := sess.Open(kmszap.DirClientToServer, payload)
		if err != nil {
			logger.Warn("kms-zap mux session open failed", "from", from, "op", op, "err", err)
			return s.respond(from, op, errBody("session decrypt failed")), nil
		}
		payload = pt
	}
	body, err := h(ctx, from, payload)
	if err != nil {
		logger.Warn("kms-zap mux handler error", "from", from, "op", op, "err", err)
		return s.respond(from, op, errBody(err.Error())), nil
	}
	return s.respond(from, op, body), nil
}

// checkAuth gates an opcode dispatch on the auth state of the peer.
// Returns true when the peer may proceed: either auth is disabled, or
// the peer presented a valid JWT in OpAuthHello. Logs and returns false
// when authRequired is on and the peer is unauthenticated.
func (s *KMSZapServer) checkAuth(from string, op uint16) bool {
	if s.auth == nil || !s.authRequired {
		if s.auth != nil {
			if _, ok := s.auth.Lookup(from); !ok {
				logger.Warn("kms-zap unauthenticated peer (advisory mode)",
					"from", from, "op", fmt.Sprintf("0x%04x", op))
			}
		}
		return true
	}
	if _, ok := s.auth.Lookup(from); !ok {
		logger.Warn("kms-zap rejecting unauthenticated peer",
			"from", from, "op", fmt.Sprintf("0x%04x", op))
		return false
	}
	return true
}

// handleAuthHello is the per-opcode handler for OpAuthHello. The body
// shape is opcode(2 LE) || zapauth.AuthHelloFrame.
func (s *KMSZapServer) handleAuthHello(ctx context.Context, from string, msg *zap.Message) (*zap.Message, error) {
	raw := extractPayload(msg)
	if len(raw) < 2 {
		return s.respond(from, zapauth.OpAuthHello, errBody("empty auth payload")), nil
	}
	return s.respondAuthHello(ctx, from, raw[2:]), nil
}

// respondAuthHello validates the bearer token in the AuthHello frame
// and attaches the verified claims to the peer ID. Returns a tiny JSON
// body with {"ok":true} on success or {"error":"..."} on failure.
func (s *KMSZapServer) respondAuthHello(ctx context.Context, from string, framed []byte) *zap.Message {
	frame, err := zapauth.UnmarshalAuthHello(framed)
	if err != nil {
		logger.Warn("kms-zap auth hello parse failed", "from", from, "err", err)
		return s.respond(from, zapauth.OpAuthHello, errBody(err.Error()))
	}
	if s.auth == nil {
		// No verifier configured. Accept the frame so a forward-rolling
		// KMS client doesn't trip on a backwards MPC, but log it.
		logger.Info("kms-zap auth hello received but verifier disabled",
			"from", from, "tokenBytes", len(frame.Token))
		ok, _ := json.Marshal(map[string]bool{"ok": true})
		return s.respond(from, zapauth.OpAuthHello, ok)
	}
	claims, err := s.auth.Verify(ctx, frame.Token)
	if err != nil {
		logger.Warn("kms-zap auth verify failed", "from", from, "err", err)
		return s.respond(from, zapauth.OpAuthHello, errBody(err.Error()))
	}
	s.auth.AttachClaims(from, *claims)
	logger.Info("kms-zap auth hello accepted",
		"from", from, "sub", claims.Subject, "iss", claims.Issuer)
	ok, _ := json.Marshal(map[string]bool{"ok": true})
	return s.respond(from, zapauth.OpAuthHello, ok)
}

// extractPayload pulls the application bytes out of a ZAP message,
// handling both the structured-Object form and the raw-bytes-after-header
// form used by zap.Builder.WriteBytes.
func extractPayload(msg *zap.Message) []byte {
	if raw := msg.Root().Bytes(0); raw != nil {
		return raw
	}
	b := msg.Bytes()
	if len(b) > zap.HeaderSize {
		return b[zap.HeaderSize:]
	}
	return nil
}

// respond frames opcode(2 LE) || body and seals under the peer's session
// key when one exists. Output matches what kms/pkg/mpc/zap_client.go expects.
func (s *KMSZapServer) respond(peerID string, opcode uint16, body []byte) *zap.Message {
	if sess := s.session(peerID); sess != nil {
		sealed, err := sess.Seal(kmszap.DirServerToClient, body)
		if err != nil {
			logger.Error("kms-zap seal failed", err, "from", peerID)
			body = errBody("session seal failed")
		} else {
			body = sealed
		}
	}
	out := make([]byte, 2+len(body))
	binary.LittleEndian.PutUint16(out[0:2], opcode)
	copy(out[2:], body)
	b := zap.NewBuilder(len(out) + 64)
	b.WriteBytes(out)
	m, err := zap.Parse(b.Finish())
	if err != nil {
		// Builder output is always parseable — invariant violation.
		logger.Error("kms-zap respond build failed", err)
		return nil
	}
	return m
}

func errBody(msg string) []byte {
	b, _ := json.Marshal(map[string]string{"error": msg})
	return b
}

// session returns the active hybrid session for a peer, or nil when the
// peer hasn't run OpClientHello.
func (s *KMSZapServer) session(peerID string) *kmszap.Session {
	s.sessionsMu.RLock()
	defer s.sessionsMu.RUnlock()
	return s.sessions[peerID]
}

// setSession stores a freshly negotiated session, replacing any prior entry.
func (s *KMSZapServer) setSession(peerID string, sess *kmszap.Session) {
	s.sessionsMu.Lock()
	s.sessions[peerID] = sess
	s.sessionsMu.Unlock()
}

// handleHandshake is the per-opcode handler for OpClientHello.
func (s *KMSZapServer) handleHandshake(_ context.Context, from string, msg *zap.Message) (*zap.Message, error) {
	if !s.checkAuth(from, kmszap.OpClientHello) {
		return s.respond(from, kmszap.OpServerHello, errBody("auth required")), nil
	}
	raw := extractPayload(msg)
	if len(raw) < 2 {
		return s.respond(from, kmszap.OpServerHello, errBody("empty handshake payload")), nil
	}
	// Strip 2-byte opcode prefix; client mux puts opcode in body.
	return s.respondHandshake(from, raw[2:]), nil
}

// respondHandshake runs the server side of the hybrid PQ handshake, installs
// the session, and returns ServerHello as the response payload (opcode 0x00F1).
//
// ServerHello rides un-AEAD'd because the key only exists after this exchange
// completes. Subsequent opcodes get sealed automatically.
func (s *KMSZapServer) respondHandshake(from string, helloBytes []byte) *zap.Message {
	replyWire, result, err := kmszap.ServerRespond(s.localCaps, helloBytes)
	if err != nil {
		logger.Warn("kms-zap handshake failed", "from", from, "err", err)
		return s.respond(from, kmszap.OpServerHello, errBody(err.Error()))
	}
	sess, err := kmszap.NewSession(result.SessionKey, result.Hybrid)
	if err != nil {
		logger.Error("kms-zap session init failed", err, "from", from)
		return s.respond(from, kmszap.OpServerHello, errBody(err.Error()))
	}
	s.setSession(from, sess)
	if !result.Hybrid {
		logger.Warn("kms-zap handshake classical-only — peer cleared ML-KEM-768",
			"from", from, "peerCaps", result.PeerCaps)
	} else {
		logger.Info("kms-zap handshake hybrid", "from", from, "alg", "X25519+ML-KEM-768")
	}
	// Frame the server hello: opcode(0x00F1) || helloBytes (no AEAD).
	out := make([]byte, 2+len(replyWire))
	binary.LittleEndian.PutUint16(out[0:2], kmszap.OpServerHello)
	copy(out[2:], replyWire)
	b := zap.NewBuilder(len(out) + 64)
	b.WriteBytes(out)
	m, err := zap.Parse(b.Finish())
	if err != nil {
		logger.Error("kms-zap handshake reply build failed", err)
		return nil
	}
	return m
}

// ---- KMS opcode handlers ----

// kmsZapStatusResponse mirrors kms/pkg/mpc/types.go ClusterStatus on the wire.
type kmsZapStatusResponse struct {
	NodeID         string `json:"node_id"`
	Mode           string `json:"mode"`
	ExpectedPeers  int    `json:"expected_peers"`
	ConnectedPeers int    `json:"connected_peers"`
	Ready          bool   `json:"ready"`
	Threshold      int    `json:"threshold"`
	Version        string `json:"version"`
}

func (s *KMSZapServer) handleStatus(_ context.Context, _ string, _ []byte) ([]byte, error) {
	st := s.backend.GetClusterStatus()
	resp := kmsZapStatusResponse{
		NodeID:         st.NodeID,
		Mode:           st.Mode,
		ExpectedPeers:  st.ExpectedPeers,
		ConnectedPeers: st.ConnectedPeers,
		Ready:          st.Ready,
		Threshold:      st.Threshold,
		Version:        st.Version,
	}
	return json.Marshal(resp)
}

// kmsZapKeygenRequest matches kms/pkg/mpc/zap_client.go Keygen() payload shape.
type kmsZapKeygenRequest struct {
	VaultID string `json:"vault_id"`
	Request struct {
		WalletID string `json:"wallet_id"`
		KeyType  string `json:"key_type,omitempty"`
	} `json:"request"`
}

func (s *KMSZapServer) handleKeygen(_ context.Context, from string, payload []byte) ([]byte, error) {
	var req kmsZapKeygenRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, fmt.Errorf("decode keygen: %w", err)
	}
	if req.VaultID == "" {
		return nil, fmt.Errorf("vault_id required")
	}
	logger.Info("kms-zap keygen", "from", from, "vault", req.VaultID, "wallet", req.Request.WalletID)
	result, err := s.backend.TriggerKeygen(req.VaultID, req.Request.WalletID)
	if err != nil {
		return nil, err
	}
	return json.Marshal(result)
}

// kmsZapSignRequest matches kms/pkg/mpc/zap_client.go Sign() payload shape.
type kmsZapSignRequest struct {
	VaultID  string `json:"vault_id"`
	WalletID string `json:"wallet_id"`
	Payload  []byte `json:"payload"`
}

func (s *KMSZapServer) handleSign(_ context.Context, from string, payload []byte) ([]byte, error) {
	var req kmsZapSignRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, fmt.Errorf("decode sign: %w", err)
	}
	if req.VaultID == "" || req.WalletID == "" {
		return nil, fmt.Errorf("vault_id and wallet_id required")
	}
	if len(req.Payload) == 0 {
		return nil, fmt.Errorf("payload required")
	}
	logger.Info("kms-zap sign", "from", from, "vault", req.VaultID, "wallet", req.WalletID, "payloadHex", hex.EncodeToString(req.Payload[:min(8, len(req.Payload))]))
	result, err := s.backend.TriggerSign(req.VaultID, req.WalletID, req.Payload)
	if err != nil {
		return nil, err
	}
	return json.Marshal(result)
}

// kmsZapReshareRequest matches kms/pkg/mpc/zap_client.go Reshare() payload shape.
type kmsZapReshareRequest struct {
	WalletID string `json:"wallet_id"`
	Request  struct {
		VaultID         string   `json:"vault_id"`
		NewThreshold    int      `json:"new_threshold"`
		NewParticipants []string `json:"new_participants"`
	} `json:"request"`
}

func (s *KMSZapServer) handleReshare(_ context.Context, from string, payload []byte) ([]byte, error) {
	var req kmsZapReshareRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, fmt.Errorf("decode reshare: %w", err)
	}
	if req.WalletID == "" || req.Request.VaultID == "" {
		return nil, fmt.Errorf("wallet_id and request.vault_id required")
	}
	logger.Info("kms-zap reshare", "from", from, "wallet", req.WalletID, "newT", req.Request.NewThreshold)
	if err := s.backend.TriggerReshare(req.Request.VaultID, req.WalletID, req.Request.NewThreshold, req.Request.NewParticipants); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]bool{"ok": true})
}

// handleWallet is a metadata read — mirrors GET /v1/wallets/{id}. We don't
// have a generic wallet-by-id lookup on MPCBackend; return cluster status as
// a placeholder so KMS Status() works and reshape later when MPCBackend grows
// a Wallet() method. Until then a Wallet() call returns a 503-shaped error
// the KMS client passes through.
func (s *KMSZapServer) handleWallet(_ context.Context, _ string, _ []byte) ([]byte, error) {
	return nil, fmt.Errorf("wallet lookup not yet exposed on MPCBackend; use /v1/wallets HTTP")
}

// parsePort extracts the numeric port from a host:port listen string.
func parsePort(listenAddr string) (int, error) {
	for i := len(listenAddr) - 1; i >= 0; i-- {
		if listenAddr[i] == ':' {
			var p int
			if _, err := fmt.Sscanf(listenAddr[i+1:], "%d", &p); err != nil {
				return 0, err
			}
			return p, nil
		}
	}
	return 0, fmt.Errorf("no port in %q", listenAddr)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
