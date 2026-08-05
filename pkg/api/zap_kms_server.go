// Package api — KMS-facing ZAP server.
//
// This file implements a luxfi/zap node that exposes MPC threshold
// operations to the KMS control plane. The port hands out threshold
// signatures over vault keys, so reachability must not equal authority.
//
// # How a peer earns the right to be served
//
//  1. ClientHello / ServerHello (0x00F0 / 0x00F1) — X25519 + ML-KEM-768,
//     yielding a 32-byte AES-256-GCM session key. Required, and required
//     to be hybrid: a peer that clears the ML-KEM bit is refused rather
//     than silently downgraded.
//  2. OpAuth (0x00F2) — the peer's native Hanzo IAM access token, sealed
//     under that key, verified against IAM's published keys.
//  3. Every KMS opcode after that: the frame must open under the session
//     key AND the session must carry an unexpired verified identity.
//
// Any step missing means refuse. There is no unauthenticated path and no
// setting that creates one — StartKMSZAP will not build a server without a
// verifier, so "serve anonymously" is not a reachable state.
//
// # Why the peer ID is not the identity
//
// luxfi/zap's `from` is a string the peer wrote into its own first frame;
// zap discards the decode error and never binds it to a key. It is a
// lookup hint, nothing more. The bind that matters is the AEAD: only the
// party that completed the KEM holds the session key, so only that party
// can produce a frame that opens. A peer spoofing another's `from` reaches
// a session it cannot decrypt, and is refused.
//
// Wire format per request: opcode(2 LE) || sealed(JSON payload).
// Response: opcode(2 LE) || sealed(JSON body). Errors set top-level
// "error". Handshake frames are the one exception — they predate the key
// and ride in the clear.
package api

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/luxfi/mpc/pkg/logger"
	"github.com/luxfi/zap"

	kmszap "github.com/luxfi/mpc/pkg/zap"
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

// Identity is the verified IAM principal behind a connection.
type Identity struct {
	Subject string    // IAM `sub` — the auditable principal
	Owner   string    // IAM `owner` — the org this credential acts in
	Expires time.Time // token expiry; the session dies with it
}

// IdentityVerifier turns an IAM access token into a verified principal, or
// an error. Production wires the native Hanzo IAM verifier (zap_kms_iam.go);
// tests supply one backed by a local JWKS.
//
// An implementation MUST verify the signature against IAM's published keys
// and MUST reject anything it cannot fully check. Returning a nil error
// grants threshold-signing authority.
type IdentityVerifier interface {
	Verify(ctx context.Context, token string) (*Identity, error)
}

// peer is the post-handshake state for one connection: the AEAD session,
// and — once OpAuth succeeds — who the peer proved itself to be. A peer
// with a nil identity has completed the handshake but not authenticated,
// and may call nothing but OpAuth.
type peer struct {
	sess     *kmszap.Session
	identity *Identity
}

// authorized returns nil when this peer may run KMS opcodes. Every refusal
// reason lands here, so there is one answer to "may I serve this frame".
func (p *peer) authorized() error {
	if p.identity == nil {
		return fmt.Errorf("authentication required")
	}
	if time.Now().After(p.identity.Expires) {
		return fmt.Errorf("credential expired")
	}
	return nil
}

// KMSZapServer wires MPCBackend onto a luxfi/zap.Node and frames responses
// in KMS's opcode-prefixed JSON dialect.
type KMSZapServer struct {
	backend  MPCBackend
	verifier IdentityVerifier

	// peers holds per-connection handshake and identity state, keyed by the
	// self-asserted `from`. The key is a hint; the AEAD is the bind — see
	// the package comment.
	peers   map[string]*peer
	peersMu sync.RWMutex

	node *zap.Node
}

// StartKMSZAP creates a luxfi/zap.Node bound to listenAddr and registers
// KMS opcode handlers.
//
// nodeID is the ZAP advertised identity. It labels logs only — the
// auditable principal is the IAM subject the peer proves, not this string.
//
// verifier is required. Without one the server could not tell a KMS pod
// from anyone else who can open a socket, so a nil verifier is a startup
// error rather than a permissive default.
func StartKMSZAP(backend MPCBackend, nodeID, listenAddr string, verifier IdentityVerifier) (*KMSZapServer, error) {
	if verifier == nil {
		return nil, fmt.Errorf("zap: identity verifier is required; this port serves threshold signatures")
	}
	port, err := parsePort(listenAddr)
	if err != nil {
		return nil, fmt.Errorf("zap: parse listen %q: %w", listenAddr, err)
	}

	node := zap.NewNode(zap.NodeConfig{
		NodeID:      nodeID,
		ServiceType: "_mpc-kms._tcp",
		Port:        port,
		NoDiscovery: true, // direct dial only — no mDNS leakage from prod pods
	})

	s := &KMSZapServer{
		backend:  backend,
		verifier: verifier,
		peers:    make(map[string]*peer),
		node:     node,
	}

	// Every opcode — handshake, auth, and the KMS surface — funnels into
	// the same dispatch. Registering them with separate wrappers is what
	// let an earlier version enforce a rule on one route and not the other.
	for _, op := range []uint16{
		kmszap.OpClientHello, kmszap.OpAuth,
		OpKMSStatus, OpKMSKeygen, OpKMSSign, OpKMSReshare, OpKMSWallet,
		0, // type-0 mux: clients that don't set the ZAP message type field
	} {
		node.Handle(op, s.serve)
	}

	if err := node.Start(); err != nil {
		return nil, fmt.Errorf("zap: start node: %w", err)
	}
	logger.Info("KMS ZAP server started",
		"addr", listenAddr, "nodeID", nodeID,
		"caps", "X25519+ML-KEM-768", "auth", "hanzo-iam")
	return s, nil
}

// Stop tears down the underlying ZAP node. Idempotent.
func (s *KMSZapServer) Stop() {
	if s.node != nil {
		s.node.Stop()
	}
}

// handlerFn is the shape of an op handler after the payload is opened and
// the caller's identity is known.
type handlerFn func(ctx context.Context, from string, id *Identity, payload []byte) ([]byte, error)

// serve is the ONE path every inbound frame takes. The opcode is read from
// the body, not the ZAP message type, so a client that leaves the type at
// zero lands in exactly the same place with exactly the same checks.
func (s *KMSZapServer) serve(ctx context.Context, from string, msg *zap.Message) (*zap.Message, error) {
	raw := extractPayload(msg)
	if len(raw) < 2 {
		return frame(0, errBody("empty payload")), nil
	}
	op := binary.LittleEndian.Uint16(raw[:2])
	body := raw[2:]

	// The handshake predates the session key and so rides in the clear.
	if op == kmszap.OpClientHello {
		return s.respondHandshake(from, body), nil
	}

	// No handshake means no session key, no identity, and nothing to serve.
	p := s.peer(from)
	if p == nil {
		logger.Warn("kms-zap refused: no handshake", "from", from, "op", op)
		return frame(op, errBody("handshake required")), nil
	}

	// Opening under the session key is what actually authenticates the
	// frame's origin. A peer that spoofed `from` to reach this session does
	// not hold the key and fails here.
	payload, err := p.sess.Open(kmszap.DirClientToServer, body)
	if err != nil {
		logger.Warn("kms-zap refused: session open failed", "from", from, "op", op, "err", err)
		return frame(op, errBody("session decrypt failed")), nil
	}

	if op == kmszap.OpAuth {
		return s.respondAuth(ctx, from, p, payload), nil
	}

	if err := p.authorized(); err != nil {
		logger.Warn("kms-zap refused", "from", from, "op", op, "reason", err)
		return s.respond(p, op, errBody(err.Error())), nil
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
		return s.respond(p, op, errBody(fmt.Sprintf("unknown opcode 0x%04x", op))), nil
	}
	out, err := h(ctx, from, p.identity, payload)
	if err != nil {
		logger.Warn("kms-zap handler error", "from", from, "op", op,
			"sub", p.identity.Subject, "err", err)
		return s.respond(p, op, errBody(err.Error())), nil
	}
	return s.respond(p, op, out), nil
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

// respond frames opcode(2 LE) || sealed(body) for a peer holding a session
// key.
func (s *KMSZapServer) respond(p *peer, opcode uint16, body []byte) *zap.Message {
	sealed, err := p.sess.Seal(kmszap.DirServerToClient, body)
	if err != nil {
		logger.Error("kms-zap seal failed", err)
		// Refusing beats leaking: emit a clear error rather than an
		// unsealed body the peer would try to decrypt.
		return frame(opcode, errBody("session seal failed"))
	}
	return frame(opcode, sealed)
}

// frame builds the ZAP message: opcode(2 LE) || body.
func frame(opcode uint16, body []byte) *zap.Message {
	out := make([]byte, 2+len(body))
	binary.LittleEndian.PutUint16(out[0:2], opcode)
	copy(out[2:], body)
	b := zap.NewBuilder(len(out) + 64)
	b.WriteBytes(out)
	m, err := zap.Parse(b.Finish())
	if err != nil {
		// Builder output is always parseable — invariant violation.
		logger.Error("kms-zap frame build failed", err)
		return nil
	}
	return m
}

func errBody(msg string) []byte {
	b, _ := json.Marshal(map[string]string{"error": msg})
	return b
}

// peer returns the connection state for a peer, or nil when it hasn't
// completed the handshake.
func (s *KMSZapServer) peer(peerID string) *peer {
	s.peersMu.RLock()
	defer s.peersMu.RUnlock()
	return s.peers[peerID]
}

// respondHandshake runs the server side of the hybrid PQ handshake and
// installs the session. The peer is NOT yet authorized — it holds a key
// and may call OpAuth, nothing else.
//
// ServerHello rides unsealed because the key only exists once this
// exchange completes.
func (s *KMSZapServer) respondHandshake(from string, helloBytes []byte) *zap.Message {
	replyWire, result, err := kmszap.ServerRespond(kmszap.CapMLKEM768, helloBytes)
	if err != nil {
		logger.Warn("kms-zap handshake failed", "from", from, "err", err)
		return frame(kmszap.OpServerHello, errBody(err.Error()))
	}
	// A peer that clears the ML-KEM bit gets classical-only key agreement.
	// Both ends of this wire are ours and both advertise it, so the only
	// party asking for the weaker mode is one that wants it weaker.
	if !result.Hybrid {
		logger.Warn("kms-zap refused: peer cleared ML-KEM-768",
			"from", from, "peerCaps", result.PeerCaps)
		return frame(kmszap.OpServerHello, errBody("ML-KEM-768 required"))
	}
	sess, err := kmszap.NewSession(result.SessionKey, result.Hybrid)
	if err != nil {
		logger.Error("kms-zap session init failed", err, "from", from)
		return frame(kmszap.OpServerHello, errBody(err.Error()))
	}
	s.peersMu.Lock()
	s.peers[from] = &peer{sess: sess}
	s.peersMu.Unlock()
	logger.Info("kms-zap handshake hybrid", "from", from, "alg", "X25519+ML-KEM-768")

	return frame(kmszap.OpServerHello, replyWire)
}

// authRequest is the OpAuth payload: the peer's IAM access token.
type authRequest struct {
	Token string `json:"token"`
}

// respondAuth verifies the peer's IAM credential and, on success, attaches
// the verified identity to the session.
func (s *KMSZapServer) respondAuth(ctx context.Context, from string, p *peer, payload []byte) *zap.Message {
	var req authRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		return s.respond(p, kmszap.OpAuth, errBody("decode auth"))
	}
	id, err := s.verifier.Verify(ctx, req.Token)
	if err != nil {
		// The reason stays in our logs. The peer learns only that it
		// failed — a verification oracle helps nobody but an attacker.
		logger.Warn("kms-zap auth rejected", "from", from, "err", err)
		return s.respond(p, kmszap.OpAuth, errBody("authentication failed"))
	}
	s.peersMu.Lock()
	p.identity = id
	s.peersMu.Unlock()
	logger.Info("kms-zap authenticated", "from", from,
		"sub", id.Subject, "owner", id.Owner, "exp", id.Expires)
	body, _ := json.Marshal(map[string]string{"subject": id.Subject, "owner": id.Owner})
	return s.respond(p, kmszap.OpAuth, body)
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

func (s *KMSZapServer) handleStatus(_ context.Context, _ string, _ *Identity, _ []byte) ([]byte, error) {
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

func (s *KMSZapServer) handleKeygen(_ context.Context, from string, id *Identity, payload []byte) ([]byte, error) {
	var req kmsZapKeygenRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, fmt.Errorf("decode keygen: %w", err)
	}
	if req.VaultID == "" {
		return nil, fmt.Errorf("vault_id required")
	}
	logger.Info("kms-zap keygen", "from", from, "sub", id.Subject, "owner", id.Owner,
		"vault", req.VaultID, "wallet", req.Request.WalletID)
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

func (s *KMSZapServer) handleSign(_ context.Context, from string, id *Identity, payload []byte) ([]byte, error) {
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
	logger.Info("kms-zap sign", "from", from, "sub", id.Subject, "owner", id.Owner,
		"vault", req.VaultID, "wallet", req.WalletID,
		"payloadHex", hex.EncodeToString(req.Payload[:min(8, len(req.Payload))]))
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

func (s *KMSZapServer) handleReshare(_ context.Context, from string, id *Identity, payload []byte) ([]byte, error) {
	var req kmsZapReshareRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, fmt.Errorf("decode reshare: %w", err)
	}
	if req.WalletID == "" || req.Request.VaultID == "" {
		return nil, fmt.Errorf("wallet_id and request.vault_id required")
	}
	logger.Info("kms-zap reshare", "from", from, "sub", id.Subject, "owner", id.Owner,
		"wallet", req.WalletID, "newT", req.Request.NewThreshold)
	if err := s.backend.TriggerReshare(req.Request.VaultID, req.WalletID, req.Request.NewThreshold, req.Request.NewParticipants); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]bool{"ok": true})
}

// handleWallet is a metadata read — mirrors GET /v1/wallets/{id}. We don't
// have a generic wallet-by-id lookup on MPCBackend; a Wallet() call returns
// a 503-shaped error the KMS client passes through until MPCBackend grows
// one.
func (s *KMSZapServer) handleWallet(_ context.Context, _ string, _ *Identity, _ []byte) ([]byte, error) {
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
