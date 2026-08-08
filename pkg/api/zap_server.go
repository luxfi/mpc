package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"

	"github.com/hanzoai/orm"

	"github.com/luxfi/zap"

	"github.com/luxfi/mpc/pkg/db"
	"github.com/luxfi/mpc/pkg/logger"
	"github.com/luxfi/mpc/pkg/types"
)

// ZAP opcodes for MPC API operations (0x0060-0x006F range).
const (
	OpMPCKeygen  uint16 = 0x0060
	OpMPCSign    uint16 = 0x0061
	OpMPCStatus  uint16 = 0x0062
	OpMPCWallets uint16 = 0x0063
	OpMPCIntent  uint16 = 0x0064
)

// ZAP object layout: a status byte and ONE payload, and the payload is JSON.
//
// FIELD OFFSETS ARE BYTES, NOT SLOTS, AND A BYTES FIELD IS EIGHT OF THEM —
// SetBytes writes a uint32 pointer at fieldOffset and a uint32 length at
// fieldOffset+4. The previous layout spaced five fields ONE byte apart
// (orgID 8, walletID 9, payload 10, intentID 11, network 12), so every write
// destroyed the one before it: setting walletID overwrote orgID's length word.
// Measured, the handler read back org_id "" with wallet_id intact — and since
// zapKeygen refuses an empty org_id, that layout rejected every request any
// client could physically send. The reply fared no better: status 8 / data 9
// put data's length word one byte past what StartObject(16) reserved, so an
// 85-byte JSON body came back with '{' replaced by 0x00.
//
// So there was no wire to preserve, only one to choose, and the choice is made:
// this is byte-for-byte hanzoai/commerce's util/zapwire — status at 0, one
// bytes field at 8, object 16 — which is what the only client of this surface
// has always spoken. A request carries its arguments as JSON in that payload
// rather than as parallel text fields, so adding an argument later changes a
// struct and not an offset nobody can see is wrong.
const (
	fieldStatus  = 0
	fieldPayload = 8

	objectSize = 16
)

// StartZAP serves the MPC-API ops over ZAP at addr (":9801", "0.0.0.0:9801").
//
// Takes an ADDRESS, like its sibling StartKMSZAP, because mpcd's other listeners
// are addresses (--listen, --api, --kms-zap-listen) and one shape for "where do
// I listen" is worth more than saving a parse.
func (s *Server) StartZAP(addr string) error {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("zap listen address %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("zap listen address %q: port is not a number: %w", addr, err)
	}

	node := zap.NewNode(zap.NodeConfig{
		NodeID:      fmt.Sprintf("mpc-api-%d", port),
		ServiceType: "_mpc._tcp",
		Port:        port,
		NoDiscovery: true,
	})

	node.Handle(OpMPCKeygen, s.zapKeygen)
	node.Handle(OpMPCSign, s.zapSign)
	node.Handle(OpMPCStatus, s.zapStatus)
	node.Handle(OpMPCWallets, s.zapWallets)
	node.Handle(OpMPCIntent, s.zapIntent)

	if err := node.Start(); err != nil {
		return fmt.Errorf("zap start: %w", err)
	}
	logger.Info("ZAP server started", "port", port)

	// Forward events to ZAP peers
	go s.zapEventForwarder(node)

	return nil
}

// zapArgs is every argument any op on this surface takes. One struct, decoded
// from the single JSON payload — a field a given op does not use is simply
// absent, which is what `omitempty` on the client side already produces.
type zapArgs struct {
	OrgID    string          `json:"org_id"`
	WalletID string          `json:"wallet_id"`
	IntentID string          `json:"intent_id"`
	Network  string          `json:"network"`
	Payload  json.RawMessage `json:"payload"`
}

// zapDecode reads the request's JSON payload. An unparseable body is refused
// rather than treated as an empty one, so a client sending the wrong frame gets
// told so instead of being silently answered "org_id required".
func zapDecode(msg *zap.Message) (zapArgs, error) {
	var a zapArgs
	body := msg.Root().Bytes(fieldPayload)
	if len(body) == 0 {
		return a, fmt.Errorf("empty request payload")
	}
	if err := json.Unmarshal(body, &a); err != nil {
		return a, fmt.Errorf("request payload is not JSON: %w", err)
	}
	return a, nil
}

func (s *Server) zapKeygen(_ context.Context, _ string, msg *zap.Message) (*zap.Message, error) {
	a, err := zapDecode(msg)
	if err != nil {
		return zapError(err.Error())
	}
	orgID, walletID := a.OrgID, a.WalletID
	if orgID == "" || walletID == "" {
		return zapError("org_id and wallet_id required")
	}

	result, err := s.mpc.TriggerKeygen(orgID, walletID)
	if err != nil {
		return zapError(err.Error())
	}

	data, _ := json.Marshal(result)
	s.Events.Publish(Event{Type: "wallet.created", OrgID: orgID, WalletID: walletID, Data: data})
	return zapOK(data)
}

func (s *Server) zapSign(_ context.Context, _ string, msg *zap.Message) (*zap.Message, error) {
	a, err := zapDecode(msg)
	if err != nil {
		return zapError(err.Error())
	}
	orgID, walletID, payload := a.OrgID, a.WalletID, []byte(a.Payload)
	if orgID == "" || walletID == "" || len(payload) == 0 {
		return zapError("org_id, wallet_id, and payload required")
	}

	// This is the general signing surface, so the network is the caller's to
	// state and is refused when absent or unrecognised — the curve it selects
	// is not something the daemon may assume on a caller's behalf.
	network, err := types.ParseNetwork(a.Network)
	if err != nil {
		return zapError(err.Error())
	}

	result, err := s.mpc.TriggerSign(orgID, walletID, network, payload)
	if err != nil {
		return zapError(err.Error())
	}

	data, _ := json.Marshal(result)
	s.Events.Publish(Event{Type: "sign.complete", OrgID: orgID, WalletID: walletID, Data: data})
	return zapOK(data)
}

func (s *Server) zapStatus(_ context.Context, _ string, _ *zap.Message) (*zap.Message, error) {
	data, _ := json.Marshal(s.mpc.GetClusterStatus())
	return zapOK(data)
}

func (s *Server) zapWallets(_ context.Context, _ string, msg *zap.Message) (*zap.Message, error) {
	a, err := zapDecode(msg)
	if err != nil {
		return zapError(err.Error())
	}
	orgID := a.OrgID
	if orgID == "" {
		return zapError("org_id required")
	}

	wallets, err := orm.TypedQuery[db.Wallet](s.db.ORM).
		Filter("orgId=", orgID).
		Order("-createdAt").
		GetAll(context.Background())
	if err != nil {
		return zapError(err.Error())
	}
	if wallets == nil {
		wallets = []*db.Wallet{}
	}

	data, _ := json.Marshal(wallets)
	return zapOK(data)
}

func (s *Server) zapIntent(_ context.Context, _ string, msg *zap.Message) (*zap.Message, error) {
	a, err := zapDecode(msg)
	if err != nil {
		return zapError(err.Error())
	}
	orgID, intentID := a.OrgID, a.IntentID
	if orgID == "" {
		return zapError("org_id required")
	}

	// Query existing intent
	if intentID != "" {
		intent, err := orm.Get[db.Intent](s.db.ORM, intentID)
		if err != nil || intent.OrgID != orgID {
			return zapError("intent not found")
		}
		data, _ := json.Marshal(intent)
		return zapOK(data)
	}

	// Create from payload
	payload := []byte(a.Payload)
	if len(payload) == 0 {
		return zapError("intent_id or payload required")
	}

	var req struct {
		WalletID   string `json:"wallet_id"`
		IntentType string `json:"intent_type"`
		Chain      string `json:"chain"`
		ToAddress  string `json:"to_address"`
		Amount     string `json:"amount"`
		Token      string `json:"token,omitempty"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return zapError("invalid intent payload")
	}
	if req.WalletID == "" || req.IntentType == "" || req.Chain == "" || req.Amount == "" {
		return zapError("wallet_id, intent_type, chain, amount required")
	}

	intent := orm.New[db.Intent](s.db.ORM)
	intent.OrgID = orgID
	intent.WalletID = req.WalletID
	intent.IntentType = req.IntentType
	intent.Chain = req.Chain
	intent.ToAddress = nilIfEmpty(req.ToAddress)
	intent.Amount = req.Amount
	intent.Token = nilIfEmpty(req.Token)
	intent.Status = "pending_sign"
	if err := intent.Create(); err != nil {
		return zapError(err.Error())
	}

	data, _ := json.Marshal(intent)
	s.Events.Publish(Event{Type: "intent.created", OrgID: orgID, WalletID: req.WalletID, Data: data})
	return zapOK(data)
}

// zapEventForwarder broadcasts EventBus events to ZAP peers.
func (s *Server) zapEventForwarder(node *zap.Node) {
	ch, unsub := s.Events.Subscribe("")
	defer unsub()
	for evt := range ch {
		data, err := json.Marshal(evt)
		if err != nil {
			continue
		}
		errs := node.Broadcast(context.Background(), zapMsg(data))
		for peer, berr := range errs {
			logger.Warn("zap broadcast failed", "peer", peer, "err", berr)
		}
	}
}

// zapError builds a ZAP response with error status. The message travels in the
// SAME payload field a success uses — the status byte is what distinguishes
// them — so a caller reads one place and never has to guess which field holds
// the answer.
func zapError(msg string) (*zap.Message, error) {
	return zapReply(1, []byte(msg))
}

// zapOK builds a ZAP response with success status and JSON data.
func zapOK(data []byte) (*zap.Message, error) {
	return zapReply(0, data)
}

func zapReply(status uint8, payload []byte) (*zap.Message, error) {
	b := zap.NewBuilder(zap.HeaderSize + objectSize + len(payload))
	ob := b.StartObject(objectSize)
	ob.SetUint8(fieldStatus, status)
	if len(payload) > 0 {
		ob.SetBytes(fieldPayload, payload)
	}
	ob.FinishAsRoot()
	return zap.Parse(b.Finish())
}

// zapMsg builds a one-way ZAP message with data payload.
func zapMsg(data []byte) *zap.Message {
	m, err := zapReply(0, data)
	if err != nil {
		return nil
	}
	return m
}
