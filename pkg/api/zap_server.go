package api

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hanzoai/orm"

	"github.com/luxfi/mpc/pkg/db"
	"github.com/luxfi/mpc/pkg/logger"
	"github.com/luxfi/zap"
)

// ZAP opcodes for MPC API operations (0x0060-0x006F range).
const (
	OpMPCKeygen  uint16 = 0x0060
	OpMPCSign    uint16 = 0x0061
	OpMPCStatus  uint16 = 0x0062
	OpMPCWallets uint16 = 0x0063
	OpMPCIntent  uint16 = 0x0064
)

// ZAP object field offsets (after the 8-byte req/resp correlation header).
const (
	fieldOrgID    = 8
	fieldWalletID = 9
	fieldPayload  = 10
	fieldIntentID = 11

	fieldStatus = 8
	fieldData   = 9
	fieldError  = 10
)

// StartZAP creates a ZAP node on a separate port and registers MPC handlers.
func (s *Server) StartZAP(port int) error {
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

func (s *Server) zapKeygen(_ context.Context, _ string, msg *zap.Message) (*zap.Message, error) {
	root := msg.Root()
	orgID := root.Text(fieldOrgID)
	walletID := root.Text(fieldWalletID)
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
	root := msg.Root()
	orgID := root.Text(fieldOrgID)
	walletID := root.Text(fieldWalletID)
	payload := root.Bytes(fieldPayload)
	if orgID == "" || walletID == "" || len(payload) == 0 {
		return zapError("org_id, wallet_id, and payload required")
	}

	result, err := s.mpc.TriggerSign(orgID, walletID, payload)
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
	orgID := msg.Root().Text(fieldOrgID)
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
	root := msg.Root()
	orgID := root.Text(fieldOrgID)
	intentID := root.Text(fieldIntentID)
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
	payload := root.Bytes(fieldPayload)
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

// zapError builds a ZAP response with error status.
func zapError(msg string) (*zap.Message, error) {
	b := zap.NewBuilder(256)
	ob := b.StartObject(16)
	ob.SetUint8(fieldStatus, 1)
	ob.SetText(fieldError, msg)
	ob.FinishAsRoot()
	return zap.Parse(b.Finish())
}

// zapOK builds a ZAP response with success status and JSON data.
func zapOK(data []byte) (*zap.Message, error) {
	b := zap.NewBuilder(len(data) + 64)
	ob := b.StartObject(16)
	ob.SetUint8(fieldStatus, 0)
	ob.SetBytes(fieldData, data)
	ob.FinishAsRoot()
	return zap.Parse(b.Finish())
}

// zapMsg builds a one-way ZAP message with data payload.
func zapMsg(data []byte) *zap.Message {
	b := zap.NewBuilder(len(data) + 64)
	ob := b.StartObject(16)
	ob.SetBytes(fieldData, data)
	ob.FinishAsRoot()
	m, _ := zap.Parse(b.Finish())
	return m
}
