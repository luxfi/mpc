package mpc

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/fystack/mpcium/pkg/common/errors"
	"github.com/fystack/mpcium/pkg/identity"
	"github.com/fystack/mpcium/pkg/keyinfo"
	"github.com/fystack/mpcium/pkg/kvstore"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/nats-io/nats.go"
)

type SessionType string

const (
	TypeGenerateWalletSuccess             = "mpc.mpc_keygen_success.%s"
	TypeReshareWalletSuccess              = "mpc.mpc_reshare_success.%s"
	SessionTypeECDSA          SessionType = "session_ecdsa"
	SessionTypeEDDSA          SessionType = "session_eddsa"
)

var (
	ErrNotEnoughParticipants = errors.New("Not enough participants to sign")
)

type TopicComposer struct {
	ComposeBroadcastTopic func() string
	ComposeDirectTopic    func(nodeID string) string
}

type KeyComposerFn func(id string) string

type Session interface {
	ListenToIncomingMessageAsync()
	ErrChan() <-chan error
}

type session struct {
	walletID           string
	pubSub             messaging.PubSub
	direct             messaging.DirectMessaging
	threshold          int
	participantPeerIDs []string
	selfPartyID        *tss.PartyID
	// IDs of all parties in the session including self
	partyIDs []*tss.PartyID
	outCh    chan tss.Message
	ErrCh    chan error
	party    tss.Party

	// preParams is nil for EDDSA session
	preParams     *keygen.LocalPreParams
	kvstore       kvstore.KVStore
	keyinfoStore  keyinfo.Store
	broadcastSub  messaging.Subscription
	directSub     messaging.Subscription
	resultQueue   messaging.MessageQueue
	identityStore identity.Store

	topicComposer *TopicComposer
	composeKey    KeyComposerFn
	getRoundFunc  GetRoundFunc
	mu            sync.Mutex
	// After the session is done, the key will be stored pubkeyBytes
	pubkeyBytes []byte
	sessionType SessionType
}

func (s *session) PartyID() *tss.PartyID {
	return s.selfPartyID
}

func (s *session) PartyIDs() []*tss.PartyID {
	return s.partyIDs
}

func (s *session) PartyCount() int {
	return len(s.partyIDs)
}

func (s *session) handleTssMessage(keyshare tss.Message) {
	data, routing, err := keyshare.WireBytes()
	if err != nil {
		s.ErrCh <- err
		return
	}

	tssMsg := types.NewTssMessage(s.walletID, data, routing.IsBroadcast, routing.From, routing.To)
	signature, err := s.identityStore.SignMessage(&tssMsg)
	if err != nil {
		s.ErrCh <- fmt.Errorf("failed to sign message: %w", err)
		return
	}
	tssMsg.Signature = signature
	msg, err := types.MarshalTssMessage(&tssMsg)
	if err != nil {
		s.ErrCh <- fmt.Errorf("failed to marshal tss message: %w", err)
		return
	}
	toIDs := make([]string, len(routing.To))
	for i, id := range routing.To {
		toIDs[i] = id.String()
	}
	logger.Info(fmt.Sprintf("%s Sending message", s.sessionType), "from", s.selfPartyID.String(), "to", toIDs, "isBroadcast", routing.IsBroadcast)
	if routing.IsBroadcast && len(routing.To) == 0 {
		err := s.pubSub.Publish(s.topicComposer.ComposeBroadcastTopic(), msg)
		if err != nil {
			s.ErrCh <- err
			return
		}
	} else {
		for _, to := range routing.To {
			nodeID := PartyIDToRoutingDest(to)
			topic := s.topicComposer.ComposeDirectTopic(nodeID)
			err := s.direct.Send(topic, msg)
			if err != nil {
				s.ErrCh <- fmt.Errorf("Failed to send direct message to %s: %w", topic, err)
			}

		}

	}
}

func (s *session) receiveTssMessage(rawMsg []byte) {
	msg, err := types.UnmarshalTssMessage(rawMsg)
	if err != nil {
		s.ErrCh <- fmt.Errorf("Failed to unmarshal message: %w", err)
		return
	}
	err = s.identityStore.VerifyMessage(msg)
	if err != nil {
		s.ErrCh <- fmt.Errorf("Failed to verify message: %w, tampered message", err)
		return
	}

	toIDs := make([]string, len(msg.To))
	for i, id := range msg.To {
		toIDs[i] = id.String()
	}

	round, err := s.getRoundFunc(msg.MsgBytes, s.selfPartyID, msg.IsBroadcast)
	if err != nil {
		s.ErrCh <- errors.Wrap(err, "Broken TSS Share")
		return
	}
	logger.Info("Received message", "round", round.RoundMsg, "isBroadcast", msg.IsBroadcast, "to", toIDs, "from", msg.From.String(), "self", s.selfPartyID.String())
	isBroadcast := msg.IsBroadcast && len(msg.To) == 0
	var isToSelf bool
	for _, to := range msg.To {
		if ComparePartyIDs(to, s.selfPartyID) {
			isToSelf = true
			break
		}
	}

	if isBroadcast || isToSelf {
		s.mu.Lock()
		defer s.mu.Unlock()
		ok, err := s.party.UpdateFromBytes(msg.MsgBytes, msg.From, msg.IsBroadcast)
		if !ok || err != nil {
			logger.Error("Failed to update party", err, "walletID", s.walletID)
			return
		}

	}
}

func (s *session) SendReplySignSuccess(natMsg *nats.Msg) {
	msg := natMsg.Data
	s.mu.Lock()
	defer s.mu.Unlock()

	err := s.pubSub.Publish(natMsg.Reply, msg)
	if err != nil {
		s.ErrCh <- fmt.Errorf("Failed to reply sign sucess message: %w", err)
		return
	}
	logger.Info("Sent reply sign sucess message", "reply", natMsg.Reply)
}

func (s *session) ListenToIncomingMessageAsync() {
	go func() {
		sub, err := s.pubSub.Subscribe(s.topicComposer.ComposeBroadcastTopic(), func(natMsg *nats.Msg) {
			msg := natMsg.Data
			s.receiveTssMessage(msg)
		})

		if err != nil {
			s.ErrCh <- fmt.Errorf("Failed to subscribe to broadcast topic %s: %w", s.topicComposer.ComposeBroadcastTopic(), err)
			return
		}

		s.broadcastSub = sub
	}()

	nodeID := PartyIDToRoutingDest(s.selfPartyID)
	targetID := s.topicComposer.ComposeDirectTopic(nodeID)
	sub, err := s.direct.Listen(targetID, func(msg []byte) {
		go s.receiveTssMessage(msg) // async for avoid timeout
	})
	if err != nil {
		s.ErrCh <- fmt.Errorf("Failed to subscribe to direct topic %s: %w", targetID, err)
	}
	s.directSub = sub

}

func (s *session) Close() error {
	err := s.broadcastSub.Unsubscribe()
	if err != nil {
		return err
	}
	err = s.directSub.Unsubscribe()
	if err != nil {
		return err
	}
	return nil
}

func (s *session) GetPubKeyResult() []byte {
	return s.pubkeyBytes
}

func (s *session) ErrChan() <-chan error {
	return s.ErrCh
}

func (s *session) GetVersion() int {
	fmt.Println("self party id", string(s.selfPartyID.GetKey()))
	version, err := strconv.Atoi(strings.Split(string(s.selfPartyID.GetKey()), ":")[1])
	if err != nil {
		return 0
	}
	return version
}
