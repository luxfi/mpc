package main

// The two halves of an opening, from this node's side.
//
// serveReveal is what this node does when someone else asks: load the share,
// answer, say so if it cannot. TriggerReveal is what this node does when it is
// the one asking: publish, wait for a quorum, combine.
//
// Every node runs both, because any node may be asked and any node may ask.
// Neither half is privileged and neither holds anything the other does not —
// the asking node learns the secret because it is the one that wanted it, and
// learns nothing about any share.

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/luxfi/mpc/pkg/event"
	"github.com/luxfi/mpc/pkg/kvstore"
	"github.com/luxfi/mpc/pkg/logger"
	"github.com/luxfi/mpc/pkg/messaging"
	"github.com/luxfi/mpc/pkg/reveal"
)

// revealDeadline bounds how long a request waits for its quorum. Long enough
// that a node under load still answers, short enough that a caller blocked on
// its own root key finds out rather than hanging: this runs at boot, and a
// process that cannot start should say so.
const revealDeadline = 20 * time.Second

// serveReveal answers opening requests for as long as ctx lives.
func (b *ConsensusMPCBackend) serveReveal(ctx context.Context) error {
	return serveReveal(ctx, b.pubSub, b.factory.KVStore(), b.nodeID)
}

// serveReveal is the answering half, over the pieces it actually needs: a bus
// to hear on, a store to read a share from, and a name to answer under.
func serveReveal(ctx context.Context, bus messaging.PubSub, store kvstore.KVStore, nodeID string) error {
	sub, err := bus.Subscribe(event.RevealRequestTopic, func(natMsg *nats.Msg) {
		var req event.RevealRequest
		if err := json.Unmarshal(natMsg.Data, &req); err != nil {
			logger.Warn("reveal: unreadable request", "error", err.Error())
			return
		}
		answerReveal(bus, store, nodeID, req)
	})
	if err != nil {
		return fmt.Errorf("reveal: subscribe: %w", err)
	}
	go func() {
		<-ctx.Done()
		_ = sub.Unsubscribe()
	}()
	logger.Info("reveal: answering opening requests", "node", nodeID)
	return nil
}

// answerReveal computes this node's contribution and publishes it.
//
// A node that holds no share for the key publishes that fact rather than
// staying quiet. Silence and refusal look identical to a caller counting
// answers, and they are not: one means wait longer, the other means never.
func answerReveal(bus messaging.PubSub, store kvstore.KVStore, nodeID string, req event.RevealRequest) {
	out := event.RevealAnswer{SessionID: req.SessionID, PartyID: nodeID}

	answer, err := reveal.Answer(store, req.OrgID, req.KeyID, req.Ciphertext)
	if err != nil {
		out.Error = err.Error()
		logger.Info("reveal: cannot answer", "key", req.KeyID, "reason", err.Error())
	} else {
		out.Answer = answer
	}

	body, err := json.Marshal(out)
	if err != nil {
		return
	}
	topic := fmt.Sprintf("%s.%s", event.RevealAnswerTopicBase, req.SessionID)
	if err := bus.Publish(topic, body); err != nil {
		logger.Warn("reveal: cannot publish an answer", "error", err.Error())
	}
}

// TriggerReveal opens ciphertext under the share set recorded for keyID.
//
// The ciphertext comes from the caller. This ring stores shares and answers
// with them; it holds nothing that needs opening, so there is no sealed
// material here to guard and a caller may keep its own wherever it likes.
func (b *ConsensusMPCBackend) TriggerReveal(orgID, keyID string, ciphertext []byte) ([]byte, error) {
	return openReveal(b.pubSub, b.factory.KVStore(), b.nodeID, orgID, keyID, ciphertext)
}

// openReveal is the asking half, over the pieces it actually needs.
func openReveal(bus messaging.PubSub, store kvstore.KVStore, nodeID, orgID, keyID string, ciphertext []byte) ([]byte, error) {
	if orgID == "" || keyID == "" {
		return nil, fmt.Errorf("reveal: org and key are required")
	}
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("reveal: nothing to open")
	}

	// How many answers this key needs, read from the share set before asking for
	// any — so the wait is for a real quorum and not for whoever turns up.
	quorum, err := reveal.Quorum(store, orgID, keyID)
	if err != nil {
		return nil, err
	}

	sessionID := fmt.Sprintf("reveal-%s-%d", nodeID, time.Now().UnixNano())

	// One answer per party, counted under a lock. A party that answers twice —
	// a redelivery, a duplicated subscription — must not count twice, or a
	// quorum is reached by repetition rather than by agreement. Open refuses
	// such a set anyway; this keeps the wait honest as well.
	var (
		mu       sync.Mutex
		answers  = map[string][]byte{}
		refusals []string
		once     sync.Once
		done     = make(chan struct{})
	)

	unsub, err := bus.Subscribe(fmt.Sprintf("%s.%s", event.RevealAnswerTopicBase, sessionID), func(natMsg *nats.Msg) {
		var in event.RevealAnswer
		if err := json.Unmarshal(natMsg.Data, &in); err != nil {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if in.Error != "" {
			refusals = append(refusals, fmt.Sprintf("%s: %s", in.PartyID, in.Error))
			return
		}
		if in.PartyID == "" || answers[in.PartyID] != nil {
			return
		}
		answers[in.PartyID] = in.Answer
		if len(answers) >= quorum {
			once.Do(func() { close(done) })
		}
	})
	if err != nil {
		return nil, fmt.Errorf("reveal: await answers: %w", err)
	}
	defer unsub.Unsubscribe()

	req := event.RevealRequest{SessionID: sessionID, OrgID: orgID, KeyID: keyID, Ciphertext: ciphertext}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("reveal: encode request: %w", err)
	}
	if err := bus.Publish(event.RevealRequestTopic, body); err != nil {
		return nil, fmt.Errorf("reveal: publish request: %w", err)
	}

	select {
	case <-done:
	case <-time.After(revealDeadline):
	}

	mu.Lock()
	collected := make([][]byte, 0, len(answers))
	for _, a := range answers {
		collected = append(collected, a)
	}
	why := append([]string(nil), refusals...)
	mu.Unlock()

	if len(collected) < quorum {
		// Say who refused and why. A quorum that never forms because two nodes
		// hold no share is a different problem from one that never forms
		// because two nodes are down, and only the nodes know which.
		if len(why) > 0 {
			return nil, fmt.Errorf("reveal: %d of %d answered for %s; refusals: %v", len(collected), quorum, keyID, why)
		}
		return nil, fmt.Errorf("reveal: %d of %d answered for %s within %s", len(collected), quorum, keyID, revealDeadline)
	}

	return reveal.Combine(store, orgID, keyID, ciphertext, collected)
}
