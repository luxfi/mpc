package mpc

import (
	"context"
	"sync"
	"testing"
	"time"

	log "github.com/luxfi/log"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/stretchr/testify/require"
)

// A shared in-process harness for driving real threshold ceremonies in tests.
//
// The point of running the ceremony rather than stubbing it is that the failures
// worth catching here are cryptographic, not structural: a key on the wrong
// curve, a signature encoded the wrong way round, a share that does not survive
// storage. None of those are visible unless the real protocol runs and the real
// bytes come out.

// ceremonyTimeout bounds a whole in-process ceremony so a stalled protocol fails
// the test in seconds instead of hanging on the library's 5m default.
const ceremonyTimeout = 90 * time.Second

// ceremonyParties is a 2-of-3 committee: the smallest shape where a signing
// subset is a strict subset of the keygen set, so Lagrange interpolation is
// genuinely exercised rather than degenerating into a single share.
func ceremonyParties() []party.ID {
	return []party.ID{"node-a", "node-b", "node-c"}
}

// runCeremony drives a threshold protocol to completion entirely in-process:
// every party gets its own protocol.Handler and messages are relayed directly
// between them.
//
// This is the same StartFunc the daemon's sessions hand to protocol.NewHandler,
// so the cryptographic output is the production output — only NATS, the kvstore,
// and the peer registry are absent.
func runCeremony(
	t *testing.T,
	ids []party.ID,
	sessionID []byte,
	start func(party.ID) protocol.StartFunc,
) map[party.ID]any {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), ceremonyTimeout)
	defer cancel()

	inbox := make(map[party.ID]chan *protocol.Message, len(ids))
	for _, id := range ids {
		inbox[id] = make(chan *protocol.Message, 256)
	}

	handlers := make(map[party.ID]*protocol.Handler, len(ids))
	for _, id := range ids {
		h, err := protocol.NewHandler(
			ctx,
			log.NewTestLogger(log.ErrorLevel),
			nil,
			start(id),
			sessionID,
			protocol.DefaultConfig(),
		)
		require.NoError(t, err, "party %s failed to start", id)
		handlers[id] = h
	}

	var (
		mu      sync.Mutex
		results = make(map[party.ID]any, len(ids))
		errs    = make(map[party.ID]error, len(ids))
		wg      sync.WaitGroup
	)

	for id, h := range handlers {
		wg.Add(1)
		go func(id party.ID, h *protocol.Handler) {
			defer wg.Done()
			for {
				select {
				case msg, ok := <-h.Listen():
					if !ok {
						res, err := h.Result()
						mu.Lock()
						results[id], errs[id] = res, err
						mu.Unlock()
						return
					}
					for other, ch := range inbox {
						if other == msg.From {
							continue
						}
						if msg.To != "" && msg.To != other {
							continue
						}
						ch <- msg
					}
				case msg := <-inbox[id]:
					h.Accept(msg)
				}
			}
		}(id, h)
	}
	wg.Wait()

	for _, id := range ids {
		require.NoError(t, errs[id], "party %s did not finish the ceremony", id)
		require.NotNil(t, results[id], "party %s produced no result", id)
	}
	return results
}
