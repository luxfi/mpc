// Package ceremony drives a threshold protocol to completion entirely
// in-process, relaying messages directly between parties.
//
// It exists so that tests can run the REAL cryptographic protocol — the same
// protocol.StartFunc the daemon's sessions hand to protocol.NewHandler — with
// only NATS, the kvstore and the peer registry absent. The failures worth
// catching at this seam are cryptographic rather than structural: a key on the
// wrong curve, a signature encoded the wrong way round, a share that does not
// survive storage. None of those are visible unless the real protocol runs and
// the real bytes come out.
//
// It lives outside _test.go because two packages need the same driver
// (pkg/mpc, which tests the sessions, and cmd/mpcd, which tests the daemon's
// signing entry point), and a protocol driver duplicated across packages is a
// driver that drifts.
package ceremony

import (
	"context"
	"fmt"
	"sync"
	"time"

	log "github.com/luxfi/log"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
)

// Timeout bounds a whole ceremony so a stalled protocol fails in seconds
// rather than hanging on the library's 5m default.
const Timeout = 90 * time.Second

// Parties is a 2-of-3 committee: the smallest shape where a signing subset is
// a strict subset of the keygen set, so Lagrange interpolation is genuinely
// exercised rather than degenerating into a single share.
func Parties() []party.ID {
	return []party.ID{"node-a", "node-b", "node-c"}
}

// Run drives start(id) for every id to completion and returns each party's
// result. An error from any party fails the whole ceremony, because a protocol
// that half-finished has produced nothing a caller may use.
func Run(
	ids []party.ID,
	sessionID []byte,
	start func(party.ID) protocol.StartFunc,
) (map[party.ID]any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), Timeout)
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
		if err != nil {
			return nil, fmt.Errorf("party %s failed to start: %w", id, err)
		}
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
		if errs[id] != nil {
			return nil, fmt.Errorf("party %s did not finish the ceremony: %w", id, errs[id])
		}
		if results[id] == nil {
			return nil, fmt.Errorf("party %s produced no result", id)
		}
	}
	return results, nil
}
