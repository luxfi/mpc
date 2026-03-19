package api

import (
	"sync"
	"time"
)

const (
	// replayTTL is how long a request ID is remembered.
	replayTTL = 5 * time.Minute
	// replayCleanupInterval is how often expired entries are purged.
	replayCleanupInterval = 1 * time.Minute
	// maxRequestAge is the maximum age of a request timestamp.
	maxRequestAge = 60 * time.Second
)

// replayGuard prevents duplicate or stale sign requests.
type replayGuard struct {
	mu      sync.Mutex
	seen    map[string]time.Time
	stopCh  chan struct{}
}

func newReplayGuard() *replayGuard {
	rg := &replayGuard{
		seen:   make(map[string]time.Time),
		stopCh: make(chan struct{}),
	}
	go rg.cleanupLoop()
	return rg
}

// check returns an error string if the request should be rejected.
// It checks:
//  1. requestID is non-empty
//  2. requestID has not been seen before (within TTL)
//  3. timestamp is within maxRequestAge of now
//
// On success it records the requestID and returns "".
func (rg *replayGuard) check(requestID string, timestamp int64) string {
	if requestID == "" {
		return "request_id is required for signing requests"
	}

	now := time.Now()

	// Validate timestamp freshness
	if timestamp > 0 {
		reqTime := time.Unix(timestamp, 0)
		age := now.Sub(reqTime)
		if age < 0 {
			age = -age
		}
		if age > maxRequestAge {
			return "request timestamp too old or too far in the future (max 60s drift)"
		}
	}

	rg.mu.Lock()
	defer rg.mu.Unlock()

	if t, ok := rg.seen[requestID]; ok && now.Sub(t) < replayTTL {
		return "duplicate request_id"
	}
	rg.seen[requestID] = now
	return ""
}

func (rg *replayGuard) cleanupLoop() {
	ticker := time.NewTicker(replayCleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			rg.mu.Lock()
			now := time.Now()
			for k, t := range rg.seen {
				if now.Sub(t) >= replayTTL {
					delete(rg.seen, k)
				}
			}
			rg.mu.Unlock()
		case <-rg.stopCh:
			return
		}
	}
}

func (rg *replayGuard) stop() {
	select {
	case <-rg.stopCh:
	default:
		close(rg.stopCh)
	}
}
