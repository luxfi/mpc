package api

import (
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// visitor tracks request count for a single IP within a time window.
type visitor struct {
	count    atomic.Int64
	lastSeen atomic.Int64 // unix seconds
}

// RateLimiter implements per-IP rate limiting using a sync.Map.
type RateLimiter struct {
	visitors   sync.Map // map[string]*visitor
	limit      int64
	windowSecs int64
}

// NewRateLimiter creates a rate limiter with the given requests-per-minute limit.
// It starts a background goroutine that evicts stale entries every 60 seconds.
func NewRateLimiter(requestsPerMinute int) *RateLimiter {
	rl := &RateLimiter{
		limit:      int64(requestsPerMinute),
		windowSecs: 60,
	}
	go rl.cleanup()
	return rl
}

// allow returns true if the IP has not exceeded the rate limit.
func (rl *RateLimiter) allow(ip string) bool {
	now := time.Now().Unix()

	val, loaded := rl.visitors.LoadOrStore(ip, &visitor{})
	v := val.(*visitor)

	if !loaded {
		v.count.Store(1)
		v.lastSeen.Store(now)
		return true
	}

	last := v.lastSeen.Load()
	if now-last >= rl.windowSecs {
		// Window expired; reset.
		v.count.Store(1)
		v.lastSeen.Store(now)
		return true
	}

	c := v.count.Add(1)
	v.lastSeen.Store(now)
	return c <= rl.limit
}

// cleanup removes entries not seen in the last 2 windows.
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Unix() - 2*rl.windowSecs
		rl.visitors.Range(func(key, val any) bool {
			v := val.(*visitor)
			if v.lastSeen.Load() < cutoff {
				rl.visitors.Delete(key)
			}
			return true
		})
	}
}

// clientIP extracts the client IP from X-Forwarded-For or RemoteAddr.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// First IP in the chain is the original client.
		if ip, _, ok := strings.Cut(xff, ","); ok {
			return strings.TrimSpace(ip)
		}
		return strings.TrimSpace(xff)
	}
	// Strip port from RemoteAddr.
	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx]
	}
	return addr
}

// RateLimitMiddleware returns chi-compatible middleware that limits requests per
// IP to requestsPerMinute within a rolling 60-second window.
func RateLimitMiddleware(requestsPerMinute int) func(http.Handler) http.Handler {
	rl := NewRateLimiter(requestsPerMinute)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r)
			if !rl.allow(ip) {
				writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
